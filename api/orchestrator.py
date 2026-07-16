"""Tool Orchestrator (Phase 2) — docs/MVP.md #4.

Coordinates external recon/scan tools behind one interface so the Agent
Core never shells out directly, normalizes every tool's output to one
finding schema, and enforces the scope gate per invocation.

A scan runs in three phases:
  1. Enumeration — subfinder discovers subdomains of the root target.
  2. Liveness — httpx probes the root plus every discovered subdomain (one
     batched container call) to find which actually respond.
  3. Per-host pipeline — the declarative PIPELINE below (katana, nmap,
     nuclei, ffuf, dalfox, sqlmap) runs once for every live host, not just
     the original target. This is what makes a scan real subdomain
     enumeration instead of a single-host check with a subdomain list
     attached as a side note.

Every stage — including per-host ones — checks scope against the
*original* target identifier, not the per-host string: a verified root
target's discovered subdomains are treated as in-scope automatically
(most bounty programs cover *.example.com under one root verification),
per-subdomain re-verification would make a large enumeration result
unusably slow. One tool failing (ToolError) or being denied scope
(ScopeDenied) doesn't stop the rest of the pipeline, it's recorded as a
warning instead.
"""

from dataclasses import dataclass
from typing import Callable, Literal

from sqlalchemy.orm import Session

from api.config import settings
from api import scan_status
from api.scope import ACTIVE_SCAN, PASSIVE_RECON, ScopeDenied, require_authorized, resolve_for_container
from api.tool_router import (
    ToolError,
    run_dalfox,
    run_ffuf,
    run_httpx,
    run_katana,
    run_nmap,
    run_nuclei,
    run_sqlmap,
    run_subfinder,
    run_zap_baseline,
    run_zap_full_scan,
)

TargetForm = Literal["host", "url"]


@dataclass(frozen=True)
class ToolStage:
    name: str
    action_class: str  # passive-recon | active-scan — see docs/SECURITY_AND_AUTHORIZATION.md
    runner: Callable[[str], list[dict]]
    target_form: TargetForm = "host"  # host-only tools (nmap) vs URL tools (the rest)


# The per-live-host chain a scan runs, after enumeration + liveness below.
# Adding a tool is a data change here plus a matching run_* in
# tool_router.py — nothing else in this module changes.
PIPELINE: list[ToolStage] = [
    ToolStage(name="katana", action_class=PASSIVE_RECON, runner=run_katana, target_form="url"),
    ToolStage(name="zap-baseline", action_class=PASSIVE_RECON, runner=run_zap_baseline, target_form="url"),
    ToolStage(name="nmap", action_class=ACTIVE_SCAN, runner=run_nmap, target_form="host"),
    ToolStage(name="nuclei", action_class=ACTIVE_SCAN, runner=run_nuclei, target_form="url"),
    ToolStage(name="ffuf", action_class=ACTIVE_SCAN, runner=run_ffuf, target_form="url"),
    ToolStage(name="dalfox", action_class=ACTIVE_SCAN, runner=run_dalfox, target_form="url"),
    ToolStage(name="sqlmap", action_class=ACTIVE_SCAN, runner=run_sqlmap, target_form="url"),
    # A different scanning engine than nuclei/dalfox/sqlmap, run last since
    # zap-full-scan is by far the slowest stage (it actively attacks every
    # spidered page/param, not a fixed template set).
    ToolStage(name="zap-full-scan", action_class=ACTIVE_SCAN, runner=run_zap_full_scan, target_form="url"),
]


def _as_host(target: str) -> str:
    return target.split("://", 1)[-1]


def _as_url(target: str) -> str:
    return target if "://" in target else f"http://{target}"


def run_pipeline(session: Session, target: str) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    warnings: list[str] = []
    container_target = resolve_for_container(target)
    root_host = _as_host(container_target)
    root_url = _as_url(container_target)

    try:
        # --- Phase 1: enumerate subdomains of the root target ---
        candidate_hosts = {root_host}
        try:
            require_authorized(session, target, PASSIVE_RECON)
            scan_status.set_stage(target, "subfinder (enumeration)", 1, 2)
            sub_findings = run_subfinder(root_host)
            findings.extend(sub_findings)
            candidate_hosts.update(f["host"] for f in sub_findings if f.get("host"))
        except ScopeDenied as exc:
            warnings.append(f"subfinder: skipped — {exc}")
        except ToolError as exc:
            warnings.append(f"subfinder: {exc}")

        ordered_hosts = [root_host] + sorted(candidate_hosts - {root_host})
        hosts_to_probe = ordered_hosts[: settings.max_enumerated_hosts]
        if len(ordered_hosts) > len(hosts_to_probe):
            dropped = len(ordered_hosts) - len(hosts_to_probe)
            warnings.append(
                f"enumeration capped at {settings.max_enumerated_hosts} host(s) — "
                f"{dropped} discovered subdomain(s) not scanned further "
                "(raise SCORPION_MAX_ENUMERATED_HOSTS to include more)"
            )

        # --- Phase 2: find which candidate hosts are actually live ---
        live_urls: list[str] = []
        httpx_attempted = False
        try:
            require_authorized(session, target, PASSIVE_RECON)
            scan_status.set_stage(target, "httpx (liveness)", 2, 2)
            httpx_attempted = True
            httpx_findings = run_httpx(hosts_to_probe)
            findings.extend(httpx_findings)
            live_urls = [f["live_url"] for f in httpx_findings if f.get("live_url")]
        except ScopeDenied as exc:
            warnings.append(f"httpx: skipped — {exc}")
        except ToolError as exc:
            warnings.append(f"httpx: {exc}")

        if not live_urls:
            live_urls = [root_url]
            if httpx_attempted:
                warnings.append(
                    "no host responded to httpx — falling back to scanning the root target directly"
                )

        # --- Phase 3: run the rest of the pipeline against every live host ---
        total = len(live_urls) * len(PIPELINE)
        done = 0
        for url in live_urls:
            host = _as_host(url)
            for stage in PIPELINE:
                done += 1
                try:
                    require_authorized(session, target, stage.action_class)
                except ScopeDenied as exc:
                    warnings.append(f"{stage.name} ({host}): skipped — {exc}")
                    continue

                scan_status.set_stage(target, f"{stage.name} ({host})", done, total)
                stage_target = host if stage.target_form == "host" else url
                try:
                    findings.extend(stage.runner(stage_target))
                except ToolError as exc:
                    warnings.append(f"{stage.name} ({host}): {exc}")
    finally:
        scan_status.clear(target)

    return findings, warnings
