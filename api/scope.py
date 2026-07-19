"""Scope/authorization gate for active tools.

See docs/SECURITY_AND_AUTHORIZATION.md — this is the technical enforcement
that doc calls for: a conversational "may I?" is not authorization, so every
active-scan call must pass through require_authorized() here, independent of
whatever the LLM/planner decided.
"""

import ipaddress
import socket
from datetime import datetime, timedelta, timezone

import httpx as httpx_client
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.config import settings
from memory.models import Target

PASSIVE_RECON = "passive-recon"
ACTIVE_SCAN = "active-scan"
# Confirming a vulnerability's real impact (e.g. enumerating what a SQLi
# actually exposes), not just detecting it. Deliberately grantable ONLY
# via verify_sow() below — self-attestation and file-token verification
# cannot include this in authorized_actions no matter what, since a
# one-line chat statement isn't strong enough authorization for it.
EXPLOITATION = "exploitation"


class ScopeDenied(Exception):
    pass


def _hostname_of(identifier: str) -> str:
    return identifier.split("://")[-1].split("/")[0].split(":")[0]


def _is_private_or_local(identifier: str) -> bool:
    host = _hostname_of(identifier)
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        pass
    try:
        resolved = socket.gethostbyname(host)
        return ipaddress.ip_address(resolved).is_private
    except (socket.gaierror, ValueError):
        return False


def _ttl_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=settings.scope_verification_ttl_days)


def _self_attest_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=settings.self_attest_ttl_days)


def get_or_create_target(session: Session, identifier: str) -> Target:
    target = session.scalar(select(Target).where(Target.identifier == identifier))
    if target is not None:
        return target

    target = Target(identifier=identifier, status="unverified", authorized_actions=[])
    if _is_private_or_local(identifier):
        # RFC1918/localhost — the user's own reachable infrastructure, no
        # third party to harm. See docs/SECURITY_AND_AUTHORIZATION.md #4.
        target.status = "verified"
        target.verification_method = "local-private-range"
        target.authorized_actions = [PASSIVE_RECON, ACTIVE_SCAN]
        target.expires_at = _ttl_expiry()

    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def verify_file_token(session: Session, identifier: str, expected_token: str) -> Target:
    """docs/SECURITY_AND_AUTHORIZATION.md verification method 1."""
    url = f"https://{identifier}/.well-known/scorpion-auth.txt"
    try:
        response = httpx_client.get(url, timeout=10, follow_redirects=False)
        response.raise_for_status()
        found = response.text.strip()
    except Exception as exc:  # noqa: BLE001
        raise ScopeDenied(f"could not fetch {url}: {exc}") from exc

    if found != expected_token:
        raise ScopeDenied(f"token mismatch at {url}")

    target = get_or_create_target(session, identifier)
    target.status = "verified"
    target.verification_method = "file-token"
    target.authorized_actions = [PASSIVE_RECON, ACTIVE_SCAN]
    target.expires_at = _ttl_expiry()
    session.commit()
    session.refresh(target)
    return target


def verify_self_attestation(session: Session, identifier: str, statement: str) -> Target:
    """docs/SECURITY_AND_AUTHORIZATION.md verification method 3 — the
    weakest one, by design. This is NOT a conversational "sure, go ahead":
    it requires an explicit, non-default CLI action (`scan --self-attest`
    or a prompt the user must actively confirm) and the actual attestation
    text is stored so it shows up in any report — a false attestation is
    attributable, unlike a chat "yes". Short TTL relative to the other
    methods to keep re-use of a false or stale attestation bounded.
    """
    target = get_or_create_target(session, identifier)
    target.status = "verified"
    target.verification_method = f"self-attested: {statement.strip()}"
    target.authorized_actions = [PASSIVE_RECON, ACTIVE_SCAN]
    target.expires_at = _self_attest_expiry()
    session.commit()
    session.refresh(target)
    return target


def verify_sow(session: Session, identifier: str, sow_text: str, parsed: dict) -> Target:
    """The only path that can grant EXPLOITATION — `parsed` is api/sow.py's
    LLM analysis of a real SOW document. The full SOW text is stored on
    the row so the specific authorization behind an exploitation action is
    always traceable later, same accountability principle as self-attestation.
    """
    target = get_or_create_target(session, identifier)
    actions = [PASSIVE_RECON, ACTIVE_SCAN]
    if parsed.get("exploitation_authorized"):
        actions.append(EXPLOITATION)
    target.status = "verified"
    target.verification_method = f"sow: {parsed.get('reasoning', '')[:400]}"
    target.authorized_actions = actions
    target.sow_text = sow_text
    target.report_requirements = parsed.get("report_requirements") or []
    target.expires_at = _ttl_expiry()
    session.commit()
    session.refresh(target)
    return target


def _is_expired(target: Target) -> bool:
    return target.expires_at is not None and target.expires_at < datetime.now(timezone.utc)


def effective_status(target: Target) -> str:
    """`target.status` is a raw DB column set once at verification time —
    it never flips back to anything else on its own once a TTL passes.
    Only require_authorized() (called per tool stage, deep in a scan)
    checks expires_at. Anything that decides *before* running the pipeline
    whether re-verification is needed (the CLI's --self-attest handling,
    /v1/targets/status) must go through this instead of target.status
    directly — otherwise a stale 'verified' row reads as still-good, the
    CLI skips re-attesting, and every stage then gets denied anyway."""
    if target.status == "verified" and _is_expired(target):
        return "expired"
    return target.status


def get_target_status(session: Session, identifier: str) -> Target:
    return get_or_create_target(session, identifier)


def resolve_for_container(identifier: str) -> str:
    """The host/URL string a containerized tool should actually target.

    Docker Desktop containers can't reach the Windows/Mac host via
    localhost/127.0.0.1 — only via settings.container_host_alias. Scope
    records stay keyed by the identifier the user gave (e.g. "localhost");
    only the value passed into the container command is substituted.
    """
    if _hostname_of(identifier) in ("localhost", "127.0.0.1"):
        return identifier.replace("localhost", settings.container_host_alias).replace(
            "127.0.0.1", settings.container_host_alias
        )
    return identifier


def require_authorized(session: Session, identifier: str, action: str) -> Target:
    """Raises ScopeDenied unless `identifier` is verified, unexpired, and
    authorized for `action`. Call this before every active tool invocation —
    never rely on a prior conversational confirmation."""
    target = get_or_create_target(session, identifier)

    if target.status != "verified":
        raise ScopeDenied(
            f"target '{identifier}' is not verified (status={target.status}). "
            "Verify it first with `scorpion verify-target` or self-attest via `scorpion scan`."
        )
    if _is_expired(target):
        raise ScopeDenied(f"target '{identifier}' scope verification expired — re-verify.")
    if action not in (target.authorized_actions or []):
        raise ScopeDenied(f"target '{identifier}' is not authorized for action '{action}'.")

    return target


def has_authorization(session: Session, identifier: str, action: str) -> bool:
    """Non-raising variant of require_authorized — for a runtime decision
    (e.g. whether sqlmap escalates past detection) rather than gating
    whether a stage runs at all. The orchestrator still calls
    require_authorized() separately before actually running any stage;
    this only decides how a stage runs, never whether it does."""
    try:
        require_authorized(session, identifier, action)
        return True
    except ScopeDenied:
        return False
