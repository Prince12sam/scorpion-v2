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
    url = f"https://{identifier}/.well-known/es-auth.txt"
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
            "Verify it first — see docs/SECURITY_AND_AUTHORIZATION.md."
        )
    if target.expires_at is not None and target.expires_at < datetime.now(timezone.utc):
        raise ScopeDenied(f"target '{identifier}' scope verification expired — re-verify.")
    if action not in (target.authorized_actions or []):
        raise ScopeDenied(f"target '{identifier}' is not authorized for action '{action}'.")

    return target
