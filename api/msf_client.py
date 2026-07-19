"""Minimal MessagePack-RPC client for Metasploit's msfrpcd.

Hand-rolled rather than depending on pymetasploit3, which hardcodes TLS
certificate verification off regardless of its own `ssl=` setting — a
reasonable choice for us too (this only ever talks to a container on the
local Docker network, never an untrusted one), but better to make that an
explicit, visible choice in this codebase than an implicit one buried in
a third-party library.

Confirmed working for real against a live msfrpcd instance during
development: auth.login, module.execute, module.running_stats, and
module.results all behave exactly as implemented here.
"""

import time

import httpx
import msgpack

from api.config import settings


class MsfRpcError(Exception):
    pass


def _decode(value):
    """msfrpcd's Ruby msgpack producer encodes strings as the legacy 'raw'
    type, not the newer utf8 'str' type — Python's msgpack only
    auto-decodes 'str'-type values even with raw=False, so 'raw'-type
    values come back as bytes and need explicit decoding here."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {_decode(k): _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


class MsfRpcClient:
    def __init__(self):
        self._base_url = f"http://{settings.msf_rpc_host}:{settings.msf_rpc_port}/api/"
        self._token: str | None = None

    def _call(self, method: str, *params, timeout: float = 30) -> dict:
        body = msgpack.packb([method, *params])
        try:
            response = httpx.post(
                self._base_url, content=body, headers={"Content-Type": "binary/message-pack"}, timeout=timeout
            )
        except httpx.HTTPError as exc:
            raise MsfRpcError(f"could not reach msfrpcd at {self._base_url}: {exc}") from exc

        result = _decode(msgpack.unpackb(response.content, raw=False))
        if isinstance(result, dict) and result.get("error"):
            raise MsfRpcError(f"{method} failed: {result.get('error_message', result)}")
        return result

    def login(self) -> None:
        result = self._call("auth.login", settings.msf_rpc_user, settings.msf_rpc_password)
        self._token = result["token"]

    def run_auxiliary_module(self, module_path: str, options: dict) -> dict:
        """Executes an auxiliary module and blocks until it finishes,
        returning module.results' payload. module_path excludes the
        'auxiliary/' prefix (e.g. "scanner/http/http_version")."""
        if self._token is None:
            self.login()

        exec_result = self._call("module.execute", self._token, "auxiliary", module_path, options)
        uuid = exec_result["uuid"]

        deadline = time.monotonic() + settings.msf_module_timeout_seconds
        while time.monotonic() < deadline:
            stats = self._call("module.running_stats", self._token)
            if uuid not in stats.get("running", []) and uuid not in stats.get("waiting", []):
                break
            time.sleep(2)
        else:
            raise MsfRpcError(f"{module_path} did not finish within {settings.msf_module_timeout_seconds}s")

        return self._call("module.results", self._token, uuid)
