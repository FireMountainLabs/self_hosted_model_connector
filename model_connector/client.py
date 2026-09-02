"""The connector's side of the relay wire protocol (protocol 1).

Poll and result are the only two verbs; both authenticate with the pairing
token as a bearer header and both travel over the AES-256-or-refuse
transport. Status codes are the protocol's grammar: 401 means the pairing
was revoked (stop, do not hammer), 426 means the relay moved to a protocol
this connector does not speak (stop loudly, naming both versions).
"""

from __future__ import annotations

from model_connector import tls


class TokenRejected(RuntimeError):
    """The relay refused the pairing token; the pairing is gone."""


class ProtocolMismatch(RuntimeError):
    """The relay speaks a different protocol major; upgrading is on a human."""


class RelayClient:
    def __init__(
        self,
        relay: str,
        token: str,
        timeout: float = 35.0,
        post=tls.https_post_json,
    ) -> None:
        self._relay = relay.rstrip("/")
        self._token = token
        # Above the relay's ~25s poll hold, so a held-then-empty poll is a
        # normal return, never a client-side timeout.
        self._timeout = timeout
        self._post = post

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def _checked(self, status: int, body: dict) -> dict:
        if status == 401:
            raise TokenRejected("the relay rejected the pairing token")
        if status == 426:
            raise ProtocolMismatch(
                (body.get("error") or {}).get("message") or "protocol version mismatch"
            )
        return body

    def poll(self, declare: dict) -> dict | None:
        status, body = self._post(
            f"{self._relay}/connector/poll", declare, self._headers(), self._timeout
        )
        return self._checked(status, body).get("job")

    def result(self, job_id: str, body: dict) -> None:
        status, resp = self._post(
            f"{self._relay}/connector/result/{job_id}", body, self._headers(), self._timeout
        )
        self._checked(status, resp)
