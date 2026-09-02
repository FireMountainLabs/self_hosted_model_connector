"""The connector's side of the relay wire protocol (protocol 2).

Three verbs. ``session`` trades the pairing token for a short-lived session
token - the one moment the long-lived credential touches the wire. ``poll``
and ``result`` authenticate with the session token only. Status codes and
body codes are the protocol's grammar:

* 401 with body code ``session_expired`` - the session ended (expiry, or a
  relay restart); establish again. Raised as :class:`SessionExpired`.
* 401 anywhere else - the pairing itself was refused; stop, do not hammer.
  Raised as :class:`TokenRejected`.
* 426 - the relay speaks a protocol this connector does not; stop loudly,
  naming both versions. Raised as :class:`ProtocolMismatch`.

The client holds only the session token between calls. The pairing token is
requested from a caller-provided source at establishment, used once, and
dropped - it is never stored on the client.
"""

from __future__ import annotations

import threading

from model_connector import tls


class TokenRejected(RuntimeError):
    """The relay refused the pairing token; the pairing is gone."""


class SessionExpired(RuntimeError):
    """The session ended (TTL, or a relay restart); establish a new one."""


class ProtocolMismatch(RuntimeError):
    """The relay speaks a different protocol major; upgrading is on a human."""


def _body_code(body: dict) -> str:
    return str((body.get("error") or {}).get("code") or "")


class RelayClient:
    def __init__(
        self,
        relay: str,
        token_source,
        timeout: float = 35.0,
        post=tls.https_post_json,
    ) -> None:
        """``token_source`` is a zero-argument callable returning the pairing
        token; it is consulted at every session establishment and never
        between - the credential's home is wherever the source reads from
        (a secrets manager, a file), not this object."""
        self._relay = relay.rstrip("/")
        self._token_source = token_source
        # Above the relay's ~25s poll hold, so a held-then-empty poll is a
        # normal return, never a client-side timeout.
        self._timeout = timeout
        self._post = post
        self._session: str | None = None
        # One session serves every worker thread; establishment is serialized
        # so N threads hitting an expiry re-establish once, not N times.
        self._lock = threading.Lock()

    # ------------------------------------------------------------- sessions
    def establish(self) -> None:
        """Trade the pairing token for a session token, under the lock.

        The pairing token is confined to this call: never assigned to the
        object, never logged, and the local name is dropped after the
        exchange. Confinement is the guarantee - Python cannot promise
        erasure of freed strings, so transient copies (the Bearer header)
        live until collection; what is promised is that nothing keeps one."""
        with self._lock:
            if self._session is not None:
                return  # another worker already re-established
            token = self._token_source()
            try:
                status, body = self._post(
                    f"{self._relay}/connector/session",
                    {"protocol": 2},
                    {"Authorization": f"Bearer {token}"},
                    self._timeout,
                )
            finally:
                del token
            if status == 401:
                raise TokenRejected("the relay rejected the pairing token")
            if status == 426:
                raise ProtocolMismatch(
                    (body.get("error") or {}).get("message") or "protocol version mismatch"
                )
            session = body.get("session_token")
            if not session:
                raise RuntimeError("the relay answered without a session token")
            self._session = str(session)

    def _drop_session(self) -> None:
        with self._lock:
            self._session = None

    def _headers(self) -> dict[str, str]:
        session = self._session
        if session is None:
            raise SessionExpired("no session established")
        return {"Authorization": f"Bearer {session}"}

    def _checked(self, status: int, body: dict) -> dict:
        if status == 401 and _body_code(body) == "session_expired":
            self._drop_session()
            raise SessionExpired("the session ended; establish a new one")
        if status == 401:
            raise TokenRejected("the relay rejected the pairing token")
        if status == 426:
            raise ProtocolMismatch(
                (body.get("error") or {}).get("message") or "protocol version mismatch"
            )
        return body

    # ----------------------------------------------------------------- verbs
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
