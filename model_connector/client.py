"""The connector's side of the relay wire protocol (protocol 2).

Three verbs. ``session`` trades the pairing token for a short-lived session
token - the one moment the long-lived credential touches the wire. ``poll``
and ``result`` authenticate with the session token only. Status codes and
body codes are the protocol's grammar:

* 401 with body code ``session_expired`` - the session ended (expiry, or a
  relay restart); establish again. Raised as :class:`SessionExpired`.
* 401 with body code ``pairing_revoked`` at establishment - the pairing
  itself was refused; stop, forget the token, do not hammer. Raised as
  :class:`TokenRejected`. Only this coded answer means revoked: the stored
  token is forgotten on it and on nothing else, because a front door, a
  restarted relay or a relay that cannot reach its store can all answer
  401 without meaning it.
* Any other 401 on a poll or a result - establish again (establishment is
  where a revoked pairing gets its own refusal). At establishment, any
  other refusal or a 5xx is :class:`RelayUnavailable` - retried, and the
  token kept.
* 409 at establishment, body code ``connector_busy`` - a live session already
  holds this pairing token. Raised as :class:`KeyBusy`.
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


class TenantChanged(RuntimeError):
    """The relay now answers for a different tenant than the one this process
    first paired with; only a deliberate restart may move a connector."""


class RelayUnavailable(RuntimeError):
    """The relay could not serve the request right now (a 5xx, or a refusal
    that names no revoked pairing). A retry, never a reason to forget the
    token: the relay's own store may be redeploying for a few seconds."""


class KeyBusy(RuntimeError):
    """The relay already holds a live session on this pairing token. One
    token serves one connector: the other holder is still polling, so this
    one waits (a restart on a crash's heels) or stops (a second machine,
    which needs its own token)."""


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
        (the stored pairing, or the operator's paste held in memory), not this
        object."""
        self._relay = relay.rstrip("/")
        self._token_source = token_source
        # Above the relay's ~25s poll hold, so a held-then-empty poll is a
        # normal return, never a client-side timeout.
        self._timeout = timeout
        self._post = post
        self._session: str | None = None
        # The tenant this process serves, pinned at first establishment and
        # held in memory only: a connector may be moved to a different
        # deployment by a restart, never by whatever its relay address
        # resolves to today. None = never established.
        self._tenant: str | None = None
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
            message = (body.get("error") or {}).get("message") or ""
            if status == 401 and _body_code(body) == "pairing_revoked":
                raise TokenRejected("the relay rejected the pairing token")
            if status == 426:
                raise ProtocolMismatch(message or "protocol version mismatch")
            if status == 409:
                raise KeyBusy(
                    message or "another connector is already connected with this pairing token"
                )
            session = body.get("session_token")
            if status != 200 or not session:
                raise RelayUnavailable(
                    f"the relay answered HTTP {status}"
                    + (f": {message}" if message else " without a session token")
                )
            # A relay that names no tenant (an older deployment) pins the
            # empty name - the check still catches a later move to a relay
            # that does name one.
            tenant = str(body.get("tenant") or "")
            if self._tenant is None:
                self._tenant = tenant
            elif tenant != self._tenant:
                raise TenantChanged(
                    f"this relay now answers for tenant {tenant or '(unnamed)'!r}, not "
                    f"{self._tenant or '(unnamed)'!r} - a connector moves tenants only "
                    "by a deliberate restart with that tenant's relay and token"
                )
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
        if status == 401 and _body_code(body) == "pairing_revoked":
            raise TokenRejected("the relay rejected the pairing token")
        if status == 401:
            # Expired, unknown to a restarted relay, or refused by something
            # in front of it: all read "establish again", and establishment
            # is the one place a revoked pairing is named as such.
            self._drop_session()
            raise SessionExpired("the session ended; establish a new one")
        if status >= 500:
            raise RelayUnavailable(
                (body.get("error") or {}).get("message") or f"the relay answered HTTP {status}"
            )
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
