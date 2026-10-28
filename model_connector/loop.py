"""Invocation checks and the serve loop - the part of the connector a person
watches.

Every refusal here happens before the first network byte, and each is one
sentence on stderr with exit 2: the operator at the model box gets told what
to fix, not a traceback. The loop itself is deliberately dumb - poll,
forward, post the answer, and on any transport wobble sleep briefly and poll
again. That re-poll IS the reconnect story - there is deliberately no
other one.
"""

from __future__ import annotations

import json
import getpass
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import NoReturn
from urllib.parse import urlsplit, urlunsplit

from model_connector import client as client_mod
from model_connector import pairing, tls

PROTOCOL = 2
_RETRY_SLEEP_SECS = 2.0
# A quiet relay answers an empty poll at once and names how long to wait
# before the next, because the host it runs on bills for every second a poll
# is held open. The wait is bounded here: a relay must not be able to park
# this process for longer than the bound by naming a large number.
_POLL_AFTER_MAX_SECS = 30.0
# How long a starting connector waits for a token's previous holder to go
# quiet before giving up: the relay lets a token go about a minute after its
# last poll, so a restart on the heels of a crash (a service manager's,
# typically) pairs on its own, while a token genuinely in use elsewhere is
# refused in plain words once the wait is up.
_BUSY_RETRY_SECS = 75.0
_BUSY_RETRY_STEP = 5.0

# The relay is not allowed to steer this process through a redirect: a probed
# service answering 302 must become a typed error, never a second request to
# a host nobody named. Returning None makes the handler re-raise the 3xx as
# the HTTPError the caller already turns into a typed result.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)

# The most wire text one terminal line may carry: a relay must not be able
# to fill the operator's scrollback with a multi-megabyte job id or message.
CLEAN_MAX_CHARS = 2000
_CUT_MARKER = "..."


def clean(text: object) -> str:
    """Text that originated on the wire, made safe for a terminal: a hostile
    relay must not be able to rewrite what the operator sees (or spoof the
    egress statement) with escape sequences, nor flood the screen.

    Every C0 control and DEL becomes a space, and so does the C1 range
    (U+0080 to U+009F): some terminals read U+009B as CSI and U+009D as OSC,
    the 8-bit spellings of the ESC sequences. A newline is kept. The result
    is at most CLEAN_MAX_CHARS long, ending in a marker when it was cut."""
    text = str(text)
    cut = len(text) > CLEAN_MAX_CHARS
    if cut:
        # Cut before the sweep: every character maps to exactly one, so the
        # length is the same either side, and the sweep stays bounded.
        text = text[: CLEAN_MAX_CHARS - len(_CUT_MARKER)]
    safe = "".join(
        ch if (ch >= " " and ch != "\x7f" and not "\x80" <= ch <= "\x9f") or ch == "\n" else " "
        for ch in text
    )
    return safe + _CUT_MARKER if cut else safe


def _die(message: str) -> NoReturn:
    # Every refusal passes through clean, whatever composed it: a message that
    # quotes the relay's words raw must still not reach the terminal raw.
    print(f"model-connector: {clean(message)}", file=sys.stderr)
    raise SystemExit(2)


class TokenSourceError(RuntimeError):
    """The token source could not produce a token right now. At startup this
    is fatal (a misconfigured source deserves a sentence while the operator
    is watching); mid-run it is a retry, because a source that cannot
    answer this instant must not kill a connector a revocation would not have."""


class TokenSource:
    """The pairing token's source, consulted at every session establishment.

    The stored token wins: a machine that paired once needs no person at a
    restart. Otherwise, in a terminal, the token is asked for once with input
    hidden and held in memory - never argv, where every user of the machine
    can read it, and never the environment, which is where machine eyes look
    first. Without a terminal and without a stored token there is nothing to
    do but say so: a service must never hang on a prompt nobody will see.

    A pasted token reaches disk only through ``remember()``, which the caller
    invokes after the relay has accepted it - a mistyped paste must not be
    remembered. ``forget()`` is the revocation path: the relay refused the
    token, so it leaves memory and disk together."""

    def __init__(self, store: pairing.PairingStore) -> None:
        self._store = store
        self._token: str | None = store.load()
        self.pasted = False

    def __call__(self) -> str:
        if self._token:
            return self._token
        if not _interactive():
            raise TokenSourceError(
                "no pairing token: run this once in a terminal and paste the token when "
                "asked - it is remembered on this machine afterwards, so a service needs "
                "no prompt"
            )
        pasted = getpass.getpass("Paste the pairing token (input is hidden): ").strip()
        if not pasted:
            raise TokenSourceError("nothing was pasted")
        self._token = pasted
        self.pasted = True
        return pasted

    @property
    def path(self) -> str:
        """Where a remembered token lives, for the one line that tells the
        operator so."""
        return str(self._store.path)

    def remember(self) -> None:
        if self.pasted and self._token:
            self._store.save(self._token)
            self.pasted = False

    def forget(self) -> None:
        self._token = None
        self.pasted = False
        self._store.forget()


def make_token_source(store: pairing.PairingStore) -> TokenSource:
    return TokenSource(store)


def _interactive() -> bool:
    """Whether a person is at this process: only then may the token be asked
    for. Under a service manager stdin is not a terminal, and a prompt there
    would hang or read the wrong thing - so it is refused with the sources
    named instead."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def egress_facts(relay: str, allowed_hosts: frozenset[str] = frozenset()) -> str:
    """Every destination this process will dial, in the process's own words -
    for the firewall reviewer who approves rules from statements, quoted
    from the tool that makes the connections."""
    r = urlsplit(relay)
    host = r.hostname or relay
    port = r.port or (443 if r.scheme == "https" else 80)
    if allowed_hosts:
        model_line = (
            f"  and to: {', '.join(sorted(allowed_hosts))} only (--model-host) -\n"
            "    the bound is scheme, host and port (a bare host means 443 for https,\n"
            "    80 for http); requests naming any other model server are refused"
        )
    else:
        model_line = (
            "  and to: the model server address your deployment names per request -\n"
            "    a machine on this network, set in your deployment's Settings\n"
            "    (bound this with --model-host HOST[:PORT] to refuse every other\n"
            "    scheme, host and port)"
        )
    # The scheme stated is the one the connector will dial: validate_relay_url
    # admits plain http only for a loopback relay, and an HTTPS or AES-256
    # claim about that connection would misstate the egress to the reviewer.
    if r.scheme == "https":
        transport = "over HTTPS (AES-256 verified per connection)"
    else:
        transport = (
            "over plain HTTP - accepted only for a loopback relay, so this\n"
            "    connection never leaves this machine"
        )
    return (
        "model-connector egress:\n"
        f"  dials out to: {host} port {port} {transport}\n"
        f"{model_line}\n"
        "  listens on: nothing - this process opens no inbound sockets, ever\n"
        "  no other destinations, and redirects are never followed"
    )


def validate_relay_url(relay: str) -> None:
    """Refuse a startup that would dial out unencrypted: everything that
    leaves this machine for the relay must ride TLS."""
    r = urlsplit(relay)
    if r.scheme != "https" and (r.hostname or "") not in tls.LOOPBACK_HOSTS:
        _die(f"the relay URL must be https (got {relay!r})")


def model_url_refusal(
    model_url: str, allow_plain: bool, allowed_hosts: frozenset[str] = frozenset()
) -> str | None:
    """None when the job's model server address is usable, else the refusal
    in plain words. A refusal is a per-job TYPED RESULT, never an exit: the
    address arrives from the deployment with each request (set in the
    deployment's Settings beside the model choice), and a bad value there deserves an
    error the admin reads on their screen, not a dead connector on a box
    they may not be watching. The unencrypted-off-machine rule stays this
    side of the wire: only the box's
    operator can judge their own network, so the acknowledgment is theirs
    (--allow-plain-http-model-url), never a Settings field.

    ``allowed_hosts`` is the operator's bound on where this process will
    forward (--model-host): each entry a lowercased ``host`` or
    ``host:port``, an IPv6 literal in its brackets. A bare host covers only
    its scheme's default port (443 https, 80 http), so the bound is scheme,
    host and port: a request-maker bounded to a host alone could still reach
    every service on that box, with the body the relay chose. The deployment
    names the address, but the box's operator names the network: a
    compromised platform must not gain a request-maker that can reach
    anything the box can. Empty means the operator declined to bound it -
    the flag is the boundary, and it lives in argv, never in anything the
    relay sends."""
    if not model_url:
        return (
            "the deployment did not name a model server for this request - set its "
            'address beside "A model on your own network" on the Settings page'
        )
    m = urlsplit(model_url)
    if m.scheme not in ("http", "https"):
        return f"the model server address must be http(s) (got {model_url!r})"
    # A model server's base address is scheme, host, port and path, and
    # nothing else has a meaning here: a query or fragment marks an address
    # that is not a server's base (checked on the raw text, because an empty
    # one parses away and that it was there is the finding), and credentials
    # in an address field would be sent with every request. Each is refused
    # rather than guessed at.
    if "?" in model_url or "#" in model_url or "@" in m.netloc:
        return (
            "the model server address must be scheme, host, port and path only - no "
            f"query, fragment or credentials (got {model_url!r})"
        )
    host = m.hostname or ""
    if not host:
        return f"the model server address names no host (got {model_url!r})"
    try:
        port = m.port
    except ValueError:
        return f"the model server address has an invalid port (got {model_url!r})"
    default_port = 443 if m.scheme == "https" else 80
    if port is None:
        port = default_port
    if allowed_hosts:
        key = f"[{host}]" if ":" in host else host
        named = f"{key}:{port}"
        if named not in allowed_hosts and not (key in allowed_hosts and port == default_port):
            return (
                f"this connector only forwards to {', '.join(sorted(allowed_hosts))} "
                "(--model-host; a bare host means its scheme's default port); the request "
                f"named {named}"
            )
    if m.scheme == "http" and host not in tls.LOOPBACK_HOSTS and not allow_plain:
        return (
            f"plain http to {m.hostname!r} would send documents across your network "
            "unencrypted; use https, or start the connector with "
            "--allow-plain-http-model-url to accept that"
        )
    return None


def _endpoint(model_url: str, suffix: str) -> str:
    """The model server's endpoint for one job: ``suffix`` joined onto the
    PATH of the split address. Joined onto the raw text, a ``#`` or ``?`` at
    the end of what the relay sent would make the suffix a fragment or a
    query and land the request on exactly the path the relay named.
    model_url_refusal turns those addresses away before a job gets here;
    the join is still by parts, because a builder that trusts its caller is
    one changed call site from that request."""
    m = urlsplit(model_url)
    return urlunsplit((m.scheme, m.netloc, m.path.rstrip("/") + suffix, "", ""))


def call_model(model_url: str, payload: dict, timeout: float = 290.0) -> dict:
    """Forward one job to the local model server; failures come back as a
    typed error body, never an exception - the relay forwards it to the
    engine, which already knows how to say 'the model endpoint failed'."""
    req = urllib.request.Request(  # noqa: S310 - scheme constrained by model_url_refusal
        _endpoint(model_url, "/chat/completions"),
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with _opener.open(req, timeout=timeout) as resp:  # noqa: S310 - as above; never redirects
            return json.loads(tls.read_capped(resp))
    except urllib.error.HTTPError as exc:
        # Reading the error body is itself a network read and can fail (a
        # peer that resets after its status line); the typed error stands
        # with or without the detail.
        try:
            detail = exc.read(4096).decode("utf-8", "replace")[:300]
        except OSError:
            detail = ""
        return {"error": {"message": f"the model server answered HTTP {exc.code}: {detail}"}}
    except tls.OversizeResponse as exc:
        return {"error": {"message": str(exc)}}
    except Exception as exc:  # noqa: BLE001 - any failure becomes the typed error the relay forwards
        return {"error": {"message": f"could not reach the model server: {exc}"[:300]}}


def _declare(concurrency: int, model_url: str) -> dict:
    return {
        "protocol": PROTOCOL,
        "concurrency": concurrency,
        "served_models": _served_models(model_url),
        # This connector honours poll_after; a relay holds the poll of a
        # connector that does not say so, since it would poll again at once.
        "can_wait": True,
    }


def poll_after(reply: dict) -> float:
    """Seconds to wait before the next poll, from an empty poll's reply: 0
    when the relay names none, or names something that is not a number."""
    value = reply.get("poll_after")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    if value != value:  # NaN
        return 0.0
    return min(max(float(value), 0.0), _POLL_AFTER_MAX_SECS)


def list_models(model_url: str, timeout: float = 10.0) -> dict:
    """The local server's /models, in the OpenAI shape the deployment already
    reads, or a typed error naming what failed. Ids are shaped here (one
    line, bounded, at most 20) because they are tenant-network text on their
    way to a screen. This answers a job of kind "models" - the deployment's
    question "what does this box serve?", asked before anyone picks."""
    try:
        with _opener.open(  # noqa: S310 - scheme constrained by model_url_refusal; no redirects
            _endpoint(model_url, "/models"), timeout=timeout
        ) as resp:
            data = json.loads(tls.read_capped(resp))
    except Exception as exc:  # noqa: BLE001 - any failure becomes the typed error the relay forwards
        return {"error": {"message": f"could not read the model list: {exc}"[:300]}}
    ids = []
    for m in data.get("data", []) if isinstance(data, dict) else []:
        mid = " ".join(str(m.get("id") or "").split())[:200] if isinstance(m, dict) else ""
        if mid:
            ids.append(mid)
    return {"data": [{"id": mid} for mid in ids[:20]]}


def _served_models(model_url: str) -> list[str]:
    """Best-effort read for the poll declaration; an empty list is fine (the
    relay's declared listing just stays empty until the next declare). The
    address is the last one a job named, so before the first job there is
    nothing to ask."""
    if not model_url:
        return []
    return [m["id"] for m in list_models(model_url, timeout=5).get("data", [])]


def serve(
    relay_client: client_mod.RelayClient,
    concurrency: int,
    *,
    allow_plain: bool = False,
    allowed_hosts: frozenset[str] = frozenset(),
    once: bool = False,
    call=call_model,
    models=list_models,
    stop: threading.Event | None = None,
    on_revoked=None,
) -> int:
    """Run the poll loops; returns an exit code. `once` does a single poll
    cycle on one thread (the smoke-test flag); `stop` lets a supervisor (or
    the contract suite) wind the loops down; `on_revoked` runs once when the
    relay refuses the pairing token, before the loop stops - the stored
    token's removal hangs off it.

    Each job names the model server it is aimed at: the address is
    set in the deployment's Settings beside the model choice, so the box
    runs nothing but token + relay. The last address seen also feeds the
    served-models declaration on later polls."""
    stop = stop or threading.Event()
    exit_code = {"value": 0}
    revoked_once = {"done": False}

    def revoked() -> None:
        # Revocation must stop the loop exactly the same way wherever it
        # surfaces - a poll, a re-establishment, a mid-delivery retry - and
        # the hook runs once however many workers see it.
        print(
            "model-connector: the pairing was revoked; stopping "
            "(generate a new token in Settings to pair again)",
            file=sys.stderr,
        )
        if on_revoked is not None and not revoked_once["done"]:
            revoked_once["done"] = True
            on_revoked()
        exit_code["value"] = 2
        stop.set()
    # Written by whichever worker thread served last; a stale read only means
    # one declaration lists the previous server's models, corrected next poll.
    last_url = {"value": ""}

    def one_cycle(wait: bool = True) -> None:
        reply = relay_client.poll_reply(_declare(concurrency, last_url["value"]))
        job = reply.get("job")
        if not job and wait:
            stop.wait(poll_after(reply))
        if job:
            print(f"model-connector: serving job {clean(job['job_id'])}")
            url = str(job.get("model_url") or "")
            refusal = model_url_refusal(url, allow_plain, allowed_hosts)
            if refusal:
                answer = {"error": {"message": refusal}}
            else:
                last_url["value"] = url
                # A job's kind names the question: a completion to forward, or
                # the server's model list. Anything else is a relay this
                # connector does not understand, answered as such rather than
                # forwarded as a completion it never was.
                kind = str(job.get("kind") or "completion")
                if kind == "completion":
                    answer = call(url, job["payload"])
                elif kind == "models":
                    answer = models(url)
                else:
                    answer = {
                        "error": {
                            "message": f"unknown job kind {kind!r} - update the connector"
                        }
                    }
            try:
                relay_client.result(job["job_id"], answer)
            except client_mod.SessionExpired:
                # A session can age out DURING a held poll or a long model
                # call; the job was legitimately claimed and its answer must
                # not be dropped for that - not for the expiry, not for a
                # token source that cannot answer this instant, and not for
                # a relay still counting the old session as live. Retry the
                # establishment on the usual backoff until it lands (or the
                # pairing is revoked, which propagates); a second expiry
                # inside one delivery is not a clock, it is a
                # revocation-shaped problem, and propagates as such.
                while not stop.is_set():
                    try:
                        relay_client.establish()
                        break
                    except (
                        TokenSourceError,
                        client_mod.KeyBusy,
                        client_mod.RelayUnavailable,
                    ) as exc:
                        print(f"model-connector: {clean(exc)}; retrying", file=sys.stderr)
                        stop.wait(_RETRY_SLEEP_SECS)
                if not stop.is_set():
                    relay_client.result(job["job_id"], answer)

    def loop_forever() -> None:
        while not stop.is_set():
            try:
                one_cycle()
            except client_mod.SessionExpired:
                # Expiry, or a relay restart - a non-event by design: consult
                # the source, establish again. A source failure here is a
                # retry like any transport wobble (a Vault blip must not kill
                # what a revocation would not have).
                try:
                    relay_client.establish()
                except (
                    TokenSourceError,
                    client_mod.KeyBusy,
                    client_mod.RelayUnavailable,
                ) as exc:
                    # A relay still counting the previous session as live, or
                    # one that cannot reach its store this instant, is the
                    # same class as a source that cannot answer right now:
                    # all clear on their own within the window.
                    print(f"model-connector: {clean(exc)}; retrying", file=sys.stderr)
                    stop.wait(_RETRY_SLEEP_SECS)
                except client_mod.TokenRejected:
                    revoked()
                except client_mod.TenantChanged as exc:
                    print(f"model-connector: {clean(exc)}; stopping", file=sys.stderr)
                    exit_code["value"] = 2
                    stop.set()
            except client_mod.TokenRejected:
                revoked()
            except client_mod.ProtocolMismatch as exc:
                print(f"model-connector: {clean(exc)}; update the connector", file=sys.stderr)
                exit_code["value"] = 2
                stop.set()
            except client_mod.TenantChanged as exc:
                # A moved tenant is a stop wherever it surfaces - including
                # the mid-delivery re-establishment - never a quiet retry.
                print(f"model-connector: {clean(exc)}; stopping", file=sys.stderr)
                exit_code["value"] = 2
                stop.set()
            except Exception as exc:  # noqa: BLE001 - the loop outlives any one failure
                print(f"model-connector: transport hiccup ({clean(exc)}); retrying", file=sys.stderr)
                stop.wait(_RETRY_SLEEP_SECS)

    if once:
        one_cycle(wait=False)
        return 0
    threads = [threading.Thread(target=loop_forever, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    while not stop.is_set():
        time.sleep(0.1)
    for t in threads:
        t.join(timeout=5)
    return exit_code["value"]
