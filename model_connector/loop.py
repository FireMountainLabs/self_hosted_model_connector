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
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import NoReturn
from urllib.parse import urlsplit

from model_connector import client as client_mod
from model_connector import tls

PROTOCOL = 2
TOKEN_ENV = "MODEL_CONNECTOR_TOKEN"  # noqa: S105 - the env var's NAME, not a secret
_RETRY_SLEEP_SECS = 2.0

# The relay is not allowed to steer this process through a redirect: a probed
# service answering 302 must become a typed error, never a second request to
# a host nobody named. Returning None makes the handler re-raise the 3xx as
# the HTTPError the caller already turns into a typed result.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def clean(text: object) -> str:
    """Text that originated on the wire, made safe for a terminal: a hostile
    relay must not be able to rewrite what the operator sees (or spoof the
    egress statement) with escape sequences."""
    return "".join(ch if ch >= " " and ch != "\x7f" or ch == "\n" else " " for ch in str(text))


def _die(message: str) -> NoReturn:
    print(f"model-connector: {message}", file=sys.stderr)
    raise SystemExit(2)


class TokenSourceError(RuntimeError):
    """The token source could not produce a token right now. At startup this
    is fatal (a misconfigured source deserves a sentence while the operator
    is watching); mid-run it is a retry, because a briefly unreachable
    secrets manager must not kill a connector a revocation would not have."""


def make_token_source(command: str | None, token_file: str | None):
    """The pairing token's source, consulted at every session establishment
    and never cached - the credential's home is the secrets manager (or the
    managed file), not this process. Precedence: command, then file, then
    the environment variable (development only; the environment is exactly
    where machine eyes look first). Never argv: every user on the machine
    can read a process's arguments.

    The command runs through the shell so manager pipelines work verbatim
    (e.g. a CLI call piped through a JSON extractor); it is the operator's
    own command on the operator's own machine. Its stdout, stripped, is the
    token; its stderr is surfaced in the failure, because "exit 1" from a
    manager CLI without its words is undiagnosable."""
    if command:

        def from_command() -> str:
            try:
                proc = subprocess.run(  # noqa: S602 - the operator's own command, by design
                    command, shell=True, capture_output=True, text=True, timeout=30
                )
            except subprocess.TimeoutExpired as exc:
                raise TokenSourceError(f"the token command timed out: {exc}") from exc
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()[:300]
                raise TokenSourceError(
                    f"the token command exited {proc.returncode}: {detail or 'no output'}"
                )
            token = proc.stdout.strip()
            if not token:
                raise TokenSourceError("the token command printed nothing")
            return token

        return from_command
    if token_file:
        warned = {"done": False}

        def from_file() -> str:
            try:
                if os.name == "posix" and not warned["done"]:
                    if os.stat(token_file).st_mode & 0o077:
                        # A warning, not a refusal: only the operator can
                        # judge their box, and Windows has no mode bits at
                        # all - but a world-readable credential deserves a
                        # sentence, the way SSH gives keys one.
                        print(
                            f"model-connector: warning: {token_file!r} is readable by "
                            "other accounts on this machine (consider chmod 600)",
                            file=sys.stderr,
                        )
                    warned["done"] = True
                content = open(token_file, encoding="utf-8").read().strip()
            except OSError as exc:
                raise TokenSourceError(f"could not read the token file: {exc}") from exc
            if not content:
                raise TokenSourceError(f"the token file {token_file!r} is empty")
            return content

        return from_file

    def from_env() -> str:
        env = (os.environ.get(TOKEN_ENV) or "").strip()
        if not env:
            raise TokenSourceError(
                f"no pairing token: pass --token-command (a secrets manager CLI - the "
                f"production pattern), --token-file, or set {TOKEN_ENV} (development)"
            )
        return env

    return from_env


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
            "    requests naming any other model server are refused"
        )
    else:
        model_line = (
            "  and to: the model server address your deployment names per request -\n"
            "    a machine on this network, set in your deployment's Settings\n"
            "    (bound this with --model-host to refuse every other address)"
        )
    return (
        "model-connector egress:\n"
        f"  dials out to: {host} port {port} over HTTPS (AES-256 verified per connection)\n"
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
    forward (--model-host, lowercased). The deployment names the address,
    but the box's operator names the network: a compromised platform must
    not gain a request-maker that can reach anything the box can. Empty
    means the operator declined to bound it - the flag is the boundary, and
    it lives in argv, never in anything the relay sends."""
    if not model_url:
        return (
            "the deployment did not name a model server for this request - set its "
            'address beside "A model on your own network" on the Settings page'
        )
    m = urlsplit(model_url)
    if m.scheme not in ("http", "https"):
        return f"the model server address must be http(s) (got {model_url!r})"
    if allowed_hosts and (m.hostname or "").lower() not in allowed_hosts:
        return (
            f"this connector only forwards to {', '.join(sorted(allowed_hosts))} "
            f"(--model-host); the request named {m.hostname!r}"
        )
    if m.scheme == "http" and (m.hostname or "") not in tls.LOOPBACK_HOSTS and not allow_plain:
        return (
            f"plain http to {m.hostname!r} would send documents across your network "
            "unencrypted; use https, or start the connector with "
            "--allow-plain-http-model-url to accept that"
        )
    return None


def call_model(model_url: str, payload: dict, timeout: float = 290.0) -> dict:
    """Forward one job to the local model server; failures come back as a
    typed error body, never an exception - the relay forwards it to the
    engine, which already knows how to say 'the model endpoint failed'."""
    req = urllib.request.Request(  # noqa: S310 - scheme constrained by validate_urls
        model_url.rstrip("/") + "/chat/completions",
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
    }


def _served_models(model_url: str) -> list[str]:
    """Best-effort read of the local server's /models; an empty list is fine
    (the relay's model listing just stays empty until the next declare). The
    address is the last one a job named, so before the first job there is
    nothing to ask."""
    if not model_url:
        return []
    try:
        with _opener.open(  # noqa: S310 - scheme constrained by validate_urls; never redirects
            model_url.rstrip("/") + "/models", timeout=5
        ) as resp:
            data = json.loads(tls.read_capped(resp))
        return [str(m.get("id")) for m in data.get("data", []) if m.get("id")][:20]
    except Exception:  # noqa: BLE001 - best-effort read; empty is a fine declaration
        return []


def serve(
    relay_client: client_mod.RelayClient,
    concurrency: int,
    *,
    allow_plain: bool = False,
    allowed_hosts: frozenset[str] = frozenset(),
    once: bool = False,
    call=call_model,
    stop: threading.Event | None = None,
) -> int:
    """Run the poll loops; returns an exit code. `once` does a single poll
    cycle on one thread (the smoke-test flag); `stop` lets a supervisor (or
    the contract suite) wind the loops down.

    Each job names the model server it is aimed at: the address is
    set in the deployment's Settings beside the model choice, so the box
    runs nothing but token + relay. The last address seen also feeds the
    served-models declaration on later polls."""
    stop = stop or threading.Event()
    exit_code = {"value": 0}
    # Written by whichever worker thread served last; a stale read only means
    # one declaration lists the previous server's models, corrected next poll.
    last_url = {"value": ""}

    def one_cycle() -> None:
        job = relay_client.poll(_declare(concurrency, last_url["value"]))
        if job:
            print(f"model-connector: serving job {clean(job['job_id'])}")
            url = str(job.get("model_url") or "")
            refusal = model_url_refusal(url, allow_plain, allowed_hosts)
            if refusal:
                answer = {"error": {"message": refusal}}
            else:
                last_url["value"] = url
                answer = call(url, job["payload"])
            try:
                relay_client.result(job["job_id"], answer)
            except client_mod.SessionExpired:
                # A session can age out DURING a held poll or a long model
                # call; the job was legitimately claimed and its answer must
                # not be dropped for that - not for the expiry, and not for a
                # secrets manager that blinks during the re-establishment
                # either. Retry the establishment on the usual backoff until
                # it lands (or the pairing is revoked, which propagates); a
                # second expiry inside one delivery is not a clock, it is a
                # revocation-shaped problem, and propagates as such.
                while not stop.is_set():
                    try:
                        relay_client.establish()
                        break
                    except TokenSourceError as exc:
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
                except TokenSourceError as exc:
                    print(f"model-connector: {clean(exc)}; retrying", file=sys.stderr)
                    stop.wait(_RETRY_SLEEP_SECS)
                except client_mod.TokenRejected:
                    # Revocation surfacing at re-establishment must stop the
                    # loop exactly like revocation surfacing anywhere else -
                    # not kill this one worker thread quietly.
                    print(
                        "model-connector: the pairing was revoked; stopping "
                        "(generate a new token in Settings to pair again)",
                        file=sys.stderr,
                    )
                    exit_code["value"] = 2
                    stop.set()
                except client_mod.TenantChanged as exc:
                    print(f"model-connector: {clean(exc)}; stopping", file=sys.stderr)
                    exit_code["value"] = 2
                    stop.set()
            except client_mod.TokenRejected:
                print(
                    "model-connector: the pairing was revoked; stopping "
                    "(generate a new token in Settings to pair again)",
                    file=sys.stderr,
                )
                exit_code["value"] = 2
                stop.set()
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
        one_cycle()
        return 0
    threads = [threading.Thread(target=loop_forever, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    while not stop.is_set():
        time.sleep(0.1)
    for t in threads:
        t.join(timeout=5)
    return exit_code["value"]
