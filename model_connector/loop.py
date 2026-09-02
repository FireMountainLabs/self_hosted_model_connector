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
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import NoReturn
from urllib.parse import urlsplit

from model_connector import client as client_mod
from model_connector import tls

PROTOCOL = 1
TOKEN_ENV = "MODEL_CONNECTOR_TOKEN"  # noqa: S105 - the env var's NAME, not a secret
_RETRY_SLEEP_SECS = 2.0


def _die(message: str) -> NoReturn:
    print(f"model-connector: {message}", file=sys.stderr)
    raise SystemExit(2)


def load_token(token_file: str | None) -> str:
    """The pairing token, from the environment or a file - never argv, where
    every user on the machine could read it from the process list."""
    env = (os.environ.get(TOKEN_ENV) or "").strip()
    if env:
        return env
    if token_file:
        try:
            content = open(token_file, encoding="utf-8").read().strip()
        except OSError as exc:
            _die(f"could not read the token file: {exc}")
        if content:
            return content
        _die(f"the token file {token_file!r} is empty")
    _die(f"no pairing token: set {TOKEN_ENV} or pass --token-file")


def egress_facts(relay: str) -> str:
    """Every destination this process will dial, in the process's own words -
    for the firewall reviewer who approves rules from statements, quoted
    from the tool that makes the connections."""
    r = urlsplit(relay)
    host = r.hostname or relay
    port = r.port or (443 if r.scheme == "https" else 80)
    return (
        "model-connector egress:\n"
        f"  dials out to: {host} port {port} over HTTPS (AES-256 verified per connection)\n"
        "  and to: the model server address your deployment names per request -\n"
        "    a machine on this network, set in your deployment's Settings\n"
        "  listens on: nothing - this process opens no inbound sockets, ever\n"
        "  no other destinations"
    )


def validate_relay_url(relay: str) -> None:
    """Refuse a startup that would dial out unencrypted: everything that
    leaves this machine for the relay must ride TLS."""
    r = urlsplit(relay)
    if r.scheme != "https" and (r.hostname or "") not in tls.LOOPBACK_HOSTS:
        _die(f"the relay URL must be https (got {relay!r})")


def model_url_refusal(model_url: str, allow_plain: bool) -> str | None:
    """None when the job's model server address is usable, else the refusal
    in plain words. A refusal is a per-job TYPED RESULT, never an exit: the
    address arrives from the deployment with each request (set in the
    deployment's Settings beside the model choice), and a bad value there deserves an
    error the admin reads on their screen, not a dead connector on a box
    they may not be watching. The unencrypted-off-machine rule stays this
    side of the wire: only the box's
    operator can judge their own network, so the acknowledgment is theirs
    (--allow-plain-http-model-url), never a Settings field."""
    if not model_url:
        return (
            "the deployment did not name a model server for this request - set its "
            'address beside "A model on your own network" on the Settings page'
        )
    m = urlsplit(model_url)
    if m.scheme not in ("http", "https"):
        return f"the model server address must be http(s) (got {model_url!r})"
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - as above
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        return {"error": {"message": f"the model server answered HTTP {exc.code}: {detail}"}}
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
        with urllib.request.urlopen(  # noqa: S310 - scheme constrained by validate_urls
            model_url.rstrip("/") + "/models", timeout=5
        ) as resp:
            data = json.loads(resp.read())
        return [str(m.get("id")) for m in data.get("data", []) if m.get("id")][:20]
    except Exception:  # noqa: BLE001 - best-effort read; empty is a fine declaration
        return []


def serve(
    relay_client: client_mod.RelayClient,
    concurrency: int,
    *,
    allow_plain: bool = False,
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
            print(f"model-connector: serving job {job['job_id']}")
            url = str(job.get("model_url") or "")
            refusal = model_url_refusal(url, allow_plain)
            if refusal:
                answer = {"error": {"message": refusal}}
            else:
                last_url["value"] = url
                answer = call(url, job["payload"])
            relay_client.result(job["job_id"], answer)

    def loop_forever() -> None:
        while not stop.is_set():
            try:
                one_cycle()
            except client_mod.TokenRejected:
                print(
                    "model-connector: the pairing was revoked; stopping "
                    "(generate a new token in Settings to pair again)",
                    file=sys.stderr,
                )
                exit_code["value"] = 2
                stop.set()
            except client_mod.ProtocolMismatch as exc:
                print(f"model-connector: {exc}; update the connector", file=sys.stderr)
                exit_code["value"] = 2
                stop.set()
            except Exception as exc:  # noqa: BLE001 - the loop outlives any one failure
                print(f"model-connector: transport hiccup ({exc}); retrying", file=sys.stderr)
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
