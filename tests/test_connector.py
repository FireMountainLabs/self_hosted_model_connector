"""The connector's promises, executed: refusals before insecure bytes, typed
per-job errors instead of dead loops, one secret only ever in the
environment, and nothing beyond the standard library. Run with
``python -m pytest tests``; no test opens a real socket - transport is an
injected callable."""

from __future__ import annotations

import contextlib
import io
import os
import threading

from model_connector import __main__ as main_mod
from model_connector import client, loop


def test_plain_http_relay_refused():
    try:
        loop.validate_relay_url("http://relay.example/x")
        raise AssertionError("non-https relay must refuse")
    except SystemExit as e:
        assert e.code == 2


def test_loopback_relay_allowed_for_tests():
    loop.validate_relay_url("http://127.0.0.1:9/x")


def test_model_url_refusal_is_a_result_not_an_exit():
    # The address arrives from the deployment with each job, so a bad one is
    # a typed per-job refusal the admin reads on their screen - never a dead
    # connector on a box nobody is watching.
    assert "--allow-plain-http-model-url" in (
        loop.model_url_refusal("http://192.168.1.9:8080/v1", False) or ""
    )
    assert loop.model_url_refusal("http://192.168.1.9:8080/v1", True) is None
    assert loop.model_url_refusal("http://127.0.0.1:8080/v1", False) is None
    assert loop.model_url_refusal("https://m.example/v1", False) is None
    assert "Settings" in (loop.model_url_refusal("", False) or "")
    refusal = loop.model_url_refusal("ftp://127.0.0.1/v1", False)
    assert refusal is not None and "http(s)" in refusal


def _client(post, source=lambda: "tok"):
    c = client.RelayClient("https://r", source, post=post)
    c.establish()
    return c


def _session_post(inner):
    """Wrap a poll/result stub with a session endpoint answering 'sess-1'."""

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            return 200, {"session_token": "sess-1", "ttl_seconds": 3600}
        return inner(url, body, headers, timeout, **kw)

    return post


def test_token_sources_command_file_env(tmp_path):
    # Command: stdout stripped is the token; a failure carries the CLI's own
    # words; consulted per call, so rotation needs no restart.
    assert loop.make_token_source("printf ' tok-cmd \n'", None)() == "tok-cmd"
    try:
        loop.make_token_source("echo nope >&2; exit 3", None)()
        raise AssertionError("a failing command must raise TokenSourceError")
    except loop.TokenSourceError as e:
        assert "3" in str(e) and "nope" in str(e)
    try:
        loop.make_token_source("true", None)()
        raise AssertionError("an empty stdout must raise")
    except loop.TokenSourceError as e:
        assert "nothing" in str(e)

    # File: re-read per call - a rotated file is picked up with no restart.
    tf = tmp_path / "tok"
    tf.write_text("first\n", encoding="utf-8")
    src = loop.make_token_source(None, str(tf))
    assert src() == "first"
    tf.write_text("rotated\n", encoding="utf-8")
    assert src() == "rotated"

    # Env: the development fallback, read fresh; absent names the production
    # pattern first.
    src = loop.make_token_source(None, None)
    os.environ[loop.TOKEN_ENV] = "tok-env"
    try:
        assert src() == "tok-env"
    finally:
        del os.environ[loop.TOKEN_ENV]
    try:
        src()
        raise AssertionError("no source must raise")
    except loop.TokenSourceError as e:
        assert "--token-command" in str(e)


def test_establish_uses_the_pairing_token_once_and_keeps_only_the_session():
    seen = {"auth": []}

    def post(url, body, headers, timeout, **kw):
        seen["auth"].append(headers["Authorization"])
        if url.endswith("/connector/session"):
            return 200, {"session_token": "sess-9", "ttl_seconds": 3600}
        return 200, {"job": None}

    calls = {"n": 0}

    def source():
        calls["n"] += 1
        return "pairing-tok"

    c = client.RelayClient("https://r", source, post=post)
    c.establish()
    c.poll({"protocol": 2})
    assert seen["auth"][0] == "Bearer pairing-tok"
    assert seen["auth"][1] == "Bearer sess-9"
    assert calls["n"] == 1
    # The pairing token is retained nowhere on the client.
    assert "pairing-tok" not in repr(vars(c))


def test_session_expiry_reestablishes_and_revocation_stops():
    minted = {"n": 0}

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            minted["n"] += 1
            return 200, {"session_token": f"sess-{minted['n']}", "ttl_seconds": 3600}
        if headers["Authorization"] == "Bearer sess-1":
            return 401, {"error": {"code": "session_expired"}}
        return 200, {"job": None}

    c = client.RelayClient("https://r", lambda: "tok", post=post)
    c.establish()
    try:
        c.poll({"protocol": 2})
        raise AssertionError("an expired session must raise SessionExpired")
    except client.SessionExpired:
        pass
    c.establish()
    assert c.poll({"protocol": 2}) is None  # sess-2 serves

    try:
        client.RelayClient(
            "https://r", lambda: "tok", post=lambda *a, **k: (401, {"error": {"code": "pairing_revoked"}})
        ).establish()
        raise AssertionError("a revoked pairing must raise TokenRejected")
    except client.TokenRejected:
        pass


def test_poll_shapes_token_rejection_and_protocol_mismatch():
    calls = []

    def post(url, body, headers, timeout, **kw):
        calls.append((url, body, headers))
        return 200, {"job": {"job_id": "j1", "payload": {"model": "m"}}}

    c = _client(_session_post(post))
    job = c.poll({"protocol": 2, "concurrency": 1, "served_models": []})
    assert job == {"job_id": "j1", "payload": {"model": "m"}}
    assert calls[0][2]["Authorization"] == "Bearer sess-1"
    assert calls[0][0] == "https://r/connector/poll"

    def post426(url, body, headers, timeout, **kw):
        return 426, {"error": {"message": "relay speaks protocol 3, connector spoke 2"}}

    try:
        client.RelayClient("https://r", lambda: "tok", post=post426).establish()
        raise AssertionError("426 must raise ProtocolMismatch")
    except client.ProtocolMismatch as e:
        assert "protocol 3" in str(e)


def test_serve_once_calls_the_jobs_own_address_and_posts_result():
    seen = {}

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/poll"):
            return 200, {
                "job": {"job_id": "j9", "payload": {"p": 1}, "model_url": "http://127.0.0.1:8080/v1"}
            }
        seen["result_url"], seen["result_body"] = url, body
        return 200, {}

    def fake_model(model_url, payload, timeout=290.0):
        assert model_url == "http://127.0.0.1:8080/v1"
        assert payload == {"p": 1}
        return {"choices": [{"message": {"content": "hi"}}]}

    rc = loop.serve(_client(_session_post(post)), 1, once=True, call=fake_model)
    assert rc == 0
    assert seen["result_url"] == "https://r/connector/result/j9"
    assert "choices" in seen["result_body"]


def test_an_unsanctioned_address_answers_typed_and_the_loop_lives_on():
    results = []
    jobs = [
        {"job_id": "j1", "payload": {"p": 1}, "model_url": "http://192.168.1.9:8080/v1"},
        {"job_id": "j2", "payload": {"p": 2}, "model_url": "http://127.0.0.1:8080/v1"},
    ]

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/poll"):
            return 200, {"job": jobs.pop(0) if jobs else None}
        results.append((url, body))
        return 200, {}

    c = _client(_session_post(post))
    loop.serve(c, 1, once=True, call=lambda u, p: {"choices": []})
    loop.serve(c, 1, once=True, call=lambda u, p: {"choices": []})
    assert results[0][0].endswith("/j1") and "--allow-plain-http-model-url" in str(results[0][1])
    assert results[1][0].endswith("/j2")


def test_serve_stops_on_stop_event_revocation_and_protocol_mismatch():
    stop = threading.Event()

    def post_stop(url, body, headers, timeout, **kw):
        stop.set()
        return 200, {"job": None}

    assert loop.serve(_client(_session_post(post_stop)), 1, stop=stop) == 0
    assert loop.serve(_client(_session_post(lambda *a, **k: (401, {}))), 1) == 2

    def post426(url, body, headers, timeout, **kw):
        return 426, {"error": {"message": "relay speaks protocol 3, connector spoke 2"}}

    assert loop.serve(_client(_session_post(post426)), 1) == 2


def test_call_model_failures_become_typed_errors():
    out = loop.call_model("http://127.0.0.1:1/v1", {"x": 1}, timeout=0.2)
    assert "error" in out and out["error"].get("message")


def test_print_egress_states_the_surface_without_a_token():
    # For the firewall reviewer: the process states every destination it
    # will dial and exits 0, before any token is loaded. A plain-http relay
    # still refuses first - the flag never describes a connection the
    # connector would not make.
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main_mod.main(["--relay", "https://relay.example:8443/x", "--print-egress"])
    assert rc == 0
    text = out.getvalue()
    assert "relay.example port 8443" in text
    assert "no inbound sockets" in text
    assert "model server address" in text
    try:
        main_mod.main(["--relay", "http://relay.example/x", "--print-egress"])
        raise AssertionError("plain-http relay must refuse before printing")
    except SystemExit as e:
        assert e.code == 2


def test_stdlib_only_package():
    import model_connector

    pkg_dir = os.path.dirname(model_connector.__file__)
    for name in sorted(os.listdir(pkg_dir)):
        if not name.endswith(".py"):
            continue
        src = open(os.path.join(pkg_dir, name), encoding="utf-8").read()
        for banned in ("fastapi", "requests", "httpx", "aiohttp", "pip"):
            assert f"import {banned}" not in src and f"from {banned}" not in src
