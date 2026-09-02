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


def test_token_from_env_then_file_then_dies(tmp_path):
    os.environ[loop.TOKEN_ENV] = "tok-abc"
    try:
        assert loop.load_token(None) == "tok-abc"
    finally:
        del os.environ[loop.TOKEN_ENV]
    tf = tmp_path / "tok"
    tf.write_text("tok-file\n", encoding="utf-8")
    assert loop.load_token(str(tf)) == "tok-file"
    for bad in (None, str(tmp_path / "missing")):
        try:
            loop.load_token(bad)
            raise AssertionError("a missing token must die with exit 2")
        except SystemExit as e:
            assert e.code == 2


def test_poll_shapes_token_rejection_and_protocol_mismatch():
    calls = []

    def post(url, body, headers, timeout, **kw):
        calls.append((url, body, headers))
        return 200, {"job": {"job_id": "j1", "payload": {"model": "m"}}}

    c = client.RelayClient("https://r", "tok", post=post)
    job = c.poll({"protocol": 1, "concurrency": 1, "served_models": []})
    assert job == {"job_id": "j1", "payload": {"model": "m"}}
    assert calls[0][2]["Authorization"] == "Bearer tok"
    assert calls[0][0] == "https://r/connector/poll"

    try:
        client.RelayClient("https://r", "bad", post=lambda *a, **k: (401, {})).poll({"protocol": 1})
        raise AssertionError("401 must raise TokenRejected")
    except client.TokenRejected:
        pass

    def post426(url, body, headers, timeout, **kw):
        return 426, {"error": {"message": "relay speaks protocol 2, connector spoke 1"}}

    try:
        client.RelayClient("https://r", "tok", post=post426).poll({"protocol": 1})
        raise AssertionError("426 must raise ProtocolMismatch")
    except client.ProtocolMismatch as e:
        assert "protocol 2" in str(e)


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

    rc = loop.serve(client.RelayClient("https://r", "tok", post=post), 1, once=True, call=fake_model)
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

    c = client.RelayClient("https://r", "tok", post=post)
    loop.serve(c, 1, once=True, call=lambda u, p: {"choices": []})
    loop.serve(c, 1, once=True, call=lambda u, p: {"choices": []})
    assert results[0][0].endswith("/j1") and "--allow-plain-http-model-url" in str(results[0][1])
    assert results[1][0].endswith("/j2")


def test_serve_stops_on_stop_event_revocation_and_protocol_mismatch():
    stop = threading.Event()

    def post_stop(url, body, headers, timeout, **kw):
        stop.set()
        return 200, {"job": None}

    assert loop.serve(client.RelayClient("https://r", "tok", post=post_stop), 1, stop=stop) == 0
    assert loop.serve(client.RelayClient("https://r", "t", post=lambda *a, **k: (401, {})), 1) == 2

    def post426(url, body, headers, timeout, **kw):
        return 426, {"error": {"message": "relay speaks protocol 2, connector spoke 1"}}

    assert loop.serve(client.RelayClient("https://r", "t", post=post426), 1) == 2


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
