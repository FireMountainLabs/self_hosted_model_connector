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
    # words; consulted per call, so rotation needs no restart. The commands
    # here are python one-liners so the same test runs on every OS the
    # matrix does - a real operator writes their platform's own command.
    import sys

    py = f'"{sys.executable}" -c'
    assert loop.make_token_source(f"{py} \"print(' tok-cmd ')\"", None)() == "tok-cmd"
    try:
        loop.make_token_source(
            f"{py} \"import sys; print('nope', file=sys.stderr); sys.exit(3)\"", None
        )()
        raise AssertionError("a failing command must raise TokenSourceError")
    except loop.TokenSourceError as e:
        assert "3" in str(e) and "nope" in str(e)
    try:
        loop.make_token_source(f"{py} \"pass\"", None)()
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


def test_no_source_in_a_terminal_asks_once_and_holds_the_paste(monkeypatch):
    # The copy-paste path: a person at a terminal is asked once, with input
    # hidden, and the paste is held in memory for the hourly re-establishment
    # - never written anywhere. Without a terminal there is no prompt: the
    # sources are named and the process exits, so a service never hangs on a
    # prompt nobody will see.
    monkeypatch.delenv(loop.TOKEN_ENV, raising=False)
    asked = []

    def fake_getpass(prompt):
        asked.append(prompt)
        return "  pasted-tok \n"

    monkeypatch.setattr(loop.getpass, "getpass", fake_getpass)
    monkeypatch.setattr(loop, "_interactive", lambda: True)
    src = loop.make_token_source(None, None)
    assert src() == "pasted-tok"
    assert src() == "pasted-tok"
    assert len(asked) == 1 and "hidden" in asked[0]
    # The environment still wins when set - the development shortcut is not
    # silently replaced by a prompt.
    monkeypatch.setenv(loop.TOKEN_ENV, "env-tok")
    assert loop.make_token_source(None, None)() == "env-tok"
    monkeypatch.delenv(loop.TOKEN_ENV)

    monkeypatch.setattr(loop.getpass, "getpass", lambda prompt: "   ")
    try:
        loop.make_token_source(None, None)()
        raise AssertionError("an empty paste must raise")
    except loop.TokenSourceError as e:
        assert "nothing was pasted" in str(e)

    def never(prompt):
        raise AssertionError("no prompt without a terminal")

    monkeypatch.setattr(loop, "_interactive", lambda: False)
    monkeypatch.setattr(loop.getpass, "getpass", never)
    try:
        loop.make_token_source(None, None)()
        raise AssertionError("no terminal and no source must raise")
    except loop.TokenSourceError as e:
        assert "terminal" in str(e) and "--token-command" in str(e)


def test_interactive_is_the_terminal_check(monkeypatch):
    import io

    monkeypatch.setattr(loop.sys, "stdin", io.StringIO())
    assert loop._interactive() is False
    monkeypatch.setattr(loop.sys, "stdin", None)
    assert loop._interactive() is False

    class Closed:
        def isatty(self):
            raise ValueError("closed")

    monkeypatch.setattr(loop.sys, "stdin", Closed())
    assert loop._interactive() is False


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


def test_result_survives_a_session_that_expired_mid_job():
    """A session ages out while the job is in flight: the answer is not
    dropped - the loop establishes once and retries the delivery."""
    minted = {"n": 0}
    delivered = []

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            minted["n"] += 1
            return 200, {"session_token": f"sess-{minted['n']}", "ttl_seconds": 1}
        if url.endswith("/connector/poll"):
            return 200, {
                "job": {"job_id": "j1", "payload": {}, "model_url": "http://127.0.0.1:8080/v1"}
            }
        if headers["Authorization"] == "Bearer sess-1":
            return 401, {"error": {"code": "session_expired"}}
        delivered.append(headers["Authorization"])
        return 200, {}

    c = client.RelayClient("https://r", lambda: "tok", post=post)
    c.establish()
    rc = loop.serve(c, 1, once=True, call=lambda u, p: {"choices": []})
    assert rc == 0
    assert delivered == ["Bearer sess-2"]
    assert minted["n"] == 2


def test_call_model_failures_become_typed_errors():
    out = loop.call_model("http://127.0.0.1:1/v1", {"x": 1}, timeout=0.2)
    assert "error" in out and out["error"].get("message")


def test_an_unreachable_relay_at_startup_is_one_sentence(monkeypatch, capsys):
    # The first establishment runs while the operator watches: a relay that
    # cannot be reached (DNS, network, firewall) or one that will not carry
    # AES-256 must end in a sentence naming the address and the reason - the
    # stack trace a bare socket error would print is not an answer.
    monkeypatch.setenv(loop.TOKEN_ENV, "tok")

    class Unreachable:
        def __init__(self, relay, source):
            pass

        def establish(self):
            raise OSError("nodename nor servname provided, or not known")

    monkeypatch.setattr(main_mod.client, "RelayClient", Unreachable)
    try:
        main_mod.main(["--relay", "https://relay.invalid"])
        raise AssertionError("an unreachable relay must exit")
    except SystemExit as e:
        assert e.code == 2
    err = capsys.readouterr().err
    assert "could not reach the relay at https://relay.invalid" in err
    assert "nodename" in err and "Traceback" not in err

    class WeakCipher(Unreachable):
        def establish(self):
            raise main_mod.tls.Aes256Error("the relay offered TLS_CHACHA20, not AES-256")

    monkeypatch.setattr(main_mod.client, "RelayClient", WeakCipher)
    try:
        main_mod.main(["--relay", "https://relay.invalid"])
        raise AssertionError("a weak cipher must exit")
    except SystemExit as e:
        assert e.code == 2
    assert "not AES-256" in capsys.readouterr().err


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


def test_model_host_allowlist_bounds_forwarding():
    # The operator's bound on where the process forwards, from argv only -
    # a compromised platform must not gain a request-maker into the network.
    allowed = frozenset({"model.internal"})
    refusal = loop.model_url_refusal("https://other.internal/v1", False, allowed)
    assert refusal is not None and "--model-host" in refusal and "other.internal" in refusal
    assert loop.model_url_refusal("https://model.internal/v1", False, allowed) is None
    assert loop.model_url_refusal("https://MODEL.internal/v1", False, allowed) is None
    # An empty bound means the operator declined one; behavior is unchanged.
    assert loop.model_url_refusal("https://anywhere.example/v1", False, frozenset()) is None


def test_serve_refuses_a_job_outside_the_model_host_bound():
    results = []

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/poll"):
            return 200, {
                "job": {"job_id": "j1", "payload": {}, "model_url": "https://evil.example/v1"}
            }
        results.append(body)
        return 200, {}

    c = _client(_session_post(post))
    loop.serve(
        c,
        1,
        once=True,
        allowed_hosts=frozenset({"model.internal"}),
        call=lambda u, p: (_ for _ in ()).throw(AssertionError("must not forward")),
    )
    assert "--model-host" in str(results[0])


def test_redirects_are_never_followed():
    # A probed service answering 302 must become a typed error, not a second
    # request to a host nobody named.
    import http.server

    class Redirector(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        out = loop.call_model(f"http://127.0.0.1:{srv.server_port}/v1", {"x": 1}, timeout=5)
    finally:
        srv.shutdown()
    assert "302" in out["error"]["message"]


def test_oversize_response_is_refused_unread():
    from model_connector import tls

    assert tls.read_capped(io.BytesIO(b"x" * 10), cap=10) == b"x" * 10
    try:
        tls.read_capped(io.BytesIO(b"x" * 11), cap=10)
        raise AssertionError("an oversize body must raise")
    except tls.OversizeResponse as e:
        assert "exceeded" in str(e)


def test_clean_strips_terminal_control_characters():
    # Wire-originated text cannot rewrite the operator's terminal.
    assert loop.clean("\x1b[2Jjob-1\r\x07") == " [2Jjob-1  "
    assert loop.clean("plain\nline") == "plain\nline"
    assert loop.clean("\x7f") == " "


def test_world_readable_token_file_warns_once(tmp_path):
    if os.name != "posix":
        return  # no comparable mode bits to check on Windows
    import sys

    tf = tmp_path / "tok"
    tf.write_text("t\n", encoding="utf-8")
    tf.chmod(0o644)
    src = loop.make_token_source(None, str(tf))
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert src() == "t"
        assert src() == "t"
    assert err.getvalue().count("readable by other accounts") == 1

    tf.chmod(0o600)
    err2 = io.StringIO()
    with contextlib.redirect_stderr(err2):
        assert loop.make_token_source(None, str(tf))() == "t"
    assert err2.getvalue() == ""


def test_result_delivery_survives_a_token_source_blip():
    """The mid-delivery re-establishment retries through a briefly
    unreachable secrets manager instead of dropping the job's answer."""
    minted = {"n": 0}
    delivered = []
    source_calls = {"n": 0}

    def source():
        source_calls["n"] += 1
        if source_calls["n"] == 2:  # the re-establishment's first attempt
            raise loop.TokenSourceError("manager blinked")
        return "tok"

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            minted["n"] += 1
            return 200, {"session_token": f"sess-{minted['n']}", "ttl_seconds": 1}
        if url.endswith("/connector/poll"):
            return 200, {
                "job": {"job_id": "j1", "payload": {}, "model_url": "http://127.0.0.1:8080/v1"}
            }
        if headers["Authorization"] == "Bearer sess-1":
            return 401, {"error": {"code": "session_expired"}}
        delivered.append(headers["Authorization"])
        return 200, {}

    c = client.RelayClient("https://r", source, post=post)
    c.establish()
    sleep = loop._RETRY_SLEEP_SECS
    loop._RETRY_SLEEP_SECS = 0.01
    try:
        rc = loop.serve(c, 1, once=True, call=lambda u, p: {"choices": []})
    finally:
        loop._RETRY_SLEEP_SECS = sleep
    assert rc == 0
    assert delivered == ["Bearer sess-2"]
    assert source_calls["n"] == 3


def test_print_egress_names_the_model_host_bound():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main_mod.main(
            ["--relay", "https://relay.example/x", "--print-egress", "--model-host", "M.internal"]
        )
    assert rc == 0
    text = out.getvalue()
    assert "m.internal only (--model-host)" in text
    assert "redirects are never followed" in text


def test_tenant_is_pinned_across_establishments():
    """The relay's session answer names its tenant; the connector pins the
    first name and refuses a later move - a re-pointed relay address must
    never silently change which deployment a running connector serves."""
    tenants = ["acme", "acme", "other"]

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            return 200, {
                "session_token": "s",
                "ttl_seconds": 3600,
                "tenant": tenants.pop(0),
            }
        return 200, {"job": None}

    c = client.RelayClient("https://r", lambda: "tok", post=post)
    c.establish()  # pins "acme"
    c._drop_session()
    c.establish()  # same tenant re-establishes fine
    c._drop_session()
    try:
        c.establish()
        raise AssertionError("a changed tenant must raise TenantChanged")
    except client.TenantChanged as e:
        assert "acme" in str(e) and "other" in str(e)


def test_a_tenant_move_stops_the_serve_loop():
    calls = {"n": 0}

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            calls["n"] += 1
            return 200, {
                "session_token": f"s{calls['n']}",
                "ttl_seconds": 3600,
                "tenant": "acme" if calls["n"] == 1 else "other",
            }
        # Every poll answers session_expired, forcing a re-establishment,
        # which then answers the wrong tenant.
        return 401, {"error": {"code": "session_expired"}}

    c = client.RelayClient("https://r", lambda: "tok", post=post)
    c.establish()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = loop.serve(c, 1)
    assert rc == 2
    assert "tenant" in err.getvalue()


def test_a_relay_naming_no_tenant_stays_compatible():
    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            return 200, {"session_token": "s", "ttl_seconds": 3600}
        return 200, {"job": None}

    c = client.RelayClient("https://r", lambda: "tok", post=post)
    c.establish()
    c._drop_session()
    c.establish()  # the empty name pins and re-pins without complaint
    assert c.poll({"protocol": 2}) is None


def test_stdlib_only_package():
    import model_connector

    pkg_dir = os.path.dirname(model_connector.__file__)
    for name in sorted(os.listdir(pkg_dir)):
        if not name.endswith(".py"):
            continue
        src = open(os.path.join(pkg_dir, name), encoding="utf-8").read()
        for banned in ("fastapi", "requests", "httpx", "aiohttp", "pip"):
            assert f"import {banned}" not in src and f"from {banned}" not in src
