"""Issue #23: a hostile or confused relay must never put raw wire text, an
escape sequence, an unbounded body, or a traceback on the operator's
terminal at startup. Run with ``python -m pytest tests``."""

from __future__ import annotations

from model_connector import __main__ as main_mod
from model_connector import client, loop, pairing


def test_a_500_with_escape_sequences_at_startup_prints_no_escape_byte(
    monkeypatch, capsys, tmp_path
):
    # The reported reproduction: a fake relay answering 500 with a cursor-move,
    # a window-title spoof, and a trailing "FAKE: paired OK" tried to rewrite
    # the operator's terminal through RelayUnavailable's message.
    p = tmp_path / "p.json"
    pairing.PairingStore("https://relay.invalid", path=p).save("tok")
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)
    # _establish_while_watching retries RelayUnavailable for _BUSY_RETRY_SECS
    # before giving up; shorten the wait so the test does not sit there.
    monkeypatch.setattr(loop, "_BUSY_RETRY_SECS", 0.0)
    monkeypatch.setattr(loop, "_BUSY_RETRY_STEP", 0.01)

    class Hostile:
        def __init__(self, relay, source):
            pass

        def establish(self):
            raise client.RelayUnavailable(
                "the relay answered HTTP 500: x\x1b[2J\x1b[H\x1b]0;pwned\x07FAKE: paired OK"
            )

    monkeypatch.setattr(main_mod.client, "RelayClient", Hostile)
    try:
        main_mod.main(["--relay", "https://relay.invalid"])
        raise AssertionError("a hostile 500 at startup must exit")
    except SystemExit as e:
        assert e.code == 2
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "the pairing is kept" in err and "Traceback" not in err
    # The pairing is not revoked, so the next start needs no paste.
    assert pairing.PairingStore("https://relay.invalid", path=p).load() == "tok"


def test_a_426_at_startup_is_one_line_not_a_traceback(monkeypatch, capsys, tmp_path):
    p = tmp_path / "p.json"
    pairing.PairingStore("https://relay.invalid", path=p).save("tok")
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)

    class SpeaksV3:
        def __init__(self, relay, source):
            pass

        def establish(self):
            raise client.ProtocolMismatch("this relay speaks protocol 3")

    monkeypatch.setattr(main_mod.client, "RelayClient", SpeaksV3)
    try:
        main_mod.main(["--relay", "https://relay.invalid"])
        raise AssertionError("a 426 at startup must exit, not raise")
    except SystemExit as e:
        assert e.code == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "protocol 3" in err and "update the connector" in err
    assert "Traceback" not in err


def test_a_non_http_answer_at_startup_is_one_line_not_a_traceback(monkeypatch, capsys, tmp_path):
    # http.client.BadStatusLine and kin are HTTPException, not OSError - a
    # listener on the port that is not the relay must not crash main.
    import http.client

    p = tmp_path / "p.json"
    pairing.PairingStore("https://relay.invalid", path=p).save("tok")
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)

    class NotTheRelay:
        def __init__(self, relay, source):
            pass

        def establish(self):
            raise http.client.BadStatusLine("NOPE\r\n")

    monkeypatch.setattr(main_mod.client, "RelayClient", NotTheRelay)
    try:
        main_mod.main(["--relay", "https://relay.invalid"])
        raise AssertionError("a non-HTTP answer at startup must exit, not raise")
    except SystemExit as e:
        assert e.code == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "did not answer HTTP" in err and "BadStatusLine" in err
    assert "Traceback" not in err


def test_clean_strips_c1_controls_and_caps_length():
    # U+009B and U+0085 are the 8-bit spellings some terminals read as CSI and
    # NEL; a relay must not reach a terminal's escape handling through either.
    assert loop.clean("a\x9bb\x85c") == "a b c"
    long_text = "x" * (loop.CLEAN_MAX_CHARS + 500)
    cleaned = loop.clean(long_text)
    assert len(cleaned) == loop.CLEAN_MAX_CHARS
    assert cleaned.endswith("...")
    assert cleaned.startswith("x" * 10)
    # Text at or under the cap is returned whole, with no marker appended.
    exact = "y" * loop.CLEAN_MAX_CHARS
    assert loop.clean(exact) == exact


def test_die_cleans_whatever_it_is_given(capsys):
    # _die is the single place every exit-2 refusal prints through; it must
    # clean its own argument rather than trust every call site to have done so.
    try:
        loop._die("x\x1b[2Jpwned")
        raise AssertionError("_die must exit")
    except SystemExit as e:
        assert e.code == 2
    err = capsys.readouterr().err
    # clean() neutralises the escape byte itself, not the printable characters
    # that followed it - matching loop.clean's existing contract.
    assert "\x1b" not in err
    assert "x [2Jpwned" in err


def test_https_post_json_treats_a_deeply_nested_body_like_malformed_json(monkeypatch):
    # json.loads raises RecursionError, not ValueError, past a few thousand
    # levels of nesting - a peer must not be able to crash this process with
    # brackets alone.
    from model_connector import tls

    class _Resp:
        status = 200

        def read(self, n):
            return (b"[" * 100000) + (b"]" * 100000)

    class _Conn:
        def __init__(self, *a, **k):
            pass

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(tls.http.client, "HTTPConnection", _Conn)
    status, body = tls.https_post_json("http://127.0.0.1/x", {}, {}, 5)
    assert (status, body) == (200, {})


def test_body_code_tolerates_a_non_dict_error_field():
    assert client._body_code({"error": "x"}) == ""
    assert client._body_code({"error": None}) == ""
    assert client._body_code({}) == ""
    assert client._body_code({"error": {"code": "pairing_revoked"}}) == "pairing_revoked"


def test_establish_tolerates_a_non_dict_error_on_every_coded_status(monkeypatch):
    # The same (body.get("error") or {}).get("message") shape appeared at
    # establishment and in poll/result's status check; a string or null
    # "error" must read as "no message", never raise.
    def post_with(status, body):
        return lambda *a, **k: (status, body)

    for status, body in (
        (401, {"error": "nope"}),
        (409, {"error": 1}),
        (426, {"error": []}),
        (500, {"error": "boom"}),
    ):
        c = client.RelayClient("https://relay", lambda: "tok", post=post_with(status, body))
        try:
            c.establish()
            raise AssertionError(f"status {status} must raise")
        except (
            client.TokenRejected,
            client.KeyBusy,
            client.ProtocolMismatch,
            client.RelayUnavailable,
        ):
            pass

    c2 = client.RelayClient("https://relay", lambda: "tok", post=post_with(200, {}))
    c2._session = "s"
    for status, body in ((500, {"error": "boom"}), (426, {"error": None})):
        c2._post = post_with(status, body)
        try:
            c2.poll_reply({})
            raise AssertionError(f"status {status} must raise")
        except (client.RelayUnavailable, client.ProtocolMismatch):
            pass
