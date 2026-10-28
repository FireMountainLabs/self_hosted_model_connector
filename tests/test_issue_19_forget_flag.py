"""``--forget``: the connector's half of a revocation. Settings revokes the
token on the platform; this flag removes it from this machine, and is the
half that still works when the platform cannot be reached. It must act on
the pairing file alone - no relay client, no token source, no socket - so a
machine whose access was severed can still clean itself up."""

from __future__ import annotations

import socket

from model_connector import __main__ as main_mod
from model_connector import pairing

RELAY_A = "https://relay-a.example/x"
RELAY_B = "https://relay-b.example/x"


def _isolate(monkeypatch, tmp_path):
    """Point the per-user pairing file into a temporary directory, and make
    any attempt at a network byte fail the test."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))

    class NeverBuilt:
        def __init__(self, *a, **kw):
            raise AssertionError("--forget must not construct a RelayClient")

    def never_source(*a, **kw):
        raise AssertionError("--forget must not build a token source")

    def never_connect(self, *a, **kw):
        raise AssertionError("--forget must not open a socket")

    monkeypatch.setattr(main_mod.client, "RelayClient", NeverBuilt)
    monkeypatch.setattr(main_mod.loop, "make_token_source", never_source)
    monkeypatch.setattr(socket.socket, "connect", never_connect)
    return pairing.default_path()


def test_forget_removes_this_relays_entry_and_leaves_the_others(monkeypatch, capsys, tmp_path):
    path = _isolate(monkeypatch, tmp_path)
    pairing.PairingStore(RELAY_A).save("tok-a")
    pairing.PairingStore(RELAY_B).save("tok-b")

    assert main_mod.main(["--relay", RELAY_A, "--forget"]) == 0

    assert pairing.PairingStore(RELAY_A).load() is None
    assert pairing.PairingStore(RELAY_B).load() == "tok-b"
    out = capsys.readouterr().out
    assert str(path) in out and RELAY_A in out
    # The line never lets a cleared file read as a revoked token: it says
    # this machine only, and where the other half of the revocation lives.
    assert "this machine only" in out and "Settings" in out
    assert "tok-a" not in out and "tok-b" not in out


def test_forget_with_nothing_saved_says_so_and_exits_zero(monkeypatch, capsys, tmp_path):
    path = _isolate(monkeypatch, tmp_path)
    assert not path.exists()

    assert main_mod.main(["--relay", RELAY_A, "--forget"]) == 0

    out = capsys.readouterr().out
    assert "nothing was saved" in out and RELAY_A in out and str(path) in out
    # Asking about an absent pairing must not create the file or its directory.
    assert not path.exists()


def test_forgetting_the_last_entry_takes_the_file_with_it(monkeypatch, capsys, tmp_path):
    path = _isolate(monkeypatch, tmp_path)
    pairing.PairingStore(RELAY_A).save("tok-a")
    assert path.exists()

    assert main_mod.main(["--relay", RELAY_A, "--forget"]) == 0
    assert not path.exists()
    # A trailing slash is the same relay, as everywhere else in the store.
    pairing.PairingStore(RELAY_A).save("tok-a")
    assert main_mod.main(["--relay", RELAY_A + "/", "--forget"]) == 0
    assert not path.exists()
    capsys.readouterr()


def test_forget_still_refuses_a_plain_http_relay_first(monkeypatch, capsys, tmp_path):
    # The relay address is validated before any flag acts on it, as it is
    # for --print-egress; no flag describes or touches a connection the
    # connector would refuse to make.
    _isolate(monkeypatch, tmp_path)
    try:
        main_mod.main(["--relay", "http://relay.example/x", "--forget"])
        raise AssertionError("plain-http relay must refuse before forgetting")
    except SystemExit as e:
        assert e.code == 2


def test_forget_help_says_the_token_stays_valid_on_the_platform(capsys):
    try:
        main_mod.main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    text = capsys.readouterr().out
    assert "--forget" in text
    assert "Settings" in text and "revoked" in text
