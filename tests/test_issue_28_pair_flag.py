"""A second connector on a machine that already holds a token for the same
relay (#28). The saved token is the first connector's and in use, so a plain
start earns only a busy answer; ``--pair`` asks for the new token instead and
remembers it in place of the saved one, and the busy refusal of a saved token
says where that token came from and how to pair with a new one."""

from __future__ import annotations

from model_connector import __main__ as main_mod
from model_connector import client, loop, pairing

RELAY = "https://relay.invalid"


def _quick_busy_wait(monkeypatch):
    monkeypatch.setattr(loop, "_BUSY_RETRY_SECS", 0.2)
    monkeypatch.setattr(loop, "_BUSY_RETRY_STEP", 0.05)


def test_pair_ignores_the_saved_token_and_remembers_the_pasted_one(monkeypatch, capsys, tmp_path):
    p = tmp_path / "p.json"
    pairing.PairingStore(RELAY, path=p).save("first-connectors-tok")
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)
    monkeypatch.setattr(loop, "_interactive", lambda: True)
    asked = []

    def fake_getpass(prompt):
        asked.append(prompt)
        return "second-tok\n"

    monkeypatch.setattr(loop.getpass, "getpass", fake_getpass)
    offered = []

    class Fine:
        def __init__(self, relay, source):
            self.source = source

        def establish(self):
            offered.append(self.source())
            # Nothing is written until the relay has accepted the paste: a
            # mistyped second token must not displace the first connector's.
            assert pairing.PairingStore(RELAY, path=p).load() == "first-connectors-tok"

    monkeypatch.setattr(main_mod.client, "RelayClient", Fine)
    monkeypatch.setattr(main_mod.loop, "serve", lambda *a, **kw: 0)
    assert main_mod.main(["--relay", RELAY, "--pair"]) == 0
    assert len(asked) == 1 and "hidden" in asked[0]
    assert offered == ["second-tok"]
    # Remembered in place of the saved token: one token per relay in the file.
    assert pairing.PairingStore(RELAY, path=p).load() == "second-tok"
    out = capsys.readouterr().out
    assert "remembered on this machine" in out and str(p) in out
    assert "second-tok" not in out and "first-connectors-tok" not in out


def test_pair_without_a_terminal_refuses_and_keeps_the_saved_token(monkeypatch, capsys, tmp_path):
    p = tmp_path / "p.json"
    pairing.PairingStore(RELAY, path=p).save("tok")
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)
    monkeypatch.setattr(loop, "_interactive", lambda: False)

    def never(prompt):
        raise AssertionError("no prompt without a terminal")

    monkeypatch.setattr(loop.getpass, "getpass", never)

    class Fine:
        def __init__(self, relay, source):
            self.source = source

        def establish(self):
            self.source()

    monkeypatch.setattr(main_mod.client, "RelayClient", Fine)
    try:
        main_mod.main(["--relay", RELAY, "--pair"])
        raise AssertionError("--pair without a terminal must exit")
    except SystemExit as e:
        assert e.code == 2
    err = capsys.readouterr().err
    assert "no pairing token" in err and "terminal" in err and "Traceback" not in err
    assert pairing.PairingStore(RELAY, path=p).load() == "tok"


def test_a_busy_saved_token_names_the_file_and_the_pair_flag(monkeypatch, capsys, tmp_path):
    p = tmp_path / "p.json"
    pairing.PairingStore(RELAY, path=p).save("s3cret-first")
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)
    _quick_busy_wait(monkeypatch)

    def never(prompt):
        raise AssertionError("no prompt with a stored token")

    monkeypatch.setattr(loop.getpass, "getpass", never)

    class Busy:
        def __init__(self, relay, source):
            self.source = source

        def establish(self):
            # The fake relay's 409 connector_busy, as the session post shapes it.
            self.source()
            raise client.KeyBusy("another connector holds it")

    monkeypatch.setattr(main_mod.client, "RelayClient", Busy)
    try:
        main_mod.main(["--relay", RELAY])
        raise AssertionError("a busy saved token must exit after the wait")
    except SystemExit as e:
        assert e.code == 2
    err = capsys.readouterr().err
    last = err.strip().splitlines()[-1]
    assert str(p) in last and RELAY in last and "--pair" in last
    assert "saved" in last and "another connector" in last
    assert "s3cret-first" not in err
    # Busy is not revoked: the first connector's token stays on disk.
    assert pairing.PairingStore(RELAY, path=p).load() == "s3cret-first"


def test_a_busy_pasted_token_keeps_the_plain_message(monkeypatch, capsys, tmp_path):
    # Pasted this run (nothing saved, or --pair): the token did not come from
    # the file, so the refusal must not point at one.
    p = tmp_path / "p.json"
    pairing.PairingStore(RELAY, path=p).save("tok")
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)
    monkeypatch.setattr(loop, "_interactive", lambda: True)
    monkeypatch.setattr(loop.getpass, "getpass", lambda prompt: "pasted")
    _quick_busy_wait(monkeypatch)

    class Busy:
        def __init__(self, relay, source):
            self.source = source

        def establish(self):
            self.source()
            raise client.KeyBusy("another connector holds it")

    monkeypatch.setattr(main_mod.client, "RelayClient", Busy)
    try:
        main_mod.main(["--relay", RELAY, "--pair"])
        raise AssertionError("a busy pasted token must exit after the wait")
    except SystemExit as e:
        assert e.code == 2
    last = capsys.readouterr().err.strip().splitlines()[-1]
    assert "another connector" in last and "generate another" in last
    assert str(p) not in last and "--pair" not in last
    # A paste the relay did not accept is never written: the saved token stays.
    assert pairing.PairingStore(RELAY, path=p).load() == "tok"


def test_from_file_tracks_where_the_token_in_hand_came_from(monkeypatch, tmp_path):
    store = pairing.PairingStore(RELAY, path=tmp_path / "p.json")
    monkeypatch.setattr(loop, "_interactive", lambda: True)
    monkeypatch.setattr(loop.getpass, "getpass", lambda prompt: "pasted")

    # Nothing saved: the paste is the source, and never "from file" - not
    # even after remember() has written it.
    src = loop.make_token_source(store)
    assert src.from_file is False
    assert src() == "pasted" and src.from_file is False
    src.remember()
    assert src.from_file is False

    # Saved: loaded, and from the file, until forgotten.
    src = loop.make_token_source(store)
    assert src.from_file is True and src() == "pasted"
    src.forget()
    assert src.from_file is False

    # Saved but ignored: the paste wins, and the file is untouched until
    # the relay accepts.
    store.save("saved")
    src = loop.make_token_source(store, ignore_saved=True)
    assert src.from_file is False and src() == "pasted" and src.pasted is True
    assert store.load() == "saved"
    src.remember()
    assert store.load() == "pasted"
