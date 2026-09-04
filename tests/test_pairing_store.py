"""The stored pairing: one owner-only file per user, keyed by relay address,
holding the pasted token between runs so a restart pairs without a person.
The file is written only after the relay accepted the token and removed the
moment the relay refuses it - so it never holds a token that is not
currently paired."""

from __future__ import annotations

import json
import os
import stat

from model_connector import pairing


def test_round_trip_keyed_by_relay(tmp_path):
    p = tmp_path / "pairings.json"
    a = pairing.PairingStore("https://relay-a", path=p)
    b = pairing.PairingStore("https://relay-b/", path=p)
    assert a.load() is None
    a.save("tok-a")
    assert a.load() == "tok-a"
    # Keyed by relay: one machine can hold pairings to several deployments,
    # and a trailing slash is the same relay.
    assert b.load() is None
    b.save("tok-b")
    assert pairing.PairingStore("https://relay-b", path=p).load() == "tok-b"
    assert pairing.PairingStore("https://relay-a/", path=p).load() == "tok-a"
    a.forget()
    assert a.load() is None and b.load() == "tok-b"
    b.forget()
    # The last entry takes the file with it: nothing is left to find.
    assert not p.exists()
    b.forget()  # forgetting twice is fine


def test_owner_only_on_posix(tmp_path):
    if os.name != "posix":
        return
    p = tmp_path / "dir" / "pairings.json"
    pairing.PairingStore("https://r", path=p).save("t")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
    # A rewrite keeps the mode (mkstemp's own mode is 0600 too, but the
    # replace must not widen it).
    pairing.PairingStore("https://r2", path=p).save("t2")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_malformed_file_reads_as_absent_and_is_replaced(tmp_path):
    p = tmp_path / "pairings.json"
    p.write_text("{not json", encoding="utf-8")
    s = pairing.PairingStore("https://r", path=p)
    assert s.load() is None
    s.save("t")
    assert s.load() == "t"
    for bad in (json.dumps({"https://r": "not-a-dict"}), json.dumps(["list"]), ""):
        p.write_text(bad, encoding="utf-8")
        assert s.load() is None
    p.write_text(json.dumps({"https://r": {"token": ""}}), encoding="utf-8")
    assert s.load() is None


def test_the_token_never_appears_in_the_file_name_or_the_directory_listing(tmp_path):
    p = tmp_path / "pairings.json"
    pairing.PairingStore("https://r", path=p).save("secret-tok")
    assert sorted(os.listdir(tmp_path)) == ["pairings.json"]  # no temp file left behind


def test_default_path_is_per_user(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    path = pairing.default_path()
    assert path.parent.parent == tmp_path
    assert path.parent.name == "model-connector"
    assert path.name == "pairings.json"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.delenv("APPDATA")
    # With neither variable the path is under the user's home, never the cwd.
    assert pairing.default_path().is_relative_to(os.path.expanduser("~"))
