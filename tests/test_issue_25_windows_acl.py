"""What the stored pairing file is protected by, said truthfully per platform.
``_write_all`` narrows the mode only on POSIX; the standard library has no
portable ACL call, so on Windows the file keeps the profile folder's own
permissions. The startup line, the README and the spec must each say so
rather than promise an owner-only file everywhere."""

from __future__ import annotations

import re
from pathlib import Path

from model_connector import __main__ as main_mod
from model_connector import loop, pairing

_ROOT = Path(__file__).resolve().parent.parent
_WINDOWS_WORDING = "profile folder's own permissions"


def test_permissions_note_follows_the_platform(monkeypatch):
    monkeypatch.setattr(pairing.os, "name", "posix")
    assert pairing.permissions_note() == "owner-only file"
    monkeypatch.setattr(pairing.os, "name", "nt")
    assert pairing.permissions_note() == "file under your profile's own permissions"
    assert "owner-only" not in pairing.permissions_note()


def test_startup_line_takes_its_wording_from_the_note(monkeypatch, capsys, tmp_path):
    # The one print that names the file's protection must get its words from
    # the helper, so a Windows run does not print the POSIX promise.
    p = tmp_path / "p.json"
    monkeypatch.setattr(main_mod.pairing, "default_path", lambda: p)
    monkeypatch.setattr(main_mod.pairing, "permissions_note", lambda: "NOTE-FROM-HELPER")
    monkeypatch.setattr(loop, "_interactive", lambda: True)
    monkeypatch.setattr(loop.getpass, "getpass", lambda prompt: "pasted")

    class Fine:
        def __init__(self, relay, source):
            self.source = source

        def establish(self):
            # Asking the source for the token is what makes this a first
            # pairing; without it there is no paste and no line to check.
            assert self.source() == "pasted"

    monkeypatch.setattr(main_mod.client, "RelayClient", Fine)
    monkeypatch.setattr(main_mod.loop, "serve", lambda relay_client, concurrency, **kw: 0)
    assert main_mod.main(["--relay", "https://relay.invalid"]) == 0
    out = capsys.readouterr().out
    assert f"(NOTE-FROM-HELPER {p})" in out
    assert "owner-only" not in out


def _prose(path: Path) -> str:
    # Wrapped prose: a phrase may break across lines, so compare on one line.
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def test_readme_and_spec_say_what_windows_actually_gets():
    readme = _prose(_ROOT / "README.md")
    spec = _prose(_ROOT / "docs" / "stored-pairing-spec.md")
    for doc in (readme, spec):
        assert _WINDOWS_WORDING in doc
        assert "SYSTEM and Administrators" in doc
        assert "nothing stronger is set" in doc
    # The sentence the audit quoted promised owner-only on every platform.
    assert "only your account can read" not in readme
    # The spec gives the reason, not just the fact.
    assert "no portable ACL call" in spec
