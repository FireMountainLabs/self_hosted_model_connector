"""Where the pasted pairing token lives between runs.

One file per user, keyed by relay address, readable by the owner only. The
token is written after the relay has accepted it once and removed the
moment the relay refuses it, so the file never holds a token that is not
currently paired. Nothing else is stored: the model server address arrives
per request from the deployment, and the tenant pin is memory-only by
design (a restart is the one deliberate way to move a connector).

The posture is that of an SSH key or a cloud CLI login - a credential on
disk under the account's own permissions. Anyone who can read this file as
this user could already read the running process, so the file adds no
exposure on the machine itself; what it adds is that a copy of the home
directory carries the pairing, which is why revocation in Settings must
stay one click away and why one token serves one connector.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

_FILENAME = "pairings.json"


def default_path() -> Path:
    """The per-user location: the platform's configuration directory, never
    the working directory (a connector started from a shared folder must not
    leave its token there)."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "model-connector" / _FILENAME


def _key(relay: str) -> str:
    return relay.rstrip("/")


class PairingStore:
    """The stored token for one relay address."""

    def __init__(self, relay: str, path: str | os.PathLike | None = None) -> None:
        self._relay = _key(relay)
        self.path = Path(path) if path is not None else default_path()

    def _read_all(self) -> dict:
        # A file that cannot be read or parsed is treated as absent and
        # replaced on the next save: a damaged file must cost one paste, not
        # a support call.
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write_all(self, data: dict) -> None:
        if not data:
            self.path.unlink(missing_ok=True)
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.path.parent, 0o700)
        # Written beside the target and renamed into place, so a crash mid-
        # write leaves the previous file intact and never a half-written one.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".pairings-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            if os.name == "posix":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self) -> str | None:
        entry = self._read_all().get(self._relay)
        token = entry.get("token") if isinstance(entry, dict) else None
        return token if isinstance(token, str) and token else None

    def save(self, token: str) -> None:
        data = self._read_all()
        data[self._relay] = {"token": token}
        self._write_all(data)

    def forget(self) -> None:
        data = self._read_all()
        data.pop(self._relay, None)
        self._write_all(data)
