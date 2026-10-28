"""The archive a consumer hash-pins is a source tree, so an installer still
runs a build backend to put ``model_connector/`` into site-packages - and
pip's isolated build fetches that backend from PyPI by whatever
``[build-system].requires`` allows, with no hash, whatever the lock says. An
exact pin is what lets a consumer install the one tool that unpacks the
archive by hash first and then build without isolation (#24). These tests
hold the pin exact, and hold the README's recipe to the same version, so the
two cannot drift apart."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A release pin and nothing else: no extras, no markers, no range, no URL.
EXACT_PIN = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==(\d+(?:\.\d+)+)$")


def _build_system():
    with (ROOT / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["build-system"]


def _pinned():
    pins = {}
    for entry in _build_system()["requires"]:
        m = EXACT_PIN.match(entry)
        assert m, f"build requirement is not an exact == pin: {entry!r}"
        pins[m.group(1).lower()] = m.group(2)
    return pins


def test_build_requires_are_exact_pins_on_setuptools():
    build = _build_system()
    assert build["build-backend"] == "setuptools.build_meta"
    assert build["requires"], "an empty requires lets pip choose any backend"
    assert "setuptools" in _pinned()


def test_readme_recipe_names_the_pinned_setuptools():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    named = set(re.findall(r"setuptools==(\d+(?:\.\d+)+)", readme))
    assert named == {_pinned()["setuptools"]}, named
    # The recipe only verifies anything if the backend is installed by hash
    # and then actually used, so both halves must be present beside the pin.
    assert re.search(r"setuptools==[\d.]+[^\n]*\\?\n?[^\n]*--hash=sha256:[0-9a-f]{64}", readme)
    assert "--no-build-isolation" in readme
