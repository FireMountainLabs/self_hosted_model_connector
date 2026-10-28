"""The egress printout states the scheme the connector will actually dial.
``validate_relay_url`` admits plain http for a loopback relay, so the line a
security reviewer quotes must not claim HTTPS or AES-256 for that connection
(#20). Run with ``python -m pytest tests``; no test opens a socket."""

from __future__ import annotations

import contextlib
import io

from model_connector import __main__ as main_mod
from model_connector import loop


def test_https_relay_states_https_and_aes256():
    text = loop.egress_facts("https://relay.example")
    assert "dials out to: relay.example port 443 over HTTPS" in text
    assert "AES-256 verified per connection" in text
    assert "plain HTTP" not in text


def test_plain_http_loopback_relay_states_plain_http_without_aes256():
    text = loop.egress_facts("http://127.0.0.1:8525")
    assert "dials out to: 127.0.0.1 port 8525 over plain HTTP" in text
    assert "accepted only for a loopback relay" in text
    assert "never leaves this machine" in text
    assert "HTTPS" not in text
    assert "AES-256" not in text


def test_print_egress_flag_prints_the_loopback_scheme():
    # Through the CLI: the loopback relay passes validate_relay_url, so the
    # flag prints, and what it prints is the plain-HTTP statement.
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main_mod.main(["--relay", "http://127.0.0.1:8525", "--print-egress"])
    assert rc == 0
    text = out.getvalue()
    assert "127.0.0.1 port 8525 over plain HTTP" in text
    assert "AES-256" not in text
    assert "no inbound sockets" in text
