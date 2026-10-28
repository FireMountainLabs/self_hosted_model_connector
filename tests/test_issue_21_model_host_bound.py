"""The --model-host bound covers scheme, host and port, not the host alone,
and the suffix a job's kind implies is appended to the PATH of the split
model URL, never to the raw string (#21). A query, fragment or credential in
the address is refused outright: none of the three names a server's base
address, and a trailing "#" or "?" on the raw string would otherwise eat the
intended path."""

from __future__ import annotations

import http.server
import io
import threading

from model_connector import __main__ as main_mod
from model_connector import loop


def _listener(handler_cls):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


class _PathRecorder(http.server.BaseHTTPRequestHandler):
    """Records the request path it received and answers 200 with an empty
    JSON object, so call_model and list_models both parse the reply."""

    seen: list[str] = []

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._answer()

    def do_GET(self):
        self._answer()

    def _answer(self):
        type(self).seen.append(self.path)
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_bound_refuses_a_port_the_operator_did_not_name():
    # A bare host in --model-host covers only its scheme's default port;
    # naming a different port on the same host must still be refused.
    allowed = frozenset({"10.0.0.5"})
    refusal = loop.model_url_refusal("https://10.0.0.5:22/", False, allowed)
    assert refusal is not None and "10.0.0.5:22" in refusal and "--model-host" in refusal


def test_bound_accepts_the_port_it_names():
    allowed = frozenset({"10.0.0.5:8443"})
    assert loop.model_url_refusal("https://10.0.0.5:8443/v1", False, allowed) is None
    # A different port on the same host is still outside this bound.
    refusal = loop.model_url_refusal("https://10.0.0.5:9999/v1", False, allowed)
    assert refusal is not None and "10.0.0.5:9999" in refusal


def test_bound_matches_a_bare_hosts_default_port_by_scheme():
    # A bare host covers its scheme's own default port - 443 for an https
    # job, 80 for an http one - whichever the job in hand asks for.
    allowed = frozenset({"m.internal"})
    assert loop.model_url_refusal("https://m.internal/v1", False, allowed) is None
    assert loop.model_url_refusal("https://m.internal:443/v1", False, allowed) is None
    assert loop.model_url_refusal("http://m.internal/v1", True, allowed) is None
    # A port that is neither scheme's default is still outside the bound.
    refusal = loop.model_url_refusal("https://m.internal:8443/v1", False, allowed)
    assert refusal is not None and "m.internal:8443" in refusal


def test_query_fragment_and_credentials_are_refused_as_a_typed_result():
    # None of these ever has a place in a server's base address; a refusal
    # here is a typed per-job result, never an exception.
    for bad in (
        "http://127.0.0.1:9/v1?x=1",
        "http://127.0.0.1:9/admin/reset#",
        "http://user:pass@127.0.0.1:9/v1",
    ):
        refusal = loop.model_url_refusal(bad, False)
        assert refusal is not None and "query, fragment or credentials" in refusal


def test_call_model_joins_the_suffix_onto_the_path_not_the_raw_string():
    _PathRecorder.seen = []
    srv, t = _listener(_PathRecorder)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/x#"
        out = loop.call_model(url, {"p": 1}, timeout=5)
    finally:
        srv.shutdown()
        t.join(timeout=5)
    assert out == {}
    assert _PathRecorder.seen == ["/x/chat/completions"]


def test_list_models_joins_the_suffix_onto_the_path_not_the_raw_string():
    _PathRecorder.seen = []
    srv, t = _listener(_PathRecorder)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/x?"
        loop.list_models(url, timeout=5)
    finally:
        srv.shutdown()
        t.join(timeout=5)
    assert _PathRecorder.seen == ["/x/models"]


def test_ipv6_literal_round_trips_through_the_bound():
    allowed = frozenset({"[::1]:8080"})
    assert loop.model_url_refusal("http://[::1]:8080/v1", False, allowed) is None
    refusal = loop.model_url_refusal("http://[::1]:9/v1", False, allowed)
    assert refusal is not None and "[::1]:9" in refusal


def test_model_host_rejects_a_malformed_entry_at_argv():
    # Anything beyond host[:port] - a scheme, a path, embedded credentials -
    # would otherwise be silently normalised into a bound that matches no
    # job's address, leaving the operator believing themselves protected.
    import argparse

    for bad in ("https://10.0.0.5", "10.0.0.5/v1", "u@10.0.0.5", "10.0.0.5:abc"):
        try:
            main_mod._model_host(bad)
            raise AssertionError(f"expected a refusal for {bad!r}")
        except argparse.ArgumentTypeError:
            pass


def test_model_host_help_names_host_and_port():
    out = io.StringIO()
    import contextlib

    with contextlib.redirect_stdout(out):
        try:
            main_mod.main(["--help"])
        except SystemExit:
            pass
    assert "HOST[:PORT]" in out.getvalue()


def test_egress_model_line_names_what_the_bound_covers():
    text = loop.egress_facts("https://relay.example", frozenset({"m.internal"}))
    assert "scheme, host and port" in text
