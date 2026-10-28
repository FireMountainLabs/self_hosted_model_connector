"""The model hop dials the address it was given, whatever proxy settings the
environment carries (#22).

The opener is built once, at import, and a default ProxyHandler reads the
environment at construction - so a test that sets http_proxy after the
module is imported would pass against the defect. The connector is therefore
run in a child process that inherits the proxied environment, the way a
service manager would hand it one, with both the "proxy" and the model
server listening on loopback in this process.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

from model_connector import loop

_ROOT = Path(__file__).resolve().parent.parent

# Run in the child: forward one job, then report which proxies the module's
# opener registered, beside those an opener built the default way registers
# in the same environment. OpenerDirector keeps only a handler that can open
# some scheme, so an empty ProxyHandler leaves no trace in `handlers` while a
# populated one is listed with its proxies.
_CHILD = """
import json, sys, urllib.request
from model_connector import loop


def proxies_of(opener):
    return [h.proxies for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]


result = loop.call_model(sys.argv[1], {"x": 1}, timeout=10)
default = urllib.request.build_opener(loop._NoRedirect)
report = {"result": result, "ours": proxies_of(loop._opener), "default": proxies_of(default)}
print(json.dumps(report))
"""


class _CountingListener:
    """A raw loopback listener standing in for the proxy: it answers nothing
    useful, it only counts who dialled it."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            self.connections += 1
            with conn:
                conn.settimeout(1)
                try:
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


class _ModelServer(http.server.BaseHTTPRequestHandler):
    seen: list[str] = []

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).seen.append(self.path)
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _proxied_env(monkeypatch, proxy_port: int) -> dict[str, str]:
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{proxy_port}")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_ROOT)
    return env


def test_call_model_ignores_proxy_settings(monkeypatch):
    proxy = _CountingListener()
    _ModelServer.seen = []
    model = http.server.HTTPServer(("127.0.0.1", 0), _ModelServer)
    threading.Thread(target=model.serve_forever, daemon=True).start()
    model_url = f"http://127.0.0.1:{model.server_port}/v1"
    env = _proxied_env(monkeypatch, proxy.port)
    try:
        child = subprocess.run(  # noqa: S603 - argv is this test's own interpreter and script
            [sys.executable, "-c", _CHILD, model_url],
            cwd=_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert child.returncode == 0, child.stderr
        report = json.loads(child.stdout)

        # The POST reached the model server directly, and the proxy saw nothing.
        assert report["result"] == {"choices": [{"message": {"content": "ok"}}]}
        assert _ModelServer.seen == ["/v1/chat/completions"]
        assert proxy.connections == 0

        # Loopback is the only address a test can dial without a network, and
        # urllib bypasses a proxy for it only via no_proxy (unset here). For
        # every other host the pin is structural: the opener registered no
        # proxy for any scheme, so no request to any host is rewritten - while
        # the default construction, in the same environment, registered the
        # proxy for both schemes.
        assert report["ours"] == []
        assert [d["http"] for d in report["default"]] == [f"http://127.0.0.1:{proxy.port}"]
        assert [d["https"] for d in report["default"]] == [f"http://127.0.0.1:{proxy.port}"]

        # Control: in the same environment, an opener built the default way
        # does send the bytes to the proxy - so the zero above is a measurement,
        # not a listener nobody could have reached.
        default_opener = urllib.request.build_opener(loop._NoRedirect)
        try:
            default_opener.open(
                urllib.request.Request(model_url + "/chat/completions", data=b"{}"), timeout=5
            )
        except urllib.error.HTTPError as exc:
            assert exc.code == 502
        assert proxy.connections == 1
        assert _ModelServer.seen == ["/v1/chat/completions"]
    finally:
        model.shutdown()
        model.server_close()
        proxy.close()


def test_the_opener_carries_no_proxy_for_any_scheme():
    # In this process the environment may well be clean, so this alone would
    # not catch the defect (the child-process test above does); it pins the
    # shape the fix relies on: no handler that opens a scheme through a proxy.
    assert not any(isinstance(h, urllib.request.ProxyHandler) for h in loop._opener.handlers)
    for scheme in ("http", "https"):
        assert not any(
            isinstance(h, urllib.request.ProxyHandler) for h in loop._opener.handle_open[scheme]
        )


def test_the_egress_statement_says_proxies_are_ignored():
    text = loop.egress_facts("https://relay.example/x")
    assert "redirects are never followed" in text
    assert "proxy settings" in text and "ignored" in text
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    # Wrapped prose: compare on one line rather than pin the exact wrap.
    assert "proxy settings in the environment and the system are ignored" in " ".join(
        readme.split()
    )
