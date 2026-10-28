"""Concurrent workers at a session expiry (#26).

Every worker thread shares one session. When it expires, the first worker
to read its 401 re-establishes; a slower worker's 401 answers a request that
was already in flight with the old session, and must not discard the fresh
one. The fake relay here keeps one live session per pairing token and
retires the previous session at each mint, as the real one does, so a
needless second mint is observable as a third establishment and as the
first worker's new session dying under it. No test opens a socket.
"""

from __future__ import annotations

import threading

from model_connector import client

DECLARE = {"protocol": 2, "concurrency": 2, "served_models": []}


class _OneSessionRelay:
    """A relay that honours exactly one session per pairing token: each
    mint retires the previous session, and ``expire()`` ends the live one
    the way the hourly TTL does."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.minted = 0
        self.live: str | None = None

    def expire(self) -> None:
        with self.lock:
            self.live = None

    def mint(self) -> tuple[int, dict]:
        with self.lock:
            self.minted += 1
            self.live = f"sess-{self.minted}"
            return 200, {"session_token": self.live, "ttl_seconds": 3600}

    def answer(self, headers: dict) -> tuple[int, dict]:
        sent = headers["Authorization"].removeprefix("Bearer ")
        with self.lock:
            if sent != self.live:
                return 401, {"error": {"code": "session_expired"}}
        return 200, {"job": None}


def test_drop_session_forgets_only_the_session_that_failed():
    c = client.RelayClient("https://r", lambda: "tok", post=lambda *a, **k: (200, {}))
    c._session = "new"
    c._drop_session("old")
    assert c._session == "new"
    c._drop_session("new")
    assert c._session is None
    # A second drop of a session already gone is a no-op, never an error.
    c._drop_session("new")
    assert c._session is None


def test_two_workers_at_one_expiry_establish_once():
    """Worker B's poll is held in flight, carrying the expired session, across
    worker A's whole recovery. B's 401 then arrives after A has minted the
    replacement: it must leave A's session in place, and B must poll on it
    rather than mint a third."""
    relay = _OneSessionRelay()
    b_in_flight = threading.Event()
    a_reestablished = threading.Event()

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            return relay.mint()
        sent = headers["Authorization"].removeprefix("Bearer ")
        if sent == "sess-1":
            # Orchestrate the race: A's refusal waits until B's poll has left
            # with the same dead session, and B's refusal waits until A has
            # finished re-establishing.
            if threading.current_thread().name == "B":
                b_in_flight.set()
                assert a_reestablished.wait(5)
            else:
                assert b_in_flight.wait(5)
        return relay.answer(headers)

    c = client.RelayClient("https://r", lambda: "tok", post=post)
    c.establish()
    relay.expire()

    expiries = {"A": 0, "B": 0}
    final = {}
    failures = []

    def worker(name: str) -> None:
        try:
            try:
                c.poll(DECLARE)
            except client.SessionExpired:
                expiries[name] += 1
                c.establish()
            if name == "A":
                a_reestablished.set()
            final[name] = c.poll(DECLARE)
        except BaseException as exc:  # surfaced to the test thread, which asserts on it
            failures.append((name, exc))
            a_reestablished.set()
            b_in_flight.set()

    threads = [threading.Thread(target=worker, args=(n,), name=n) for n in ("A", "B")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert not [t.name for t in threads if t.is_alive()]
    assert failures == []
    # One mint at start-up and exactly one more for the expiry: B's stale 401
    # neither dropped sess-2 nor minted sess-3.
    assert relay.minted == 2
    assert c._session == "sess-2"
    assert expiries == {"A": 1, "B": 1}
    # Both workers' next polls were served by the one live session.
    assert final == {"A": None, "B": None}


def test_result_refused_for_a_superseded_session_keeps_the_new_one():
    """The same race on the result verb, in one thread: while a result is in
    flight on sess-1 another worker drops it and establishes sess-2. The 401
    that answers the sess-1 result must not forget sess-2, and the retried
    delivery runs on sess-2 without another mint."""
    relay = _OneSessionRelay()
    c = client.RelayClient("https://r", lambda: "tok", post=lambda *a, **k: (200, {}))
    deliveries = []

    def post(url, body, headers, timeout, **kw):
        if url.endswith("/connector/session"):
            return relay.mint()
        sent = headers["Authorization"].removeprefix("Bearer ")
        if sent == "sess-1":
            relay.expire()
            # The other worker's recovery, completed while this request is
            # on the wire.
            c._drop_session("sess-1")
            c.establish()
        deliveries.append(sent)
        return relay.answer(headers)

    c._post = post
    c.establish()
    try:
        c.result("job-1", {"choices": []})
        raise AssertionError("a result on the retired session must raise SessionExpired")
    except client.SessionExpired:
        pass
    assert c._session == "sess-2"
    # establish() finds the session the other worker left and does not mint.
    c.establish()
    assert relay.minted == 2
    c.result("job-1", {"choices": []})
    assert deliveries == ["sess-1", "sess-2"]
