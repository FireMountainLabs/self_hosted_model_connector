"""AES-256-or-refuse HTTPS for every off-machine hop the connector opens.

In modern TLS the server picks the cipher from what the client offers, and
Python cannot restrict the TLS 1.3 suite list, so offering strong suites is
not a guarantee. The guarantee here is verify-then-refuse: connect, read the
cipher the handshake actually produced, and if it is not AES-256-GCM close
the connection and retry under a TLS 1.2 profile that can only produce
AES-256. Data never moves over a lesser cipher
- the encryption promise this connector makes is verified, not assumed.

Stdlib only: this file runs on whatever Python the tenant has.
"""

from __future__ import annotations

import http.client
import json
import ssl
from urllib.parse import urlsplit

# Loopback traffic never leaves the machine, so it is the one place plain
# http is legal (encryption-standard rule 1) - and what the loopback
# contract suite runs over.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# The negotiated-cipher names for AES-256-GCM: TLS 1.3 spells it
# TLS_AES_256_GCM_SHA384, TLS 1.2 suites spell it ...-AES256-GCM-....
_MARKERS = ("AES_256_GCM", "AES256-GCM")


class Aes256Error(RuntimeError):
    """The transport could not guarantee AES-256; nothing was sent."""


def is_aes256(cipher_name: str) -> bool:
    return any(m in cipher_name for m in _MARKERS)


def _base_ctx(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Governs the TLS <= 1.2 suite offer; 1.3 suites are not restrictable
    # from Python, which is exactly why the post-handshake check exists.
    # Explicit suite names, not aliases: alias grammar differs across
    # OpenSSL and LibreSSL builds ("ECDHE+AES256GCM" parses on one and is
    # "no cipher can be selected" on the other), and a transport guard that
    # fails to construct is an outage, not a refusal.
    ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384")
    if insecure:
        # Test seam only: drops certificate verification for the suite's
        # self-signed loopback cert. The cipher check is never dropped.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def strict_context(*, _insecure: bool = False) -> ssl.SSLContext:
    return _base_ctx(_insecure)


def tls12_aes256_context(*, _insecure: bool = False) -> ssl.SSLContext:
    """The retry profile: capped at TLS 1.2, where the pinned cipher list is
    authoritative, so a handshake either produces AES-256-GCM or fails."""
    ctx = _base_ctx(_insecure)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float):
    """One handshake attempt: (connection, cipher) on an AES-256 handshake,
    (None, reason) otherwise. A handshake that fails outright counts as a
    refusal, not an error - with the client's 1.2 offer pinned to AES-256, a
    server that cannot meet it has nothing to agree on, and that outcome is
    exactly the guarantee working."""
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    try:
        conn.connect()
    except ssl.SSLError as exc:
        conn.close()
        return None, f"handshake failed: {getattr(exc, 'reason', exc)}"
    cipher = conn.sock.cipher() if conn.sock is not None else None
    name = cipher[0] if cipher else "no cipher (handshake produced no TLS socket)"
    if not is_aes256(name):
        conn.close()
        return None, name
    return conn, name


def https_post_json(
    url: str,
    body: dict,
    headers: dict[str, str],
    timeout: float,
    *,
    _test_ctx_insecure: bool = False,
) -> tuple[int, dict]:
    """POST JSON over a connection verified to be AES-256 (or loopback).

    Returns (status, parsed JSON body or {}). Raises Aes256Error before any
    byte of ``body`` is sent when the transport cannot meet the standard.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    conn: http.client.HTTPConnection
    if parts.scheme == "http":
        if host not in LOOPBACK_HOSTS:
            raise Aes256Error(f"plain http to {host!r} would cross a machine boundary unencrypted")
        conn = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
    elif parts.scheme == "https":
        c, first = _connect(
            host, parts.port or 443, strict_context(_insecure=_test_ctx_insecure), timeout
        )
        if c is None:
            c, second = _connect(
                host,
                parts.port or 443,
                tls12_aes256_context(_insecure=_test_ctx_insecure),
                timeout,
            )
            if c is None:
                raise Aes256Error(
                    f"{host} would not negotiate AES-256 (offered {first!r} then {second!r})"
                )
        conn = c
    else:
        raise Aes256Error(f"unsupported scheme {parts.scheme!r} in {url!r}")
    try:
        payload = json.dumps(body).encode()
        conn.request(
            "POST",
            parts.path + (f"?{parts.query}" if parts.query else ""),
            body=payload,
            headers={"Content-Type": "application/json", **headers},
        )
        resp = conn.getresponse()
        raw = resp.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        return resp.status, parsed
    finally:
        conn.close()
