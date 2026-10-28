"""Entry point: validate everything before the first connection, then serve.

The printed startup line names the relay - the one fact an operator needs
when a pairing does not go green - and never the token.
"""

from __future__ import annotations

import argparse
import sys
import time
from urllib.parse import urlsplit

from model_connector import client, loop, pairing, tls


def _model_host(entry: str) -> str:
    """One --model-host entry, in the spelling model_url_refusal compares
    against: a lowercased host, or host:port, an IPv6 literal kept in its
    brackets. It is read as a URL authority so the bound and the job's
    address are parsed by the same code, and anything beyond host and port
    (a scheme, a path, credentials) is refused at the prompt: accepted, it
    would become a host named "https" that no request ever matches, and the
    operator would believe themselves bounded."""
    parts = urlsplit("//" + entry)
    try:
        port = parts.port
    except ValueError:
        port = -1
    host = parts.hostname or ""
    key = f"[{host}]" if ":" in host else host
    normalised = key if port is None else f"{key}:{port}"
    if not host or port == -1 or normalised != parts.netloc.lower() or parts.path:
        raise argparse.ArgumentTypeError(
            f"expected HOST or HOST:PORT (an IPv6 literal in brackets), got {entry!r}"
        )
    return normalised


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="model_connector",
        description="Serve your own model to your deployment, dialing out only.",
    )
    p.add_argument("--relay", required=True, help="your deployment's relay URL (https)")
    p.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="how many requests at once your model server can take (default 1)",
    )
    p.add_argument(
        "--model-host",
        action="append",
        default=[],
        type=_model_host,
        metavar="HOST[:PORT]",
        help="only forward to this model server, host[:port] (repeatable); a bare "
        "host means the scheme's default port (443 https, 80 http), and requests "
        "naming any other scheme, host or port are refused - your bound on where "
        "this process will connect, independent of what the deployment sends",
    )
    p.add_argument(
        "--allow-plain-http-model-url",
        action="store_true",
        help="accept an unencrypted model server address on another machine "
        "(your network, your call)",
    )
    p.add_argument("--once", action="store_true", help="one poll cycle, then exit (smoke test)")
    p.add_argument(
        "--forget",
        action="store_true",
        help="remove the saved pairing for this relay from this machine, then exit; "
        "the token itself stays valid until revoked in Settings, Connectors tab",
    )
    p.add_argument(
        "--print-egress",
        action="store_true",
        help="print every network destination this process will dial, then exit",
    )
    args = p.parse_args(argv)

    # There is deliberately no model URL here: the command establishes
    # the connection and nothing else. Each request arrives naming the model
    # server it is aimed at - set in the deployment's Settings beside the
    # model choice - so the model configuration lives in exactly one place.
    loop.validate_relay_url(args.relay)
    allowed_hosts = frozenset(args.model_host)
    if args.print_egress:
        # The whole egress surface, stated by the process itself so a network
        # review can quote the tool rather than trust a document. Printed
        # before any token is loaded: describing where this would connect
        # must not require the credential to connect.
        print(loop.egress_facts(args.relay, allowed_hosts))
        return 0
    if args.forget:
        # The connector's half of a revocation, for when the platform cannot
        # be reached: the credential leaves this machine without a byte to
        # the relay - no RelayClient, no token source, no prompt. It cannot
        # revoke the token (only Settings can), so the line says that
        # plainly rather than let a cleared file read as a revoked token.
        store = pairing.PairingStore(args.relay)
        if store.load() is None:
            print(f"model-connector: nothing was saved for {args.relay} in {store.path}")
        else:
            store.forget()
            print(
                f"model-connector: removed the saved pairing for {args.relay} from "
                f"{store.path} on this machine only; the token stays valid on the "
                "platform until it is revoked in Settings, Connectors tab"
            )
        return 0
    source = loop.make_token_source(pairing.PairingStore(args.relay))
    relay_client = client.RelayClient(args.relay, source)
    try:
        # Establish the first session now, while the operator is watching: a
        # dead pairing or a token in use elsewhere gets a sentence here, not
        # a silent retry loop.
        _establish_while_watching(relay_client)
    except loop.TokenSourceError as exc:
        return loop._die(str(exc))
    except client.TokenRejected:
        # The token the relay just refused must not be offered again at the
        # next start: a revoked pairing leaves this machine with it.
        source.forget()
        return loop._die(
            "the pairing token was not accepted - generate a new one in Settings and pair again"
        )
    except client.KeyBusy:
        return loop._die(
            "another connector is already connected with this pairing token - each "
            "connector needs its own: generate another in Settings"
        )
    except client.RelayUnavailable as exc:
        # Not revoked, so the token stays: the next start needs no paste.
        return loop._die(f"{exc} - the pairing is kept; try again shortly")
    except tls.Aes256Error as exc:
        return loop._die(str(exc))
    except OSError as exc:
        # A relay that cannot be reached at all - a mistyped address, no
        # network, a firewall - is the operator's problem to fix, and gets
        # the address and the OS's reason in one line, not a stack trace.
        return loop._die(f"could not reach the relay at {args.relay}: {exc}")
    first_pairing = source.pasted
    source.remember()
    if first_pairing:
        print(
            "model-connector: paired; the token is remembered on this machine "
            f"({pairing.permissions_note()} {source.path}), so this command needs no "
            "paste from now on"
        )
    print(
        f"model-connector: session established with {args.relay}; each request "
        "names the model server set in Settings"
    )
    return loop.serve(
        relay_client,
        max(1, args.concurrency),
        allow_plain=args.allow_plain_http_model_url,
        allowed_hosts=allowed_hosts,
        once=args.once,
        on_revoked=source.forget,
    )


def _establish_while_watching(relay_client) -> None:
    """The first establishment, with the operator at the keyboard. Two
    answers are waited out for a bounded time: busy - the relay lets a token
    go about a minute after its previous holder's last poll, so a restart
    right after a crash pairs on its own - and unavailable - a relay whose
    store is redeploying for a few seconds. After the wait each is refused
    in plain words; a token genuinely in use elsewhere needs its own."""
    deadline = time.monotonic() + loop._BUSY_RETRY_SECS
    said = False
    while True:
        try:
            relay_client.establish()
            return
        except (client.KeyBusy, client.RelayUnavailable) as exc:
            if time.monotonic() >= deadline:
                raise
            if not said:
                line = (
                    "another connector is connected with this token; waiting for it to go quiet"
                    if isinstance(exc, client.KeyBusy)
                    else f"{loop.clean(exc)}; waiting for the relay"
                )
                print(f"model-connector: {line}", file=sys.stderr)
                said = True
            time.sleep(loop._BUSY_RETRY_STEP)


if __name__ == "__main__":
    raise SystemExit(main())
