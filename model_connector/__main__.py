"""Entry point: validate everything before the first connection, then serve.

The printed startup line names the relay - the one fact an operator needs
when a pairing does not go green - and never the token.
"""

from __future__ import annotations

import argparse

from model_connector import client, loop


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="model_connector",
        description="Serve your own model to your deployment, dialing out only.",
    )
    p.add_argument("--relay", required=True, help="your deployment's relay URL (https)")
    p.add_argument(
        "--token-command",
        help="a command whose stdout is the pairing token - your secrets "
        "manager's CLI, for a connector that restarts on its own; consulted "
        "at each session establishment, so rotation needs no restart. "
        "Without any token option, the token is asked for at a hidden "
        "prompt and held in memory only",
    )
    p.add_argument(
        "--token-file",
        help=f"file holding the pairing token, re-read per establishment "
        f"(or set {loop.TOKEN_ENV} - development only)",
    )
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
        metavar="HOST",
        help="only forward to this model server host (repeatable); requests "
        "naming any other address are refused - your bound on where this "
        "process will connect, independent of what the deployment sends",
    )
    p.add_argument(
        "--allow-plain-http-model-url",
        action="store_true",
        help="accept an unencrypted model server address on another machine "
        "(your network, your call)",
    )
    p.add_argument("--once", action="store_true", help="one poll cycle, then exit (smoke test)")
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
    allowed_hosts = frozenset(h.lower() for h in args.model_host if h)
    if args.print_egress:
        # The whole egress surface, stated by the process itself so a network
        # review can quote the tool rather than trust a document. Printed
        # before any token is loaded: describing where this would connect
        # must not require the credential to connect.
        print(loop.egress_facts(args.relay, allowed_hosts))
        return 0
    source = loop.make_token_source(args.token_command, args.token_file)
    relay_client = client.RelayClient(args.relay, source)
    try:
        # Establish the first session now, while the operator is watching: a
        # misconfigured source or a dead pairing gets a sentence here, not a
        # silent retry loop. The pairing token itself is handled inside the
        # client for the length of the exchange and dropped.
        relay_client.establish()
    except loop.TokenSourceError as exc:
        return loop._die(str(exc))
    except client.TokenRejected:
        return loop._die(
            "the pairing token was not accepted - generate a new one in Settings and pair again"
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
    )


if __name__ == "__main__":
    raise SystemExit(main())
