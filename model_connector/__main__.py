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
        "--token-file",
        help=f"file holding the pairing token (or set {loop.TOKEN_ENV})",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="how many requests at once your model server can take (default 1)",
    )
    p.add_argument(
        "--allow-plain-http-model-url",
        action="store_true",
        help="accept an unencrypted model server address on another machine "
        "(your network, your call)",
    )
    p.add_argument("--once", action="store_true", help="one poll cycle, then exit (smoke test)")
    args = p.parse_args(argv)

    # There is deliberately no model URL here: the command establishes
    # the connection and nothing else. Each request arrives naming the model
    # server it is aimed at - set in the deployment's Settings beside the
    # model choice - so the model configuration lives in exactly one place.
    loop.validate_relay_url(args.relay)
    token = loop.load_token(args.token_file)
    relay_client = client.RelayClient(args.relay, token)
    print(
        f"model-connector: connected to {args.relay}; each request names the "
        "model server set in Settings"
    )
    return loop.serve(
        relay_client,
        max(1, args.concurrency),
        allow_plain=args.allow_plain_http_model_url,
        once=args.once,
    )


if __name__ == "__main__":
    raise SystemExit(main())
