# Self-hosted model connector

Serves a model on your own network to your deployed tenant, **dialing out
only** - nothing on your network ever accepts an incoming connection.

This repository exists so that what runs on your machines is inspectable:
it is the connector exactly as shipped, published in the open. It is plain
Python with **no dependencies at all** - the standard library only - which
you can verify by reading the five files in `model_connector/`.

## Run it

You normally don't clone this repository to run the connector: your
deployment serves it as a single file, with a checksum, from the
pairing-token page in its Settings. The command printed there is:

```bash
curl -fsSLO https://<your dashboard>/<the connector file named on your token page>
MODEL_CONNECTOR_TOKEN=<your token> python3 <the downloaded file> \
  --relay https://<your relay>
```

In production, keep the token in your secrets manager and hand the
connector the command that reads it - the token is consulted only when a
session is established, then traded for a short-lived session token and
dropped (see `docs/session-tokens-spec.md`):

```bash
python3 <the downloaded file> --relay https://<your relay> \
  --token-command "<your secrets manager CLI printing the token>"
```

From a checkout of this repository, the same program runs as
`python3 -m model_connector` with the same flags; the
`MODEL_CONNECTOR_TOKEN` environment variable remains as the development
fallback.

Python 3.12 or newer. A signed container image with a software bill of
materials is also published, for machines without Python.

## What it does, and does not, do

- **Dials out only.** The connector long-polls your deployment's relay over
  HTTPS and forwards each request to the model server *you* named in your
  deployment's Settings. It opens no ports and accepts no connections.
- **Verifies encryption.** It refuses a relay connection that would not
  carry AES-256, and refuses plain http to a model server on a different
  machine unless you explicitly acknowledge it
  (`--allow-plain-http-model-url`).
- **Forwards only where you allow.** Each request names the model server it
  is aimed at (set in your deployment's Settings). Pass `--model-host`
  (repeatable) and the connector refuses to forward anywhere else - your
  bound on your network, independent of anything the deployment sends.
  Redirects are never followed, and oversized responses are dropped unread.
- **Holds one secret, in the environment.** The pairing token rides
  `MODEL_CONNECTOR_TOKEN` (or `--token-file`), never a command-line
  argument - argv is readable by every user of the machine. Your deployment
  stores only the token's SHA-256; revoking it in Settings stops the
  connector on its next poll.
- **Serves one tenant.** The session handshake names the tenant the relay
  serves; the connector pins that name at first establishment and stops if
  it ever changes. Moving a connector to a different deployment is a
  deliberate restart, never something a re-pointed relay address can do to
  a running process. (Re-pairing the same tenant with a new token needs no
  restart - the token source is read fresh at every establishment.)
- **Stores nothing.** Requests are forwarded and answered; nothing is
  written to disk.

## Reporting a problem

Open an issue here, or use the reporting address shown on your
deployment's Settings page.
