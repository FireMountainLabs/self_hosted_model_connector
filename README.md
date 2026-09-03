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
python3 <the downloaded file> --relay https://<your relay>
```

It asks for the pairing token, with input hidden - paste it from the token
page. Once the relay has accepted it, the token is remembered on this
machine in a file only your account can read
(`~/.config/model-connector/pairings.json`; `%APPDATA%\model-connector\`
on Windows), so every later start - a reboot, a service manager's restart -
pairs on its own with nobody at a terminal. The pairing lasts until
someone revokes the token in your deployment's Settings; then the
connector stops, says so, and forgets the token (see
`docs/stored-pairing-spec.md`).

One token serves one connector. To connect a second machine, generate a
second token in Settings: a token already in use is refused, the attempt
is shown beside the token in Settings, and the newcomer stops after a
short wait (a connector restarting right after a crash gets in on its
own).

From a checkout of this repository, the same program runs as
`python3 -m model_connector` with the same flags.

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
- **Holds one secret.** The pairing token is pasted at a hidden prompt -
  never a command-line argument, which every user of the machine can read,
  and never the environment. After the relay accepts it, it is kept in a
  file readable by your account only, and removed the moment the relay
  refuses it. Your deployment stores only the token's SHA-256; revoking it
  in Settings stops the connector on its next check-in.
- **Serves one tenant.** The session handshake names the tenant the relay
  serves; the connector pins that name at first establishment and stops if
  it ever changes. Moving a connector to a different deployment is a
  deliberate restart, never something a re-pointed relay address can do to
  a running process.
- **Stores one thing.** The pairing token, on this machine, after the
  relay accepted it. Requests are forwarded and answered and never written
  anywhere.

## Reporting a problem

Open an issue here, or use the reporting address shown on your
deployment's Settings page.
