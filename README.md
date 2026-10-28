# Self-hosted model connector

Serves a model on your own network to your deployed tenant, **dialing out
only** - nothing on your network ever accepts an incoming connection.

This repository exists so that what runs on your machines is inspectable:
it is the connector exactly as shipped, published in the open. It is plain
Python with **no dependencies at all** - the standard library only - which
you can verify by reading the six files in `model_connector/`.

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
machine (`~/.config/model-connector/pairings.json`;
`%APPDATA%\model-connector\` on Windows), so every later start - a reboot,
a service manager's restart - pairs on its own with nobody at a terminal.
On Linux and macOS the file is owner-only (`0600` in a `0700` directory);
on Windows it carries the profile folder's own permissions (your account,
SYSTEM and Administrators by default) and nothing stronger is set. The
pairing lasts until
someone revokes the token in your deployment's Settings; then the
connector stops, says so, and forgets the token (see
`docs/stored-pairing-spec.md`).

One token serves one connector. To connect a second machine, generate a
second token in Settings: a token already in use is refused, the attempt
is shown beside the token in Settings, and the newcomer stops after a
short wait (a connector restarting right after a crash gets in on its
own).

### Unpairing this machine

A revocation has two halves. Revoking the token in your deployment's
Settings (Connectors tab) is what actually ends the pairing: the relay
refuses the token from then on, and a running connector stops and forgets
it on its next check-in. Removing the token from this machine is the other
half, and it is a flag:

```bash
python3 <the downloaded file> --relay https://<your relay> --forget
```

`--forget` deletes the saved pairing for that relay from the owner-only
file named above (and the file itself when it was the last entry) and
exits, without contacting the relay. It is the half that still works when
the platform cannot be reached - when your access to it has been severed,
or it is down - but it is only that half: the token stays valid on the
platform until someone revokes it in Settings.

### Two connectors on one machine

Each connector still needs its own token, and on a machine that already
runs one the second needs its own pairing run too: started plainly, it
would load the token saved for that relay - the first connector's, in
use - be answered busy, and say so, naming the file. Generate a second
token in Settings and start the second connector with `--pair`:

```bash
python3 <the downloaded file> --relay https://<your relay> --pair
```

`--pair` ignores the saved token and asks for a paste. Once the relay
accepts it, the new token is remembered **in place of** the previous one:
the pairing file holds one token per relay address, so two connectors to
the same relay under the same account share that one slot. The first
connector keeps running - it holds its token in memory - but a connector
started later under this account *without* `--pair` (a reboot, a service
manager's restart) pairs with the newest saved token, and only one of the
two comes back on its own. If both must survive restarts, run the second
connector under a different user account, or with its own
`XDG_CONFIG_HOME` (`APPDATA` on Windows) so it keeps its own pairing file.

From a checkout of this repository, the same program runs as
`python3 -m model_connector` with the same flags.

Python 3.12 or newer. A signed container image with a software bill of
materials is also published, for machines without Python.

## Installing as a package

A deployment that ships the connector pins this repository at a commit and
installs the GitHub archive of that commit under pip's `--require-hashes`,
so bytes that differ from the recorded archive cannot get in. But the
archive is a source tree, not a wheel: an installer still runs a build
backend to copy `model_connector/` into site-packages, and in pip's default
isolated build that backend is fetched from PyPI on the spot - the archive's
hash never covers it. `pyproject.toml` therefore pins the backend to an
exact version, `setuptools==84.2.1`, and a fully hash-verified install is
two steps: install that setuptools by hash first, then install the archive
*without* build isolation, so pip builds with the setuptools it just
verified instead of fetching another.

```bash
printf '%s\n' \
  'setuptools==84.2.1 --hash=sha256:ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2' \
  | pip install --require-hashes -r /dev/stdin
pip install --no-build-isolation --no-deps --require-hashes -r connector.lock
```

where `connector.lock` is one requirement, the archive of the commit you
chose and its sha256:

```
self-hosted-model-connector @ https://github.com/FireMountainLabs/self_hosted_model_connector/archive/<commit>.tar.gz \
    --hash=sha256:<sha256 of that archive>
```

pip reads a `--hash` only from a requirements file, hence the first line's
`-r /dev/stdin`; a one-line file does the same where there is no `/dev/stdin`.
The sha256 above is that of the `setuptools-84.2.1-py3-none-any.whl` on
PyPI, and the test suite holds this section to the version `pyproject.toml`
pins, so the two cannot drift. Without `--no-build-isolation` pip builds in
a fresh environment and fetches setuptools from PyPI with no hash, pinned
version or not, and the whole exercise verifies the archive but not what
installed it. With it, these two lines are the complete transitive surface:
the connector has no dependencies, and neither does that setuptools wheel.
The one thing left unverified by them is pip itself, which is whatever your
Python already carries.

## What it does, and does not, do

- **Dials out only.** The connector long-polls your deployment's relay over
  HTTPS and forwards each request to the model server *you* named in your
  deployment's Settings. It opens no ports and accepts no connections.
  When no work has come for a while, the relay answers each poll at once
  and tells the connector to wait (at most 30 seconds) before the next, so
  the relay's host is not billed for a poll held open around the clock.
- **Verifies encryption.** It refuses a relay connection that would not
  carry AES-256, and refuses plain http to a model server on a different
  machine unless you explicitly acknowledge it
  (`--allow-plain-http-model-url`).
- **Forwards only where you allow.** Each request names the model server it
  is aimed at (set in your deployment's Settings). Pass `--model-host
  HOST[:PORT]` (repeatable) and the connector refuses to forward anywhere
  else: the bound is scheme, host and port - a bare host covers only its
  scheme's default port (443 for https, 80 for http), so a request naming
  another port on the same box is refused with the rest. It is your bound
  on your network, independent of anything the deployment sends. An address
  carrying a query, a fragment or credentials is refused outright. Redirects
  are never followed, and oversized responses are dropped unread.
- **Holds one secret.** The pairing token is pasted at a hidden prompt -
  never a command-line argument, which every user of the machine can read,
  and never the environment. After the relay accepts it, it is kept in a
  file readable by your account only, and removed the moment the relay
  says it was revoked - and on nothing else, so a relay that is briefly
  unreachable or restarting never costs you the pairing. Your deployment
  stores only the token's SHA-256; revoking it in Settings stops the
  connector on its next check-in.
- **Serves one tenant.** The session handshake names the tenant the relay
  serves; the connector pins that name at first establishment and stops if
  it ever changes. Moving a connector to a different deployment is a
  deliberate restart, never something a re-pointed relay address can do to
  a running process.
- **Answers two questions.** A job is a completion to forward, or the
  deployment asking what the server at that address serves (its `/models`
  list, so the admin picks from real names before the first review). Any
  other kind of job is refused with a message, never forwarded.
- **Stores one thing.** The pairing token, on this machine, after the
  relay accepted it. Requests are forwarded and answered and never written
  anywhere.

## Reporting a problem

Open an issue here, or use the reporting address shown on your
deployment's Settings page.
