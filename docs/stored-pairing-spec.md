# The stored pairing, and one connector per token

Status: implemented in v3.0.0 (protocol 2, unchanged on the wire except
for one new refusal at establishment).

## Purpose

A connector should pair once and stay paired until the token is revoked -
across restarts, reboots, and the service manager's own restarts - without
a person at a keyboard and without a second system to hold the credential.
And one token should mean one connector: a copied token must not be able
to quietly serve alongside the real one.

v2 held the pasted token in memory only, so every restart asked again, and
the page that showed the token cannot be reopened - a restart meant a new
token. For a machine that restarts on its own, v2's answer was a secrets
manager's CLI. That is the right posture for a fleet and the wrong default
for one machine next to one model server: it made the simplest deployment
depend on a tool the operator may not have, to hold a credential that a
file under their own account holds just as well.

## The shape, in one paragraph

The connector asks for the token once, in a terminal, with input hidden.
After the relay has accepted it, the token is written to one owner-only
file in the user's configuration directory, keyed by the relay address.
Every later start reads it from there and needs no person. When the relay
refuses the token - revocation, or a token that never existed - the
connector removes it from memory and disk together and stops, saying so.
The relay grants one live session per token: while a session on a token is
still polling, a second request for one is refused with a named code, the
attempt is recorded and shown on the deployment's Settings page, and the
newcomer waits briefly (a restart on a crash's heels) and then stops
(a second machine, which needs its own token).

## Decisions

1. **The pasted token is the only source.** `--token-command`,
   `--token-file` and `MODEL_CONNECTOR_TOKEN` are gone. Each was a second
   place for the credential to live, and each existed for the restart
   problem the stored pairing now solves. Without a terminal and without a
   stored token the connector exits naming the way in, so a service never
   hangs on a prompt nobody will see.

2. **The file is written only after acceptance.** A mistyped paste is not
   remembered; the relay's first "yes" is what earns the token its place
   on disk. The file holds the token and nothing else - the model server
   address arrives per request from the deployment, and the tenant pin
   stays memory-only (a restart remains the one deliberate way to move a
   connector; a relay address that now answers for another tenant refuses
   the old token anyway).

3. **Where, and how.** `$XDG_CONFIG_HOME/model-connector/pairings.json`
   (`~/.config/...` by default) on POSIX, `%APPDATA%\model-connector\` on
   Windows; directory `0700`, file `0600`, written beside the target and
   renamed into place. Keyed by relay address, so one machine can hold
   pairings to several deployments. A damaged file reads as absent and is
   replaced on the next save: it costs one paste, never a support call.

4. **Only the revocation answer forgets.** The relay's coded
   `pairing_revoked` answer at establishment removes the token from memory
   and disk, wherever it surfaces - at startup, at an hourly
   re-establishment, or mid-delivery. The next start asks again. This is
   what keeps the file honest: it never holds a token that is not currently
   paired. Nothing else forgets: an uncoded 401 (a front door, a relay
   restarted since the session was minted), a 5xx (a relay that cannot
   reach its store for a few seconds) and busy are all retried with the
   token kept, because each can happen to a pairing the deployment still
   holds, and a connector that forgot on one of them would destroy the
   only copy of a good credential.

5. **One live session per token.** The relay tracks each session's last
   poll. A session that polled inside the live window (a minute; the poll
   hold is 25 seconds) holds its token, and establishment on that token
   answers `409` with body code `connector_busy`. The first session is not
   displaced - take-over would let a stolen copy bump the real connector
   and the two would fight silently; refusal keeps the real one running
   and makes the attempt visible.

6. **Busy is waited out at startup, retried mid-run, and never forgotten.**
   At startup the connector retries for about 75 seconds, printing one
   line, then exits with the sentence that names the fix (another token).
   A crashed connector's session goes quiet within the window, so its own
   restart gets in without a person. At re-establishment mid-run, busy is
   a retry like any transport wobble. Busy is not revoked, so the stored
   token stays.

7. **The relay records the attempt.** Each refusal is audited and counted
   per token, and the deployment's Settings page shows it beside the
   token, with Revoke one click away. A copied token is the one theft the
   file makes easier; this is what makes it visible.

## Rejected alternatives

- **Keep the secrets-manager command as an option.** Every optional source
  is a second home for the credential and a second path to test, document
  and explain. The stored pairing covers the case the command existed for.
  A fleet that wants a manager can template the file the connector reads
  under its own account; the connector need not know.
- **Take over the session instead of refusing.** See decision 5.
- **Bind the stored token to the machine (a hardware id, a keyring).** The
  standard library has no portable keyring, and a machine id adds nothing
  against the adversary who can already read the file as this user. File
  permissions are the boundary, as they are for SSH keys and cloud CLI
  logins.

## What an attacker gets

| Attacker holds | v2 (memory-only paste) | v3 (stored pairing) |
|---|---|---|
| The wire, inside TLS | the pairing token once per session; a session token otherwise | unchanged |
| The process environment | nothing | nothing |
| A steady-state memory snapshot | the pairing token, for the process lifetime | unchanged |
| This user's files, or a copy of them | nothing | the pairing token - usable only until revoked, and its use beside the real connector is refused and shown |
| Shell history and argv | nothing | nothing |
