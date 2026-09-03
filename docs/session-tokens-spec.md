# Sessions, and pairing built for a secrets manager

Status: implemented in v2.0.0 (protocol 2). Decision 1's token sources were
superseded in v3.0.0 by the stored pairing (`stored-pairing-spec.md`): the
pasted token is the one source, remembered on the machine after the relay
accepts it. Sessions, the two failure meanings, revocation, restart and the
tenant pin (decisions 2 to 9) stand unchanged.

## Purpose

The pairing token is the connector's one credential. Today it is a
long-lived bearer that rides every poll and sits in the process environment
for the connector's whole life. That was the right first shape; it is not
the final one, because the adversary on an operator's machine has changed
in kind: it is no longer only malware grepping for key patterns, but AI
agents with shell access reading environments, histories, and process
lists as a feature - invited, daily. A credential that "lives somewhere"
on a box must be assumed found. The defensible home for a long-lived
secret is a secrets manager: existence observable, access attributable,
revocation one operation.

This design moves the connector to that posture: the long-lived token
lives *only* in the manager; the connector borrows it for the milliseconds
of an exchange, trades it for a short-lived session token, and holds
nothing worth stealing in steady state.

## The shape, in one paragraph

At startup - and again whenever a session ends - the connector obtains the
pairing token from a pluggable **token source** (a secrets-manager
command, a re-read file, or a dev-only environment variable), presents it
once to a session endpoint on the relay, receives a short-lived **session
token**, and immediately forgets the pairing token. All polling and result
delivery authenticates with the session token. Sessions live only in relay
memory, so a relay restart or an expiry simply sends the connector back to
its token source. Revoking the pairing refuses new sessions at once and
invalidates live ones within seconds.

## Decisions

1. **The token source is pluggable and consulted per establishment; only
   the interactive paste is held.**
   - `--token-command "<command>"` - the connector runs the operator's
     command and reads the token from its stdout (stripped). This is the
     universal secrets-manager adapter: every manager has a CLI, so the
     connector integrates with all of them by integrating with none -
     standard-library `subprocess`, no SDKs, no vendor picks.
   - `--token-file <path>` - re-read at every establishment, so
     file-templating managers rotate the credential without touching the
     process.
   - The environment variable - kept for development and smoke tests, read
     fresh per establishment, and documented as not the production
     pattern: the environment is exactly where machine eyes look first.
   - A hidden-input prompt, when none of the above is given and a person is
     at a terminal - the copy-paste path from the token page. The pasted
     token is held in the process's memory for its lifetime, because
     re-establishment is hourly and a person cannot be asked hourly; it is
     never written anywhere, and a restart asks again. Without a terminal
     there is no prompt: the sources are named and the process exits, so a
     service never hangs on a prompt nobody will see.

2. **Session establishment is one new endpoint.** `POST
   /connector/session`, pairing token as the bearer, answering a session
   token and its TTL (an hour). The relay keeps sessions in memory only,
   consistent with its holds-nothing-durable design, and establishment
   shares the existing failed-auth rate limiter.

3. **Polls and results authenticate with the session token.** The pairing
   token appears on exactly one request per session; in steady state the
   wire carries only a credential that dies within the hour on its own.

4. **The two failure meanings get distinct answers.** A dead session and a
   dead pairing must not look alike - one means "establish again", the
   other means "stop". Expired or unknown sessions answer 401 with body
   code `session_expired`; establishment against a revoked pairing answers
   401 with `pairing_revoked`. The connector re-establishes on the first
   and exits with the revocation message on the second.

5. **Revocation stays a seconds-bounded kill switch on both paths.** Every
   session records the pairing hash it was minted under; the relay's
   session check compares that against its current pairing read (already
   cached for a few seconds), so a revoked pairing's live sessions die
   within the same window new establishment is refused.

6. **A relay restart is a non-event.** Sessions vanish with the process;
   the connector's next poll answers `session_expired`, it consults its
   token source, and establishes again - the same retry temperament the
   loop already has for transport wobbles. This is what makes decision 1
   load-bearing: a source consulted on demand means seamless reconnection
   no longer requires holding the credential.

7. **A token-source failure mid-run is a retry, not a death.** A briefly
   unreachable manager at re-establishment logs a plain-words failure and
   retries on the existing backoff. At *startup*, a failing source exits
   with a sentence immediately - a misconfigured command deserves an
   answer while the operator is watching.

8. **Memory hygiene means confinement, not erasure.** A token from a
   command, file or the environment lives in a variable scoped to the
   establishment call; a pasted one lives in the source's closure. Either
   way: never logged, never stored on the client, never placed back into
   the environment.
   Python cannot guarantee that freed strings are zeroed, so transient
   copies (the Authorization header) exist until garbage collection; the
   guarantee is that nothing retains one past the exchange.

9. **The tenant is pinned for the life of the process.** The session
   answer names the tenant the relay serves; the connector pins that name
   at first establishment and stops - loudly, exit 2 - if a later
   establishment answers a different one. A re-pointed relay address must
   never silently move a running connector between deployments. The pin is
   memory-only (the connector stores nothing), so re-pairing stays simple:
   a new token for the same tenant works live with no restart, and moving
   a box to a different tenant is a deliberate restart with that tenant's
   relay and token. A relay that names no tenant (an older deployment)
   pins the empty name, which keeps the connector compatible until the
   fleet catches up.

## Rejected alternatives

- **Keypair enrollment / proof-of-possession signing** - the Python
  standard library has no asymmetric cryptography, and adding a dependency
  would end this package's strongest reviewable property.
- **mTLS client certificates** - the platform's TLS terminates at a cloud
  front end that cannot verify client certificates.
- **HMAC device-secret enrollment** - verification would require the
  server to store the raw device secret, strictly worse than the hash-only
  pairing record it has today.

## What an attacker gets

| Attacker holds | Today | With sessions |
|---|---|---|
| The wire, inside TLS | the long-lived token, every request | a short-lived session token; the pairing token once per session |
| The process environment | the long-lived token | nothing (dev mode: the token, as labeled) |
| A steady-state memory snapshot | the long-lived token | a short-lived session token (interactively paired: the pairing token too, for the process lifetime) |
| Shell history and argv | nothing (refused by design) | nothing - the command names a *reference*; running it authenticates against, and is logged by, the manager |
