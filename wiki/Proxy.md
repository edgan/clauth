# clauth proxy

`clauth proxy` mirrors another machine's accounts onto this one. One host (the
**origin**) runs `clauth daemon --listen` and owns everything: it polls
usage, rotates tokens, and decides switches. Another (the **replica**) runs
`clauth proxy`, and writes what it gets into its own `~/.clauth`. The origin
holds each request open until the accounts actually move, so a switch there
reaches the replica in about a round trip rather than on a poll interval. `claude` then works on the replica against the origin's accounts and
follows whichever one the origin has active.

This is for running Claude Code on more than one machine off one set of
accounts, without a second login per machine and without copying credential
files around by hand.

```
origin                                     replica
  clauth daemon --listen                     clauth proxy --from boson.example.org
  polls usage, rotates tokens                one held request, answered on change
  decides switches                           follows the active account
```

## Setting it up

On the origin, once:

```console
$ clauth daemon --replace --listen
$ clauth daemon --print-token
3f9a...64 hex characters...c1
```

On the replica, once:

```console
$ clauth proxy --from boson.example.org
clauth: mirroring boson.example.org.
  run `clauth daemon --print-token` there, and paste it below (input stays hidden)
Origin token:
```

After that a bare `clauth proxy` reuses the stored origin, token and cadence, so
the usual form under a service manager is just `clauth proxy`.

## What crosses, and what does not

- **The refresh token never leaves the origin.** This is the whole design, not a
  precaution. Anthropic's OAuth refresh chain is single-use: whoever spends a
  refresh token revokes every other copy of it. Two machines refreshing one
  chain is how accounts break, and clauth answers the `invalid_grant` its loser
  receives with a local quarantine that only a `clauth login` lifts. The mirror
  sends an **access token** and leaves the refresh token out of the body
  entirely, so a replica can spend an account but cannot advance its chain,
  whatever it or Claude Code decides to do. That is the same shape a
  `claude setup-token` login already has on disk, which is what a `--setup-token`
  profile installs as the live credentials today.
- **A replica's credentials are short-lived by construction.** An access token
  lasts about eight hours. The origin replaces it roughly fifteen minutes before
  it expires, and the replica picks that up on its next pull. Nothing on the
  replica can renew one.
- **What is mirrored:** each account's `config.toml`, its credentials, its
  `session-token.json` when it has one, its identity anchor, and its usage
  caches. Plus the roster, the fallback chain, the quarantine list, and which
  account is active.
- **What is not:** this host's own settings. Theme, clock format, reset display,
  estimate and pace toggles, refresh interval and every switch threshold stay
  local. They are the replica operator's, and they drive decisions a replica
  never makes.

## What a replica refuses

While `~/.clauth/proxy.json` exists, this host is a replica:

| | |
|---|---|
| `clauth <profile>`, `clauth login`, `clauth delete`, `clauth disable`, `clauth enable` | refused, naming the origin |
| `clauth daemon` | refused. A daemon polls and rotates, which is the origin's job |
| `clauth start --with-fallback` | refused. The chain walk needs a local daemon to decide the hops |
| the background usage refresher | never starts, in the TUI as well as the daemon |
| `clauth list`, `which`, `status --json`, `sessions`, the TUI | work normally, off the mirrored caches |
| `clauth start`, `claude` | work normally |

The refresher staying down is the enforcement, not a convention. Opening the TUI
on a replica would otherwise begin polling the origin's accounts, and that is the
easiest way to trip into a second rotator.

`clauth proxy --forget` removes `proxy.json` and re-arms the host. The mirrored
profiles stay on disk, and their credentials still carry no refresh token, so
re-authenticate anything you mean to keep using with `clauth login`.

## Flags

| Flag | Meaning |
|---|---|
| `--from HOST[:PORT]` | origin, as the FQDN its certificate names. Port defaults to 8443. Stored on first run |
| `--token-file PATH` | read the origin's bearer token from a file instead of prompting |
| `--once` | pull once and exit, instead of following |
| `--interval SECS` | fallback poll interval, for a failed pull or an origin too old to hold a request. Default 60, capped at 300. Not the latency |
| `--forget` | stop mirroring and re-arm this host |

There is deliberately no `--token`. An argument is visible in shell history and
process listings, and this one is a password. Without `--token-file` the token is
read with echo off from the terminal, or as one line from a pipe.

## Rules worth knowing

- **Dial the name, never an address.** The origin serves its own
  [lego](https://github.com/go-acme/lego) certificate, so `https://10.0.0.4:8443`
  fails verification whatever is listening. `clauth proxy` refuses an address up
  front rather than letting it surface as a handshake error. The name also has to
  resolve to the daemon from the replica, which on a LAN usually means
  split-horizon DNS or a `hosts` entry. See [Daemon](Daemon) for the certificate
  layout.
- **Changes are pushed, not polled for.** The replica keeps one request open at
  the origin (`?wait`), and the origin answers it the moment the accounts move,
  so a switch propagates in about a round trip. The connection is renewed every
  fifty seconds when nothing happens, which costs one of the origin's 32
  connection slots for as long as the replica runs.
- **`--interval` is only the fallback.** It paces two cases with nothing to wait
  on: retrying after a failed pull, and an origin too old to understand `?wait`,
  which the replica detects by noticing its request came back immediately. On
  that path the cap is a real constraint: the origin rotates an access token
  about fifteen minutes before expiry, and Claude Code refreshes its own within
  five minutes of expiry, so a pull has roughly a ten minute window to carry the
  new token across. A slower cadence builds a replica whose sessions start
  failing at expiry, with no refresh token on that side to recover with. That is
  why 300 seconds is a refusal and not a clamp.
- **A failed pull backs off, up to that same cap.** The first failure retries at
  the configured interval, because a daemon restart is over in seconds and should
  not cost a backed-off wait. A run of failures doubles the wait each time and
  stops at 300 seconds — never above it, for the reason in the point above — and
  the first successful pull puts the cadence straight back to the interval. So a
  dead origin is dialled about a dozen times an hour rather than sixty, and a
  brief one is still picked up immediately.
- **A long outage does not flood the log.** The first failure is reported, as is
  any change of reason; an unchanging outage then checks in every tenth failed
  pull, carrying the count and how long it has been going. Recovery gets a line of
  its own, so the log distinguishes "the origin came back" from "the proxy stopped
  running" — which otherwise look identical from the outside.
- **A replica clears Claude Code's first-run gate for you.** Claude Code decides
  whether to run its onboarding — which asks for a login — from
  `hasCompletedOnboarding` in `~/.claude.json`, not from whether it can already
  authenticate. On a machine that has never run it, that means a login prompt on
  top of credentials that work perfectly well, and a replica is exactly the
  machine nobody is meant to log in on. So a pull sets that one flag, creating
  `~/.claude.json` if Claude Code has not yet written one. Nothing else in the
  file is touched, and a file that already reads `true` is left alone entirely.
- **An origin outage is survivable for hours, not days.** The replica keeps
  working on the access token it holds. When that expires the account is
  quarantined locally, which is the honest answer: it genuinely cannot be used
  here any more. A successful pull clears it.
- **Revocation propagates for free.** Disable an account or re-login on the
  origin and the replica goes dark by itself within one token lifetime. There is
  nothing to revoke on the replica separately.
- **The mirror token is the same bearer everything else uses.** The route is on
  whenever the daemon is listening, guarded by the one token, so anything holding
  it can read the origin's accounts. That includes a menu-bar client you gave the
  token to for the status feed. An operator who wants a client that cannot pull
  credentials needs a second daemon on another port with its own token.
- **A replica shares the origin's usage windows.** Mirroring shows an account's
  remaining quota on another machine; it does not create more of it.
- **The replica owns its live login outright.** Claude Code rewrites
  `~/.claude/.credentials.json` rather than following the symlink clauth puts
  there, so on any host that has run `claude` the live slot is an ordinary file.
  A normal switch refuses to overwrite one that differs, in case it holds a
  re-login you have not captured. `clauth proxy` overwrites it anyway: the origin
  owns every credential here, `clauth login` is refused, and a diverged file on a
  replica carries nothing the origin's copy does not. Without that, the first
  switch or rotation after Claude Code touched the file would be the last one
  this host ever followed.
- **The prune is bounded by a manifest.** `proxy.json` records which profiles this
  proxy created, and only those are removed when the origin drops them. A profile
  you made on the replica is never touched, and neither is one with a live
  session.

## The route it uses

`GET /api/v1/mirror` on the origin's REST API, with the same bearer token every
other route needs, served whenever that daemon is listening. The response is
conditional: the `ETag` digests the accounts and not the timestamp. Adding
`?wait=<secs>` to a request that already carries the current tag makes the origin
hold it open until that tag stops matching, up to sixty seconds, which is what
turns this from a poll into a push. Without `wait` it answers at once, so an
older client is unaffected. Full route table in [Daemon](Daemon).

| The replica says | It means |
|---|---|
| `401` | wrong or rotated token. Re-run `clauth daemon --print-token` on the origin |
| `403` | nothing in clauth answers that, so something in between is: check for a reverse proxy in front of the daemon |
| `404` | the origin runs a clauth too old to mirror |
| a certificate error | you dialled an address, or a name the certificate does not cover |
| connection refused | the daemon is down there, or `CLAUTH_NO_API=1` is set |
