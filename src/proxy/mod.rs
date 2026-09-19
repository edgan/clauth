//! `clauth proxy` — follow another host's accounts.
//!
//! One machine (the **origin**) runs `clauth daemon --listen` and owns
//! everything: it polls usage, rotates tokens, and decides switches. Another
//! (the **replica**) runs this, pulls a snapshot on an interval, and writes it
//! into its own `~/.clauth`. `claude` then works on the replica against the
//! origin's accounts, and follows the origin's active one.
//!
//! The replica is read-only by construction, not by convention:
//!
//!   * The mirrored credential carries **no refresh token** ([`wire`]), so this
//!     host cannot advance a single-use refresh chain even if something here
//!     tried. That is the whole safety argument; everything else is hygiene.
//!   * The background refresher does not start while `proxy.json` exists, so
//!     opening the TUI here does not begin polling the origin's accounts.
//!   * Every `clauth` command that would mutate an account refuses and names
//!     the origin ([`refuse_if_replica`]), as does the TUI's login. The TUI's
//!     own switch and delete are not gated: both are undone by the next pull,
//!     which reinstalls the origin's active account and re-creates anything it
//!     still lists.
//!
//! What that costs: a replica outlives an origin outage by at most one access
//! token, a few hours. That is the intended trade. It also means revocation
//! propagates for free -- disable or re-login on the origin and this host goes
//! dark by itself within one token lifetime.

pub(crate) mod apply;
pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod wire;

use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::cli::ProxyArgs;
use crate::logline::logline;
use crate::out::outln;

pub(crate) use config::is_replica;

/// Refuse an action that belongs to the origin, naming it.
///
/// Used by every mutating command. The message says where to go and how to stop
/// being a replica, because "not supported here" without either is a dead end.
pub(crate) fn refuse_if_replica(action: &str) -> Result<()> {
    if !is_replica() {
        return Ok(());
    }
    let origin = config::load()
        .ok()
        .flatten()
        .map(|c| c.origin)
        .unwrap_or_else(|| "its origin".to_string());
    bail!(
        "this host mirrors {origin}; {action} there instead. \
         `clauth proxy --forget` stops mirroring and re-arms this machine"
    )
}

/// `clauth proxy`.
pub(crate) fn run(args: &ProxyArgs) -> Result<()> {
    if args.forget {
        return forget();
    }

    // Two schedulers on one refresh chain is the failure this whole feature is
    // shaped around, and a local daemon is a scheduler. Refuse before writing
    // proxy.json, so a mistaken run leaves the host exactly as it was.
    // Unknown reads as held: if the lock cannot be inspected, refusing costs a
    // diagnosable error while proceeding could put two rotators on one chain.
    if crate::daemon::singleton_held().unwrap_or(true) {
        bail!(
            "a clauth daemon is running on this host. A daemon polls and rotates, which is the \
             origin's job -- stop it before mirroring, or run the proxy on a different machine"
        );
    }

    let config = config::resolve(args, || prompt_token(args))?;

    let mut config = config;
    if args.once {
        let applied = pull_once(&client::agent(), &config, None)?.1;
        // Recorded even for a one-shot: the manifest is what bounds the next
        // run's prune, and a `--once` that forgot what it wrote would leave a
        // later run unable to clean up after it.
        remember(&mut config, &applied)?;
        report(&applied);
        return Ok(());
    }

    // Long-running from here, so stderr IS the log and undated lines cost real
    // forensics time -- the call `daemon::serve` makes first, for the same
    // reason.
    crate::logline::enable_timestamps();
    logline!("clauth proxy: following {}", config.origin);

    // Owned, not a process global, so the loop can throw it away -- see the
    // `client` module docs for why a long outage makes that worth having.
    let mut agent = client::agent();

    // The first pull is fatal. An operator who just typed a wrong host or
    // pasted a stale token wants to be told now, not to watch a retry loop.
    let (etag, applied) = pull_once(&agent, &config, None)?;
    let mut etag = etag;
    remember(&mut config, &applied)?;
    report_log(&applied);

    // No sleep between pulls. The origin holds each request open until the
    // accounts actually move (`?wait`), so the next pull returns when there is
    // something to apply rather than when a timer says so, and a switch there
    // lands here in about a round trip.
    let base = config.interval_secs;
    let mut outage = Outage::default();
    loop {
        let started = std::time::Instant::now();
        // Every failure after the first is survivable: the origin restarting, a
        // flapping link, a certificate renewal. Keep the last good snapshot in
        // place and back off rather than exiting and leaving this host with
        // credentials nobody is refreshing.
        let outcome = pull_once(&agent, &config, etag.as_deref());
        let waited = started.elapsed();
        match outcome {
            Ok((new_etag, applied)) => {
                if let Some(line) = outage.recovered() {
                    logline!("{line}");
                }
                etag = new_etag;
                if let Err(e) = remember(&mut config, &applied) {
                    logline!("clauth proxy: failed to record the manifest: {e}");
                }
                report_log(&applied);
            }
            Err(e) => {
                if let Some(line) = outage.failed(&e.to_string()) {
                    logline!("{line}");
                }
                // A failed call left nothing in the pool worth keeping, so
                // discarding the agent costs nothing -- and it is the only lever
                // this loop has over state inside the client it cannot inspect.
                // Bounded rather than immediate so a single blip does not churn.
                if outage.failures >= AGENT_RECYCLE_AFTER {
                    agent = client::agent();
                }
                std::thread::sleep(Duration::from_secs(backoff_secs(outage.failures, base)));
                continue;
            }
        }
        // An origin too old to understand `?wait` answers instantly, every
        // time. Without this the loop would spin against it at whatever rate the
        // network allows. Detected by how long the call took rather than by
        // asking, so it needs no negotiation and no version check: a request
        // that was genuinely held cannot return this fast.
        if waited < IMMEDIATE {
            std::thread::sleep(Duration::from_secs(base));
        }
    }
}

/// Consecutive failures after which the loop rebuilds its HTTP agent.
///
/// Two, not one: a single failed pull is a blip -- a daemon restart, a dropped
/// packet -- and the pool holds nothing that survived it anyway, so rebuilding
/// there would be churn for its own sake. Two in a row means the client has been
/// sitting against a dead origin, which is the case where discarding whatever it
/// accumulated is worth one handshake.
const AGENT_RECYCLE_AFTER: u64 = 2;

/// Failed pulls between log lines once an outage is established.
///
/// The first failure and every change of reason always speak (see [`Outage`]);
/// this only bounds how often an UNCHANGING outage repeats itself. At the 300s
/// backoff ceiling ten failures is under an hour, so a day-long outage costs
/// about two dozen lines instead of about fourteen hundred.
const LOUD_EVERY: u64 = 10;

/// Below this, a `?wait` request plainly was not held, so the origin does not
/// support waiting and the loop falls back to its interval. Generous enough that
/// a real change arriving the instant the request lands is not mistaken for it,
/// which costs one interval of latency in a case that resolves itself on the
/// next pull anyway.
const IMMEDIATE: Duration = Duration::from_millis(500);

/// How long to wait after `failures` consecutive failed pulls, given the
/// configured fallback `base`.
///
/// Pure so the schedule is unit-testable, the shape `switch_backoff_ms` already
/// uses (`daemon::types`). The first failure retries at the configured interval:
/// a daemon restart is over in seconds and must not cost the replica a backed-off
/// wait for something that has already fixed itself.
///
/// The ceiling is [`ProxyArgs::MAX_INTERVAL_SECS`] and it is load-bearing, not a
/// round number. `--interval` is capped at the same value because the origin
/// rotates an access token about fifteen minutes before it expires and Claude
/// Code refreshes its own within five minutes of expiry, leaving a pull roughly
/// ten minutes to carry the new token across. A backoff that climbed past the cap
/// would break, silently and only under a long outage, the exact contract
/// `validate_interval` refuses to let an operator break by hand.
fn backoff_secs(failures: u64, base: u64) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    base.saturating_mul(1_u64 << doublings)
        .min(ProxyArgs::MAX_INTERVAL_SECS)
}

/// Failure bookkeeping for the follow loop: how many in a row, since when, and
/// what was last said about it.
///
/// Exists because the loop used to write one line per failed pull. A multi-hour
/// outage is thousands of identical lines, which is how the evidence for the
/// 2026-09-04 crash came to be buried in its own retry log -- the same reason
/// `SwitchBackoff` dedups the daemon's switch failures.
#[derive(Default)]
struct Outage {
    /// Consecutive failed pulls; zero while the origin is answering.
    failures: u64,
    /// The reason last written, so an unchanging outage does not repeat itself.
    said: Option<String>,
    /// When the current run of failures began.
    started: Option<std::time::Instant>,
}

impl Outage {
    /// Record a failed pull. Returns the line to log, or `None` when this
    /// failure is a repeat of one already reported.
    fn failed(&mut self, reason: &str) -> Option<String> {
        self.failures += 1;
        if self.started.is_none() {
            self.started = Some(std::time::Instant::now());
        }
        let changed = self.said.as_deref() != Some(reason);
        if !changed && !self.failures.is_multiple_of(LOUD_EVERY) {
            return None;
        }
        self.said = Some(reason.to_string());
        Some(match self.failures {
            1 => format!("clauth proxy: pull failed: {reason}"),
            n => format!(
                "clauth proxy: pull failed ({n} in a row{}): {reason}",
                self.elapsed()
                    .map(|d| format!(
                        ", {} so far",
                        crate::usage::humanize_duration(d.as_secs() as i64)
                    ))
                    .unwrap_or_default()
            ),
        })
    }

    /// Record a successful pull. Returns a line when it ENDS an outage, so the
    /// log says the replica is following again rather than just going quiet.
    fn recovered(&mut self) -> Option<String> {
        let failures = std::mem::take(&mut self.failures);
        let elapsed = self.elapsed();
        self.said = None;
        self.started = None;
        if failures == 0 {
            return None;
        }
        Some(format!(
            "clauth proxy: the origin answered again after {failures} failed pull{}{}",
            if failures == 1 { "" } else { "s" },
            elapsed
                .map(|d| format!(
                    " over {}",
                    crate::usage::humanize_duration(d.as_secs() as i64)
                ))
                .unwrap_or_default()
        ))
    }

    fn elapsed(&self) -> Option<Duration> {
        self.started.map(|s| s.elapsed())
    }
}

/// One pull-and-apply. Returns the tag to send next time, and what changed.
///
/// The tag is computed from the body rather than read off the `ETag` header:
/// both ends digest the same content with the same function, so the replica can
/// derive it without trusting a header round-trip.
fn pull_once(
    agent: &ureq::Agent,
    config: &config::ProxyConfig,
    etag: Option<&str>,
) -> Result<(Option<String>, apply::Applied)> {
    match client::pull(agent, &config.origin, &config.token, etag)? {
        client::Pull::Unchanged => Ok((
            etag.map(str::to_string),
            apply::Applied {
                mirrored: config.mirrored.clone(),
                ..Default::default()
            },
        )),
        client::Pull::Fetched(body) => {
            let applied = apply::apply(&body, &config.mirrored)?;
            Ok((Some(body.etag()), applied))
        }
    }
}

/// Record the new manifest, so the next prune knows what this proxy owns.
fn remember(config: &mut config::ProxyConfig, applied: &apply::Applied) -> Result<()> {
    if applied.mirrored == config.mirrored {
        return Ok(());
    }
    config.mirrored = applied.mirrored.clone();
    config::save(config)
}

fn report(applied: &apply::Applied) {
    outln!(
        "clauth: mirrored {} profile{}{}",
        applied.mirrored.len(),
        if applied.mirrored.len() == 1 { "" } else { "s" },
        applied
            .active
            .as_deref()
            .map(|a| format!(", active '{a}'"))
            .unwrap_or_default()
    );
    if !applied.pruned.is_empty() {
        outln!("clauth: removed {}", applied.pruned.join(", "));
    }
}

/// The follow loop's version: silent on a tick that changed nothing, so a
/// steady-state proxy does not write a line to `daemon.log` every minute.
fn report_log(applied: &apply::Applied) {
    if applied.is_quiet() {
        return;
    }
    logline!(
        "clauth proxy: updated {}{}{}",
        if applied.written.is_empty() {
            "nothing".to_string()
        } else {
            applied.written.join(", ")
        },
        if applied.pruned.is_empty() {
            String::new()
        } else {
            format!("; removed {}", applied.pruned.join(", "))
        },
        if applied.relinked {
            format!(
                "; live credentials now '{}'",
                applied.active.as_deref().unwrap_or("none")
            )
        } else {
            String::new()
        }
    );
}

fn forget() -> Result<()> {
    if config::forget()? {
        outln!(
            "clauth: stopped mirroring. The refresher, switching and login work here again.\n\
             The mirrored profiles are still on disk and their credentials carry no refresh \
             token, so re-authenticate anything you mean to keep using with `clauth login`."
        );
    } else {
        outln!("clauth: this host was not mirroring anything.");
    }
    Ok(())
}

/// Read the origin's bearer token without putting it on a command line.
///
/// Echo-off on a TTY, one line from a pipe otherwise, matching how
/// `clauth login --setup-token` takes its mint. The value is never echoed and
/// never logged.
fn prompt_token(args: &ProxyArgs) -> Result<String> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read the token from stdin")?;
        return Ok(line.trim().to_string());
    }
    let origin = args.from.as_deref().unwrap_or("the origin");
    outln!("clauth: mirroring {origin}.");
    outln!("  run `clauth daemon --print-token` there, and paste it below (input stays hidden)");
    rpassword::prompt_password("Origin token: ")
        .map(|t| t.trim().to_string())
        .map_err(|e| anyhow::anyhow!("failed to read the token: {e}"))
}

#[cfg(test)]
#[path = "../../tests/inline/proxy.rs"]
mod tests;
