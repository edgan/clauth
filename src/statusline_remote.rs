//! `clauth statusline --to <fqdn>` — post this session's reading to a
//! `clauth daemon --listen` on another machine.
//!
//! The status-line hook records into `~/.clauth` on the box it runs on, which is
//! the right answer only while the accounts are stored there too. Run Claude Code
//! on a second machine — a replica, a laptop against the daemon's accounts, a
//! dev box — and the reading lands nowhere anybody reads, while the daemon that
//! owns the account and publishes `status.json` keeps showing the rounded
//! `/usage` figure for the one window that is actually moving.
//!
//! So this host becomes a client of that daemon's REST API. The auth is the
//! auth every other client of it uses, and deliberately nothing new:
//!
//!   * **TLS to the name on the certificate.** The daemon serves its own
//!     [lego](https://github.com/go-acme/lego) certificate, so a bare address
//!     fails verification whatever is listening. [`parse_origin`] refuses one up
//!     front rather than letting it surface as a handshake dump.
//!   * **The bearer token from `clauth daemon --print-token`**, presented on
//!     every request. Stored 0600 in `~/.clauth/statusline.json`, peer of
//!     `auth_token.json` and `tls.json`.
//!   * **No `--token`.** An argument is visible in `ps` and in shell history,
//!     and this one is a password. It is read echo-off from the terminal, from
//!     a `--token-file`, or as one line from a pipe.
//!
//! # What this must never cost
//!
//! Claude Code re-runs the status-line command on every state change — several
//! times a second while a response streams — and it runs it in the foreground of
//! the thing the user is watching. Two consequences shape everything below.
//!
//! A request per fire is out of the question, so an identical reading is never
//! sent twice ([`SendState::sent`]), and a daemon that is not answering is left
//! alone for a backed-off while ([`backoff_secs`]) instead of being dialled at
//! display rate. And a failure must be silent: the timeouts are seconds, not the
//! minute-scale ones a long poll wants, every diagnostic goes to the log file
//! rather than stderr (which is the channel Claude Code surfaces to the user,
//! and is unbounded), and nothing here ever writes stdout, which IS the rendered
//! status line.

use std::io::IsTerminal as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::cli::StatuslineArgs;
use crate::logline::to_logfile;
use crate::out::outln;
use crate::profile::{ClaudeCredentials, atomic_write_600, clauth_dir};
use crate::statusline_core::{LiveUsage, STATUSLINE_ROUTE, StatuslineBody, credential_digest};
use crate::usage::now_ms;

/// Peer of `status.json` / `auth_token.json` in `~/.clauth`.
const CONFIG_FILE: &str = "statusline.json";
/// The dedup + backoff memo. Separate from the config because it is derived
/// state rewritten several times a minute, and a corrupt one must cost a
/// redundant POST rather than the configured daemon.
const STATE_FILE: &str = "statusline_sent.json";
/// Bumped only on a breaking change to either file's shape, like `status.json`.
const SCHEMA: u64 = 1;

/// The port `--to` fills in for a bare hostname, matching the daemon's own
/// `--listen` default.
pub(crate) const DEFAULT_PORT: u16 = 8443;

/// Hex characters in a daemon API token (`clauth daemon --print-token`).
const TOKEN_LEN: usize = 64;

/// How long a failed POST suppresses the next one, and the ceiling it doubles
/// to. Seconds.
///
/// The floor is what makes a dead daemon cheap: without it a hook firing at
/// display rate would open a connection per frame. The ceiling is only a
/// ceiling — unlike `clauth proxy`'s, nothing expires if a reading is missed,
/// since the next payload carries the current figure and the daemon's own poll
/// covers the gap.
const BACKOFF_FLOOR_SECS: u64 = 30;
const BACKOFF_CEILING_SECS: u64 = 300;

/// `~/.clauth/statusline.json`: which daemon, and the token to reach it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct RemoteConfig {
    pub(crate) schema: u64,
    /// Already normalized to `host:port` by [`parse_origin`].
    pub(crate) origin: String,
    /// The daemon's bearer token, 64 hex characters.
    pub(crate) token: String,
}

fn config_path() -> Result<PathBuf> {
    Ok(clauth_dir()?.join(CONFIG_FILE))
}

fn state_path() -> Result<PathBuf> {
    Ok(clauth_dir()?.join(STATE_FILE))
}

/// The stored daemon, or `None` when this host forwards nowhere.
///
/// A malformed file is a hard error rather than a silent "not configured": an
/// operator who set this up is owed a reason, and quietly recording only
/// locally would look exactly like the bug they configured it to fix. Only the
/// hook's own call site downgrades that to a log line, because a status line
/// must not fail.
pub(crate) fn load() -> Result<Option<RemoteConfig>> {
    let path = config_path()?;
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    };
    let parsed: RemoteConfig = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(parsed))
}

fn save(config: &RemoteConfig) -> Result<()> {
    let path = config_path()?;
    atomic_write_600(&path, serde_json::to_vec_pretty(config)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// `clauth statusline --forget`: stop forwarding, keep recording locally.
pub(crate) fn forget() -> Result<()> {
    let path = config_path()?;
    let removed = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e).with_context(|| format!("failed to remove {}", path.display())),
    };
    // The memo is derived from the daemon that is going away; leaving it would
    // suppress the first POST to whichever daemon is configured next.
    if let Ok(state) = state_path() {
        let _ = std::fs::remove_file(state);
    }
    if removed {
        outln!("clauth: stopped forwarding status-line readings. They are recorded here only.");
    } else {
        outln!("clauth: this host was not forwarding status-line readings.");
    }
    Ok(())
}

/// `clauth statusline --to <fqdn>`: store the daemon and its token, then exit.
///
/// Setup, not a send: it reads no payload and posts nothing. A first reading
/// arrives the next time Claude Code refreshes the status line, which is within
/// a second of the operator going back to it.
pub(crate) fn configure(args: &StatuslineArgs) -> Result<()> {
    let Some(raw) = args.to.as_deref() else {
        bail!("no daemon given; pass --to <fqdn>");
    };
    let origin = parse_origin(raw)?;
    let stored = load()?;

    // A token already on disk is reused for the SAME daemon, so re-running with
    // the host spelled out (to confirm it, or after an upgrade) costs no paste.
    // A different daemon prompts: the old token means nothing to it, and reusing
    // it would surface later as an opaque 401 from a hook that says nothing.
    let token = match (&args.token_file, &stored) {
        (Some(path), _) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?
            .trim()
            .to_string(),
        (None, Some(cfg)) if cfg.origin == origin => cfg.token.clone(),
        (None, _) => prompt_token(&origin)?,
    };
    if !token_is_well_formed(&token) {
        bail!(
            "that does not look like a clauth API token (expected {TOKEN_LEN} hex characters, got \
             {}). Get it from `clauth daemon --print-token` on {origin}",
            token.len()
        );
    }

    save(&RemoteConfig {
        schema: SCHEMA,
        origin: origin.clone(),
        token,
    })?;
    // The memo remembers what was last accepted BY A DAEMON; a new one has
    // accepted nothing, and suppressing the first POST to it would leave the
    // operator staring at an unchanged figure.
    if let Ok(state) = state_path() {
        let _ = std::fs::remove_file(state);
    }
    outln!("clauth: status-line readings now go to {origin}.");
    outln!("  wire the hook in if you have not: `printf '%s' \"$input\" | clauth statusline &`");
    Ok(())
}

/// True for the exact shape `clauth daemon --print-token` emits. Checked here so
/// a mistyped paste is refused at setup, where someone is watching, instead of
/// becoming a 401 inside a hook that is forbidden to complain.
fn token_is_well_formed(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Read the daemon's bearer token without putting it on a command line.
///
/// Echo-off on a TTY, one line from a pipe otherwise — the same shape
/// `clauth login --setup-token` takes its mint with. Never echoed, never logged.
fn prompt_token(origin: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read the token from stdin")?;
        return Ok(line.trim().to_string());
    }
    outln!("clauth: forwarding status-line readings to {origin}.");
    outln!("  run `clauth daemon --print-token` there, and paste it below (input stays hidden)");
    rpassword::prompt_password("Daemon token: ")
        .map(|t| t.trim().to_string())
        .map_err(|e| anyhow::anyhow!("failed to read the token: {e}"))
}

/// Normalize `HOST[:PORT]` to `host:port`, refusing anything that cannot be the
/// name on a certificate.
///
/// An address is rejected by name rather than left to fail later as an opaque
/// TLS error: the daemon serves its own lego certificate, so a client dialing
/// `10.0.0.4:8443` fails verification no matter what is listening, and that is
/// the mistake this deployment invites. Catching it here costs one parse and
/// saves an operator the handshake dump — especially here, where the failure
/// would otherwise land in a log file nobody is tailing.
pub(crate) fn parse_origin(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("no daemon given; pass --to <fqdn>");
    }
    // Addresses are caught BEFORE the port split, because an IPv6 literal is
    // full of colons and `rsplit_once` would happily read `::1` as host `:` on
    // port 1 -- an unhelpful "not a usable hostname" instead of the real reason.
    let bare = raw.trim_start_matches('[');
    if raw.parse::<IpAddr>().is_ok()
        || raw.starts_with('[')
        || raw.matches(':').count() > 1
        || bare
            .split_once(']')
            .is_some_and(|(inside, _)| inside.parse::<IpAddr>().is_ok())
    {
        bail!(
            "the daemon has to be the name on its certificate, not an address: {raw} would fail \
             verification whatever is listening. Use the FQDN `clauth daemon --listen` serves, and \
             make sure it resolves to the daemon from here"
        );
    }
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let port: u16 = p
                .parse()
                .with_context(|| format!("{p:?} is not a usable port"))?;
            if port == 0 {
                bail!("port 0 is not a usable port");
            }
            (h, port)
        }
        _ => (raw, DEFAULT_PORT),
    };
    if host.parse::<IpAddr>().is_ok() {
        bail!(
            "the daemon has to be the name on its certificate, not an address: {host} would fail \
             verification whatever is listening. Use the FQDN `clauth daemon --listen` serves, and \
             make sure it resolves to the daemon from here"
        );
    }
    let plausible = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && !host.ends_with(['-', '.'])
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !plausible {
        bail!("{host:?} is not a usable hostname");
    }
    Ok(format!("{host}:{port}"))
}

/// `~/.clauth/statusline_sent.json`: what the daemon has already been told, and
/// how badly it is currently failing to be told anything.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct SendState {
    #[serde(default)]
    schema: u64,
    /// The daemon everything below was learned from.
    ///
    /// Both memos are answers from ONE daemon and mean nothing about another, so
    /// a mismatch here throws the whole record away. `--to` and `--forget` both
    /// delete this file, but they are not the only way the origin moves: the
    /// config is plain JSON at a documented path, and an operator who repoints
    /// it by hand would otherwise carry `rejected` across — suppressing every
    /// POST to a daemon that may well have the account, until the access token
    /// rotates hours later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    /// The last body a daemon ANSWERED, with `session_id` cleared. An identical
    /// one is not sent again: the reading has not moved, so the POST would
    /// rewrite the same cache entry with a new ingest stamp and nothing else.
    ///
    /// `session_id` is cleared because it is diagnostic only. Two sessions on
    /// one host reporting one account report the same windows under different
    /// ids, and sending the second would buy the daemon nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sent: Option<StatuslineBody>,
    /// The credential digest the daemon last answered `404` for.
    ///
    /// Keyed on the CREDENTIAL and not on the body, unlike [`SendState::sent`]:
    /// if the daemon does not have this account, no reading under this token
    /// will ever be accepted, so posting each new percentage would be a request
    /// and a log line per figure for an answer that cannot change. It clears
    /// itself when the access token rotates — about every eight hours, which is
    /// a sane cadence for re-asking whether the daemon has the account now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rejected: Option<String>,
    /// Consecutive failed POSTs; zero while the daemon is answering.
    #[serde(default)]
    failures: u64,
    /// Epoch-ms of the last failure, the start of the current backoff.
    #[serde(default)]
    failed_at_ms: u64,
}

fn load_state() -> SendState {
    // Every failure here is survivable by re-sending, so a corrupt or missing
    // memo reads as "nothing known" rather than failing the hook.
    state_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|b| serde_json::from_str(&b).ok())
        .unwrap_or_default()
}

fn save_state(state: &SendState) {
    let Ok(path) = state_path() else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(state) else {
        return;
    };
    let _ = atomic_write_600(&path, bytes);
}

/// How long a POST is suppressed after `failures` consecutive failures.
///
/// Pure so the schedule is unit-testable, the shape `switch_backoff_ms` already
/// uses. Doubles from [`BACKOFF_FLOOR_SECS`] and stops at
/// [`BACKOFF_CEILING_SECS`]: a daemon that has been down for an hour is dialled
/// about a dozen times an hour rather than at the rate Claude Code repaints.
fn backoff_secs(failures: u64) -> u64 {
    if failures == 0 {
        return 0;
    }
    let doublings = failures.saturating_sub(1).min(16);
    BACKOFF_FLOOR_SECS
        .saturating_mul(1_u64 << doublings)
        .min(BACKOFF_CEILING_SECS)
}

/// Whether a POST is allowed right now given `state`.
///
/// A stamp in the FUTURE reads as "the backoff is over" rather than as a very
/// long wait. It means the clock moved backwards under this host — a suspend, an
/// NTP step, a container with a borrowed clock — and treating that as a wait
/// would suppress every reading until wall time caught up, which for a bad stamp
/// is forever. One redundant POST against a daemon that may well be up is the
/// cheap side of that trade.
fn backoff_elapsed(state: &SendState, now_ms: u64) -> bool {
    if now_ms < state.failed_at_ms {
        return true;
    }
    let wait_ms = backoff_secs(state.failures).saturating_mul(1_000);
    now_ms - state.failed_at_ms >= wait_ms
}

/// The body as it is memoized: diagnostic-only fields cleared, so two sessions
/// reporting one account's one reading compare equal.
fn memo_of(body: &StatuslineBody) -> StatuslineBody {
    StatuslineBody {
        session_id: None,
        ..body.clone()
    }
}

/// Post `live` to the configured daemon, if there is one and if it is worth
/// posting.
///
/// Infallible by construction. Every failure below is a log line and a backoff,
/// because the caller is a status line: it has already recorded what it could
/// locally, its stdout is the user's display, and there is no outcome here worth
/// failing that over. What a persistent failure must NOT do is accumulate —
/// hence the memo, the backoff, and `to_logfile` rather than stderr.
pub(crate) fn forward(live: &LiveUsage) {
    let now = now_ms();
    let mut state = load_state();

    let config = match load() {
        Ok(Some(config)) => config,
        Ok(None) => return,
        // A configuration error, not a transient one, so it will be here on
        // every fire until someone fixes it — which is exactly why it goes
        // through the same failure accounting as an unreachable daemon rather
        // than writing a line per repaint. It takes the backoff gate itself,
        // since there is no origin to compare it against.
        Err(e) => {
            if backoff_elapsed(&state, now) {
                note_failure(&mut state, &format!("{e:#}"), now);
                save_state(&state);
            }
            return;
        }
    };
    // Before the gate, not after: a stale backoff belongs to the daemon that
    // earned it, and holding a fresh one to it would suppress the first reading
    // after a repoint for up to the ceiling.
    if state.origin.as_deref() != Some(config.origin.as_str()) {
        state = SendState::default();
    }
    // Then the cheap gate, so a daemon that is down costs two file reads per
    // repaint rather than a connection attempt — and so a failure recorded below
    // cannot be re-recorded on the very next fire.
    if !backoff_elapsed(&state, now) {
        return;
    }

    let Some(digest) = session_digest() else {
        // An api-key, Bedrock or Vertex session, or one whose credentials this
        // host cannot read. None of those carries rate-limit headers either, so
        // there is nothing to attribute and nothing lost.
        return;
    };
    if state.rejected.as_deref() == Some(digest.as_str()) {
        return;
    }
    let body = StatuslineBody::new(live, digest);
    let memo = memo_of(&body);
    if state.sent.as_ref() == Some(&memo) {
        return;
    }

    match post(&config, &body) {
        // The daemon answered, so there is nothing to back off from either way.
        Ok(accepted) => {
            // It does not know this credential: an account it does not have, or
            // one whose access token it has rotated past. Said once and then
            // remembered against the CREDENTIAL, so neither the line nor the
            // request repeats for every later figure under the same token.
            let rejected = match accepted {
                Accepted::UnknownCredential => {
                    to_logfile(format_args!(
                        "clauth statusline: {} does not recognise this session's credential, so \
                         its reading was not recorded there. Expected on a host whose account the \
                         daemon does not have; if it should, check `clauth which` here names an \
                         account the daemon lists",
                        config.origin
                    ));
                    Some(body.credential_sha256.clone())
                }
                Accepted::Recorded => None,
            };
            state = SendState {
                schema: SCHEMA,
                origin: Some(config.origin.clone()),
                sent: Some(memo),
                rejected,
                failures: 0,
                failed_at_ms: 0,
            };
        }
        Err(e) => {
            state.origin = Some(config.origin.clone());
            note_failure(&mut state, &format!("{} — {e:#}", config.origin), now);
        }
    }
    save_state(&state);
}

/// Count a failure and back off from it, saying so only occasionally.
///
/// A line on the way INTO an outage and then one every [`LOUD_EVERY`], so a
/// daemon that is down all day costs a handful of lines rather than one per
/// repaint. The log file is size-rotated; stderr is not, and stderr is the
/// channel Claude Code surfaces to the user.
fn note_failure(state: &mut SendState, reason: &str, now_ms: u64) {
    state.schema = SCHEMA;
    state.failures = state.failures.saturating_add(1);
    state.failed_at_ms = now_ms;
    if state.failures == 1 || state.failures.is_multiple_of(LOUD_EVERY) {
        to_logfile(format_args!(
            "clauth statusline: reading not forwarded ({} in a row): {reason}",
            state.failures
        ));
    }
}

/// Failed POSTs between log lines once an outage is established. The first
/// always speaks; this bounds how often an unchanging one repeats itself.
const LOUD_EVERY: u64 = 20;

/// What the daemon did with a reading it answered.
enum Accepted {
    Recorded,
    UnknownCredential,
}

/// The digest of the access token THIS session authenticates with.
///
/// Read through [`crate::which::active_credentials_path`], so it honours
/// `CLAUDE_CONFIG_DIR` and a `clauth start` runtime reports its own credential
/// rather than the global one — the same file `which` resolves against, so the
/// two can never name different logins.
fn session_digest() -> Option<String> {
    let path = crate::which::active_credentials_path()?;
    let body = std::fs::read_to_string(path).ok()?;
    let creds: ClaudeCredentials = serde_json::from_str(&body).ok()?;
    creds
        .access_token()
        .filter(|t| !t.is_empty())
        .map(credential_digest)
}

/// One authenticated POST to the daemon.
///
/// The agent is built per call rather than held in a `LazyLock`: this process
/// makes exactly one request and exits, so a pool would be state nothing ever
/// reuses. Certificate verification is ureq's default and is not relaxed —
/// [`parse_origin`] refuses an address up front precisely so nobody needs it to
/// be.
fn post(config: &RemoteConfig, body: &StatuslineBody) -> Result<Accepted> {
    let agent = ureq::Agent::config_builder()
        // Seconds, deliberately. A hook that hangs is worse than one that gives
        // up: Claude Code fires this again on the next repaint, and the reading
        // it carries will be newer than the one being abandoned here.
        .timeout_connect(Some(Duration::from_secs(3)))
        .timeout_recv_response(Some(Duration::from_secs(4)))
        // One bound over the whole call, body included, so a peer that trickles
        // bytes cannot hold the process open past it.
        .timeout_global(Some(Duration::from_secs(6)))
        // Status codes belong on the Ok path: 404 is an answer, not a failure.
        .http_status_as_error(false)
        .build();
    let agent: ureq::Agent = agent.into();

    let url = format!("https://{}{STATUSLINE_ROUTE}", config.origin);
    let payload = serde_json::to_string(body).context("failed to serialize the reading")?;
    let response = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {}", config.token))
        .header(
            "User-Agent",
            concat!("clauth-statusline/", env!("CARGO_PKG_VERSION")),
        )
        .header("Content-Type", "application/json")
        .send(&payload);

    let response = response.map_err(|e| {
        anyhow::anyhow!(
            "{e}. If this is a certificate error, dial the FQDN the daemon's certificate names, \
             not an address. If the connection was refused, check it is running \
             `clauth daemon --listen` and that CLAUTH_NO_API=1 is not set there"
        )
    })?;

    match response.status().as_u16() {
        200 => Ok(Accepted::Recorded),
        // Also what a daemon too old to have the route answers, and the two are
        // indistinguishable from here. Both are quiet and both are memoized, so
        // neither turns into a retry loop.
        404 => Ok(Accepted::UnknownCredential),
        401 => bail!(
            "the daemon rejected this token (401). Get the current one with \
             `clauth daemon --print-token` there, then re-run `clauth statusline --to {}`",
            config.origin
        ),
        400 => bail!(
            "the daemon refused the reading as malformed (400). Upgrade whichever of the two \
             hosts is older"
        ),
        other => bail!("the daemon answered {other}"),
    }
}

#[cfg(test)]
#[path = "../tests/inline/statusline_remote.rs"]
mod tests;
