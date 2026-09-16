//! `clauth statusline` — record the rate-limit windows Claude Code hands its
//! status line, and overlay them on the polled `/usage` figures.
//!
//! # Why a second source at all
//!
//! `/api/oauth/usage` reports each window as a WHOLE percent, and it rounds to
//! nearest: 13,452 readings across every profile in the wild have never carried
//! a fraction. Claude Code's own limit banner does not read that endpoint. It
//! floors the `anthropic-ratelimit-unified-{5h,7d}-utilization` response
//! headers instead (`Math.floor(utilization * 100)`), and those are the true
//! fraction truncated, not rounded. The two therefore disagree by a point for
//! half of every percent, with clauth always the higher of the pair — a live
//! same-instant capture on one account read `5h 42 / 42` but `7d 14 / 15`.
//!
//! No arithmetic recovers the difference: rounding has already destroyed the
//! half-point that decides it. The only fix is to read what Claude Code reads,
//! and the only free way to do that is to let Claude Code hand it over.
//!
//! # The channel
//!
//! Claude Code passes `rate_limits.{five_hour,seven_day}.{used_percentage,
//! resets_at}` to the configured status-line command on stdin, refreshed from
//! the response headers of EVERY API response (its own
//! `claudeAiLimits.extractRawUtilization`, which is deliberately separate from
//! the warning-threshold value). `used_percentage` is the header fraction times
//! 100 — the same 0-100 scale as [`UsageWindow::utilization`] — so flooring it
//! reproduces the banner's digits by construction.
//!
//! That costs nothing: no request, no tokens, no window opened. It arrives only
//! for the account a live session is spending, which is exactly the account
//! whose figure is moving; an idle profile's polled reading is not drifting, so
//! it needs no correction.
//!
//! Wire it into an existing status line by teeing the payload:
//!
//! ```sh
//! input=$(cat)
//! printf '%s' "$input" | clauth statusline &   # fire-and-forget
//! ```
//!
//! # Sessions on another machine
//!
//! Everything above assumes the account being spent is stored on the machine
//! running Claude Code. When the accounts live on a `clauth daemon --listen`
//! elsewhere, this host has nothing to record against and the daemon — the one
//! surface an operator is watching — keeps showing the rounded figure for
//! exactly the account that is moving.
//!
//! `clauth statusline --to <fqdn>` points the hook at that daemon: the reading
//! is posted to its REST API, which attributes and records it there. See
//! [`crate::statusline_remote`] for the client and [`crate::statusline_core`]
//! for what crosses. The local recording below still runs either way, so a host
//! that has its own accounts and its own TUI does not lose them by forwarding.
//!
//! # Trust boundary
//!
//! The reading is an OVERLAY, never a source. It can only lower or raise a
//! window the poll already established, and only when the reading and the poll
//! name the SAME window, so a wrong or stale payload degrades to the polled
//! number rather than inventing one.
//!
//! Inside one window the reading then stays the source until that window resets.
//! It used to yield to any poll that landed after it, and the two sources
//! legitimately disagree by a point — the API rounds, Claude Code floors — so
//! the display alternated between them frame by frame. At the top of a window
//! that alternation reads as spent quota coming back: 100%, then 99%, then 100%.
//!
//! Several sessions can report against one profile at once, each carrying the
//! header from its own last API response, so the readings arrive out of order.
//! `statusline_core::steadied` settles that on the way in by holding each window
//! at its high-water mark.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cli::StatuslineArgs;
use crate::profile::ProfileName;
use crate::profile_cache::{STATUSLINE_CACHE_FILE, load_profile_cache};
use crate::statusline_core::{LiveUsage, LiveWindow, same_reset};
use crate::usage::{UsageInfo, UsageWindow, iso_to_epoch_secs, now_ms};

/// The status-line payload, narrowed to the two things worth keeping. Every
/// field is optional: `rate_limits` is absent for API-key, Bedrock and Vertex
/// sessions, and for a subscriber session that has not had its first API
/// response yet.
#[derive(Debug, Deserialize)]
struct StatusLinePayload {
    #[serde(default)]
    rate_limits: Option<RawRateLimits>,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRateLimits {
    #[serde(default)]
    five_hour: Option<RawLiveWindow>,
    #[serde(default)]
    seven_day: Option<RawLiveWindow>,
}

#[derive(Debug, Deserialize)]
struct RawLiveWindow {
    #[serde(default)]
    used_percentage: Option<f64>,
    /// Epoch seconds. Read as `f64` so a whole number that arrives with a
    /// decimal point still parses.
    #[serde(default)]
    resets_at: Option<f64>,
}

impl RawLiveWindow {
    /// Both halves or nothing: a percentage with no `resets_at` can't be tied
    /// to a window, and [`overlay`] would refuse it anyway.
    fn to_window(&self) -> Option<LiveWindow> {
        let used_percentage = self.used_percentage.filter(|p| p.is_finite())?;
        let resets_at = self.resets_at.filter(|r| r.is_finite())?;
        Some(LiveWindow {
            used_percentage,
            resets_at: resets_at as i64,
        })
    }
}

/// `clauth statusline` — read one status-line payload on stdin and record its
/// rate-limit windows against the profile owning this session's credentials.
///
/// Prints nothing. A status line's stdout IS the rendered line, so anything
/// written there would corrupt the display of whoever pipes this wrong.
///
/// Succeeds quietly when the payload carries no `rate_limits` (an API-key
/// session, or a subscriber session before its first API response) and when the
/// session can't be attributed to a stored profile — neither is an error worth
/// failing a status line over. Malformed stdin IS an error: that is a wiring
/// mistake, and it only surfaces when someone runs this by hand.
///
/// The setup flags never read stdin. `clauth statusline --to <host>` is typed at
/// a prompt, not piped a payload, and a setup run that blocked on an empty stdin
/// would look like a hang.
pub(crate) fn run(args: &StatuslineArgs) -> Result<()> {
    if args.forget {
        return crate::statusline_remote::forget();
    }
    if args.to.is_some() {
        return crate::statusline_remote::configure(args);
    }
    let mut raw = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)
        .context("reading the status line payload on stdin")?;
    ingest(&raw)
}

/// [`run`]'s pure-ish core: parse `raw`, resolve the owning profile, persist,
/// and forward to a configured daemon. Split out so the parse and the refusals
/// are testable without a real stdin.
fn ingest(raw: &str) -> Result<()> {
    let payload: StatusLinePayload = serde_json::from_str(raw)
        .context("the status line payload is not JSON Claude Code would emit")?;
    let Some(live) = reading(&payload, now_ms()) else {
        return Ok(());
    };
    // The local write gets a COPY, because `record` rewrites what it is handed:
    // a window held at this host's high-water mark comes back carrying the mark
    // instead of the figure Claude Code just reported. Forwarding that would
    // post one host's history to the daemon as though this session had read it,
    // and would dedup against the mark, so every real movement under it went
    // unsent. The daemon keeps its own mark; what it needs from here is the
    // reading, unedited.
    let mut local_copy = live.clone();
    let local = record_locally(&mut local_copy);
    // AFTER the local write, and independent of whether it found a profile or
    // even succeeded: on a host whose accounts all live on the daemon, nothing
    // local ever resolves, and that host is precisely the one with something to
    // forward. Letting an unreadable local roster swallow the forward would make
    // the remote case fail for a reason that has nothing to do with it.
    crate::statusline_remote::forward(&live);
    local
}

/// Record the reading against this host's own roster, if this host has one that
/// owns the session. A miss is ordinary, not an error — see [`run`] — but a
/// roster that cannot be READ is, and stays one.
fn record_locally(live: &mut LiveUsage) -> Result<()> {
    let config = crate::profile::load_config()?;
    let Some((name, _)) = crate::which::resolve_active(&config) else {
        return Ok(());
    };
    crate::statusline_core::record(&ProfileName::from(name.as_str()), live);
    Ok(())
}

/// The persistable reading inside a payload, or `None` when it carries neither
/// window. Pure, so the shape mapping is pinned without touching disk.
fn reading(payload: &StatusLinePayload, now_ms: u64) -> Option<LiveUsage> {
    let limits = payload.rate_limits.as_ref()?;
    let five_hour = limits.five_hour.as_ref().and_then(RawLiveWindow::to_window);
    let seven_day = limits.seven_day.as_ref().and_then(RawLiveWindow::to_window);
    (five_hour.is_some() || seven_day.is_some()).then(|| LiveUsage {
        observed_at_ms: now_ms,
        five_hour,
        seven_day,
        session_id: payload.session_id.clone(),
    })
}

/// Overlay `name`'s stored status-line reading onto `info`'s 5h and 7d windows,
/// leaving every other field alone.
///
/// A no-op unless there is a reading to apply; see [`apply`] for the two guards
/// each window must clear. Called on the display path rather than the fetch
/// path so a reading that lands between polls shows up on the next frame; the
/// cost is one small read per profile per refresh, which is the same order as
/// the `UsageInfo` clone it rides alongside.
pub(crate) fn overlay(name: &ProfileName, info: &mut UsageInfo) {
    let Some(live) = load_profile_cache::<LiveUsage>(name, STATUSLINE_CACHE_FILE) else {
        return;
    };
    apply(&live, info);
}

/// [`overlay`]'s decision, testable without the filesystem.
///
/// A window takes the live figure on ONE condition: the reading and the cached
/// window name the same reset instant, within
/// [`crate::statusline_core::RESET_MATCH_TOLERANCE_SECS`]. A
/// reading from a window that has since rolled over describes spend that no
/// longer exists, and a reading attributed to the wrong profile almost never
/// lands on its reset instant, so this is also what keeps a bad attribution
/// inert — including one posted from another machine, where the reporting
/// session is not one this host can see at all.
///
/// Once a reading exists for the current window it is the source until that
/// window resets — a newer poll does NOT take the window back. It used to: the
/// guard compared the reading's ingest time against the usage cache's mtime and
/// let the fresher one win. But the two sources disagree by a point by
/// construction (the API rounds, Claude Code floors), so "whichever measured
/// last" made the displayed figure alternate between them, and at the top of a
/// window that alternation reads as spent quota coming back. Which source wins
/// has to be decided per window, not per timestamp; a value-based rule cannot
/// help, because the 1-point correction this feature exists to make and the
/// 1-point step back it has to stop are the same size.
///
/// The cost is that a session's last reading now retires at the window's reset
/// rather than at the next poll. For the 5h window that is bounded and small.
/// For the 7d window it means that if a session exits and spend continues from
/// another client, the weekly figure can hold the exited session's reading for
/// up to a week. A staleness bound (retire a reading more than N minutes older
/// than the poll) would cap that without restoring the flap, and is deliberately
/// not here yet.
///
/// No clamping and no monotonic guard. Reading LOWER than the poll is the whole
/// point (a floored 14 against a rounded 15), and the display clamps its own
/// range, so a window legitimately past its cap survives to be shown as such.
fn apply(live: &LiveUsage, info: &mut UsageInfo) {
    for (reading, window) in [
        (live.five_hour, info.five_hour.as_mut()),
        (live.seven_day, info.seven_day.as_mut()),
    ] {
        let (Some(reading), Some(window)) = (reading, window) else {
            continue;
        };
        if same_window(&reading, window) {
            window.utilization = reading.used_percentage;
        }
    }
}

/// Whether a live reading and a cached window name the same reset instant.
/// False whenever either side has no usable stamp — an unanchored reading is
/// exactly the one that must not be trusted.
fn same_window(reading: &LiveWindow, cached: &UsageWindow) -> bool {
    cached
        .resets_at
        .as_deref()
        .and_then(iso_to_epoch_secs)
        .is_some_and(|cached| same_reset(cached, reading.resets_at))
}

#[cfg(test)]
#[path = "../tests/inline/statusline.rs"]
mod tests;
