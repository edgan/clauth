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
//! [`IGNORED_DROP_PCT`] settles that on the way in by holding each window at its
//! high-water mark.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::profile::ProfileName;
use crate::profile_cache::{STATUSLINE_CACHE_FILE, load_profile_cache, write_profile_cache};
use crate::usage::{UsageInfo, UsageWindow, iso_to_epoch_secs, now_ms};

/// How far apart a status-line `resets_at` and a cached `resets_at` may sit and
/// still name the same window, in seconds.
///
/// They describe one instant in two roundings: the header is `Math.round`ed to
/// a whole second by Claude Code, while `/usage` reports the sub-second truth
/// just under it (`11:19:59.541249` against the header's `11:20:00`). A couple
/// of seconds of slack absorbs that without ever spanning two real windows,
/// which are hours apart.
const RESET_MATCH_TOLERANCE_SECS: i64 = 5;

/// How far a fresh reading may step BACKWARD inside one window before it is
/// believed, in percentage points.
///
/// Spend only ever accumulates inside a window, so a genuine figure never
/// falls: the only honest drop is a reset, which lands as a new `resets_at` and
/// never reaches this rule. Every small dip therefore comes from the reporter,
/// not the account — most often two Claude Code sessions on one profile, each
/// reporting the header from ITS own last API response. An idle session keeps
/// re-reporting a figure minutes old, and because both stamp the moment clauth
/// ingested them rather than the moment Anthropic issued them, the stale one
/// looks just as fresh and the display oscillates (`92 · 91 · 94`).
///
/// Holding the high-water mark settles that: a step back is dropped, a step
/// forward is always taken, and a real reset clears the mark with it.
///
/// The bound is deliberately generous, because how far a stale reporter lags is
/// set by how long it has been idle, not by anything small — a session quiet
/// through a heavy stretch on another one comes back tens of points behind, and
/// a tight bound would let exactly that walk the display backwards. What is
/// left outside the bound is a fall too steep for lag to explain, which is the
/// only case worth believing over the mark.
const IGNORED_DROP_PCT: f64 = 25.0;

/// One window as Claude Code reports it to a status line.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub(crate) struct LiveWindow {
    /// `used_percentage`: the response header's fraction times 100, so already
    /// on [`UsageWindow::utilization`]'s 0-100 scale. Can exceed 100 when usage
    /// legitimately runs past a window's cap.
    pub(crate) used_percentage: f64,
    /// `resets_at` in unix epoch seconds — the window's identity, and the only
    /// thing tying a reading to the window it was taken from.
    pub(crate) resets_at: i64,
}

/// A profile's most recent status-line reading, as persisted per profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct LiveUsage {
    /// Epoch-ms this reading was ingested. Compared against the usage cache's
    /// own mtime so a poll that landed later always wins.
    pub(crate) observed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) five_hour: Option<LiveWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) seven_day: Option<LiveWindow>,
    /// The Claude Code session that reported it. Diagnostic only — attribution
    /// runs through [`crate::which`], never through this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_id: Option<String>,
}

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
pub(crate) fn run() -> Result<()> {
    let mut raw = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)
        .context("reading the status line payload on stdin")?;
    ingest(&raw)
}

/// [`run`]'s pure-ish core: parse `raw`, resolve the owning profile, persist.
/// Split out so the parse and the refusals are testable without a real stdin.
fn ingest(raw: &str) -> Result<()> {
    let payload: StatusLinePayload = serde_json::from_str(raw)
        .context("the status line payload is not JSON Claude Code would emit")?;
    let Some(mut live) = reading(&payload, now_ms()) else {
        return Ok(());
    };
    let config = crate::profile::load_config()?;
    let Some((name, _)) = crate::which::resolve_active(&config) else {
        return Ok(());
    };
    let name = ProfileName::from(name.as_str());
    if let Some(stored) = load_profile_cache::<LiveUsage>(&name, STATUSLINE_CACHE_FILE) {
        steady(&mut live, &stored);
    }
    write_profile_cache(&name, STATUSLINE_CACHE_FILE, &live);
    Ok(())
}

/// Hold each window at its high-water mark, per [`IGNORED_DROP_PCT`].
///
/// `live.observed_at_ms` is deliberately left at the ingest time even for a
/// window whose figure was held: the reading IS current, it is only the dip
/// that was refused, and letting the stamp go stale would hand the window back
/// to the poll's rounded figure on the next frame.
fn steady(live: &mut LiveUsage, stored: &LiveUsage) {
    live.five_hour = steadied(live.five_hour, stored.five_hour);
    live.seven_day = steadied(live.seven_day, stored.seven_day);
}

/// The figure to keep for one window: `incoming`, unless it steps back from
/// `stored` by no more than [`IGNORED_DROP_PCT`] inside the same window.
///
/// A window `stored` doesn't cover, or covers under a reset that has since
/// rolled, has no mark to defend and takes `incoming` whole — which is what
/// lets a reset land immediately instead of being mistaken for a dip.
fn steadied(incoming: Option<LiveWindow>, stored: Option<LiveWindow>) -> Option<LiveWindow> {
    let (Some(new), Some(held)) = (incoming, stored) else {
        return incoming;
    };
    if !same_reset(new.resets_at, held.resets_at) {
        return incoming;
    }
    let dropped = held.used_percentage - new.used_percentage;
    if dropped > 0.0 && dropped <= IGNORED_DROP_PCT {
        return stored;
    }
    incoming
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
/// window name the same reset instant, within [`RESET_MATCH_TOLERANCE_SECS`]. A
/// reading from a window that has since rolled over describes spend that no
/// longer exists, and a reading attributed to the wrong profile almost never
/// lands on its reset instant, so this is also what keeps a bad attribution
/// inert.
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

/// Whether two reset instants name one window, within
/// [`RESET_MATCH_TOLERANCE_SECS`].
fn same_reset(a: i64, b: i64) -> bool {
    (a - b).abs() <= RESET_MATCH_TOLERANCE_SECS
}

#[cfg(test)]
#[path = "../tests/inline/statusline.rs"]
mod tests;
