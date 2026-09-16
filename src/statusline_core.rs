//! What a status-line reading IS, and what happens to it once some host has
//! decided which account it belongs to.
//!
//! Split out of [`crate::statusline`] because a reading now arrives two ways.
//! The local hook still resolves its own session against its own roster and
//! records it here. A session on another machine cannot: it posts the reading to
//! `clauth daemon --listen` over [`STATUSLINE_ROUTE`], and the DAEMON decides
//! whose it is and records it — same types, same high-water rule, same cache
//! file. Everything below is reached from both, so neither path can drift into
//! recording something the other would not.
//!
//! # Attributing a reading nobody local can attribute
//!
//! The payload names no account, and [`crate::which::resolve_active`] — which
//! matches the live `.credentials.json` against the stored profiles — cannot run
//! on the posting host: it may hold no `~/.clauth/profiles` at all, and a
//! mirrored login carries no refresh token to match on even when it does. So the
//! client sends the SHA-256 of the access token its session is authenticating
//! with ([`credential_digest`]) and the daemon matches it against what each of
//! its own accounts would install — which is the daemon's side of the route, and
//! lives with it rather than here.
//!
//! The digest is what crosses rather than the token because the daemon already
//! holds the token: it needs to RECOGNISE the credential, not to learn it. A
//! digest cannot be spent, so a reading in a log or a proxy buffer is inert.
//! Nothing is proved by it either — an attacker holding the bearer token could
//! post any digest they liked — but the worst a wrong one can do is name a
//! window, and [`crate::statusline::apply`] refuses a reading whose reset
//! instant does not match the window it would overwrite.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::profile::ProfileName;
use crate::profile_cache::{STATUSLINE_CACHE_FILE, load_profile_cache, write_profile_cache};

/// The route a remote reading is posted to, spelled ONCE and in full.
///
/// The daemon's router matches on the remainder after its own
/// `daemon::api::routes::API_PREFIX`, so it cannot spell this itself without
/// the two halves being able to disagree; a test there pins prefix + suffix
/// against this constant instead.
#[allow(
    dead_code,
    reason = "only the CLI client dials a URL; the daemon is dialled"
)]
pub(crate) const STATUSLINE_ROUTE: &str = "/api/v1/statusline";

/// Bumped only on a breaking change to [`StatuslineBody`]'s shape. A daemon
/// refuses a body newer than it knows rather than recording half of one: a
/// newer client may express something this build would silently drop, and
/// dropping half a reading is worse than not moving.
pub(crate) const STATUSLINE_SCHEMA: u64 = 1;

/// How far apart a status-line `resets_at` and a cached `resets_at` may sit and
/// still name the same window, in seconds.
///
/// They describe one instant in two roundings: the header is `Math.round`ed to
/// a whole second by Claude Code, while `/usage` reports the sub-second truth
/// just under it (`11:19:59.541249` against the header's `11:20:00`). A couple
/// of seconds of slack absorbs that without ever spanning two real windows,
/// which are hours apart.
pub(crate) const RESET_MATCH_TOLERANCE_SECS: i64 = 5;

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
///
/// Remote readings widen the case rather than changing it: several machines'
/// sessions now report against one account, and a WAN round trip reorders them
/// on top of everything a single host already did.
const IGNORED_DROP_PCT: f64 = 25.0;

/// One window as Claude Code reports it to a status line.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub(crate) struct LiveWindow {
    /// `used_percentage`: the response header's fraction times 100, so already
    /// on [`crate::usage::UsageWindow::utilization`]'s 0-100 scale. Can exceed
    /// 100 when usage legitimately runs past a window's cap.
    pub(crate) used_percentage: f64,
    /// `resets_at` in unix epoch seconds — the window's identity, and the only
    /// thing tying a reading to the window it was taken from.
    pub(crate) resets_at: i64,
}

/// A profile's most recent status-line reading, as persisted per profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct LiveUsage {
    /// Epoch-ms this reading was ingested, stamped by whoever RECORDED it and
    /// never by the reporter. A remote client's clock has no say here: it may
    /// be minutes off, and a stamp from the future would pin a window against
    /// every later reading.
    pub(crate) observed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) five_hour: Option<LiveWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) seven_day: Option<LiveWindow>,
    /// The Claude Code session that reported it. Diagnostic only — attribution
    /// runs through [`crate::which`] locally and through the posted credential
    /// digest remotely, never through this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_id: Option<String>,
}

/// The body of a `POST` to [`STATUSLINE_ROUTE`], defined once and used by both
/// ends the way `proxy::wire::MirrorBody` is, so the client and the daemon
/// cannot drift into disagreeing about a field.
///
/// `observed_at_ms` is deliberately absent — see [`LiveUsage::observed_at_ms`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct StatuslineBody {
    pub(crate) schema: u64,
    /// SHA-256, hex, of the access token the reporting session authenticates
    /// with. See the module docs for why a digest and not the token.
    pub(crate) credential_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) five_hour: Option<LiveWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) seven_day: Option<LiveWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_id: Option<String>,
}

impl StatuslineBody {
    /// The body a client sends for `live`, addressed by `digest`.
    ///
    /// Only `clauth statusline` builds one; the daemon exclusively parses them,
    /// so this is dead code in a build whose statusline client has been cut out.
    #[allow(
        dead_code,
        reason = "the constructing half is the CLI client, not the daemon"
    )]
    pub(crate) fn new(live: &LiveUsage, digest: String) -> Self {
        Self {
            schema: STATUSLINE_SCHEMA,
            credential_sha256: digest,
            five_hour: live.five_hour,
            seven_day: live.seven_day,
            session_id: live.session_id.clone(),
        }
    }
}

/// SHA-256 of an access token, lowercase hex. The only thing that identifies a
/// reporting session to the daemon.
pub(crate) fn credential_digest(access_token: &str) -> String {
    <[u8; 32]>::from(Sha256::digest(access_token.as_bytes()))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Persist `live` as `name`'s reading, holding each window at its high-water
/// mark on the way in.
///
/// The one write path. The local hook reaches it with a profile it resolved
/// itself; the daemon's route reaches it with one the posted digest named.
pub(crate) fn record(name: &ProfileName, live: &mut LiveUsage) {
    if let Some(stored) = load_profile_cache::<LiveUsage>(name, STATUSLINE_CACHE_FILE) {
        steady(live, &stored);
    }
    write_profile_cache(name, STATUSLINE_CACHE_FILE, live);
}

/// Hold each window at its high-water mark, per [`IGNORED_DROP_PCT`].
///
/// `live.observed_at_ms` is deliberately left at the ingest time even for a
/// window whose figure was held: the reading IS current, it is only the dip
/// that was refused, and letting the stamp go stale would hand the window back
/// to the poll's rounded figure on the next frame.
pub(crate) fn steady(live: &mut LiveUsage, stored: &LiveUsage) {
    live.five_hour = steadied(live.five_hour, stored.five_hour);
    live.seven_day = steadied(live.seven_day, stored.seven_day);
}

/// The figure to keep for one window: `incoming`, unless it steps back from
/// `stored` by no more than [`IGNORED_DROP_PCT`] inside the same window.
///
/// A window `stored` doesn't cover, or covers under a reset that has since
/// rolled, has no mark to defend and takes `incoming` whole — which is what
/// lets a reset land immediately instead of being mistaken for a dip.
pub(crate) fn steadied(
    incoming: Option<LiveWindow>,
    stored: Option<LiveWindow>,
) -> Option<LiveWindow> {
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

/// Whether two reset instants name one window, within
/// [`RESET_MATCH_TOLERANCE_SECS`].
pub(crate) fn same_reset(a: i64, b: i64) -> bool {
    (a - b).abs() <= RESET_MATCH_TOLERANCE_SECS
}

#[cfg(test)]
#[path = "../tests/inline/statusline_core.rs"]
mod tests;
