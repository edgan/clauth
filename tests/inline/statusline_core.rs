#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The shared half of `clauth statusline`: the reading itself, the high-water
//! rule that decides whether a fresh one is allowed to move a window, and the
//! body that carries one between machines.
//!
//! Every case here is reached from both directions — the local hook and the
//! daemon's route — so a change that broke one without the other would red here
//! rather than in whichever surface happened to be exercised.

use super::*;

/// The 5h reset used throughout, as Claude Code reports it: epoch seconds,
/// rounded to a whole one. Reconciling that against `/usage`'s sub-second
/// spelling is the overlay's job, and is pinned beside it in
/// `tests/inline/statusline.rs`; nothing here reads an ISO stamp.
const RESET_EPOCH: i64 = 1_788_348_000;

fn live(five_h: Option<LiveWindow>, observed_at_ms: u64) -> LiveUsage {
    LiveUsage {
        observed_at_ms,
        five_hour: five_h,
        seven_day: None,
        session_id: None,
    }
}

fn reading_at(used_percentage: f64, resets_at: i64) -> LiveWindow {
    LiveWindow {
        used_percentage,
        resets_at,
    }
}

// --- the high-water mark, against out-of-order reporters ---

/// The reported bug: two Claude Code sessions on one profile, each reporting
/// the header from its own last API response, walked the tray display back and
/// forth (`92 · 91 · 94`). A small step back is the reporter, never the
/// account — spend does not un-spend inside a window.
#[test]
fn a_small_step_back_inside_one_window_is_ignored() {
    let held = live(Some(reading_at(94.0, RESET_EPOCH)), 1_000);
    let mut got = live(Some(reading_at(92.0, RESET_EPOCH)), 2_000);
    steady(&mut got, &held);
    assert_eq!(got.five_hour, Some(reading_at(94.0, RESET_EPOCH)));
}

/// Holding the figure must not hold the stamp with it: the reading is current,
/// only the dip was refused, and a stale stamp would hand the window straight
/// back to the poll's rounded number.
#[test]
fn a_held_figure_still_carries_the_fresh_stamp() {
    let held = live(Some(reading_at(94.0, RESET_EPOCH)), 1_000);
    let mut got = live(Some(reading_at(92.0, RESET_EPOCH)), 2_000);
    steady(&mut got, &held);
    assert_eq!(got.observed_at_ms, 2_000);
}

/// The bound, from both sides. Exactly `IGNORED_DROP_PCT` is still a dip; past
/// it the correction is large enough to believe.
#[test]
fn the_drop_bound_is_inclusive_and_ends() {
    let held = Some(reading_at(94.0, RESET_EPOCH));
    assert_eq!(steadied(Some(reading_at(69.0, RESET_EPOCH)), held), held);
    assert_eq!(
        steadied(Some(reading_at(68.9, RESET_EPOCH)), held),
        Some(reading_at(68.9, RESET_EPOCH))
    );
}

/// Forward is always believed — the mark is a floor, not a freeze.
#[test]
fn a_step_forward_is_always_taken() {
    let held = Some(reading_at(94.0, RESET_EPOCH));
    assert_eq!(
        steadied(Some(reading_at(94.5, RESET_EPOCH)), held),
        Some(reading_at(94.5, RESET_EPOCH))
    );
}

/// A reset is the one honest drop, and it arrives as a new `resets_at` — so it
/// must land whole rather than being mistaken for a dip and pinned at 94 for
/// the next five hours.
#[test]
fn a_reset_clears_the_mark_instead_of_reading_as_a_dip() {
    let held = Some(reading_at(94.0, RESET_EPOCH));
    let after = Some(reading_at(0.0, RESET_EPOCH + 5 * 3600));
    assert_eq!(steadied(after, held), after);
}

/// A window with no mark yet has nothing to defend.
#[test]
fn a_window_with_no_stored_mark_takes_the_reading() {
    let fresh = Some(reading_at(3.0, RESET_EPOCH));
    assert_eq!(steadied(fresh, None), fresh);
    assert_eq!(steadied(None, Some(reading_at(94.0, RESET_EPOCH))), None);
}

/// 5h and 7d hold their own marks: a dip on one must not drag the other.
#[test]
fn each_window_holds_its_own_mark() {
    let seven_d = 1_788_703_200;
    let held = LiveUsage {
        observed_at_ms: 1_000,
        five_hour: Some(reading_at(94.0, RESET_EPOCH)),
        seven_day: Some(reading_at(12.0, seven_d)),
        session_id: None,
    };
    let mut got = LiveUsage {
        observed_at_ms: 2_000,
        five_hour: Some(reading_at(92.0, RESET_EPOCH)),
        seven_day: Some(reading_at(13.0, seven_d)),
        session_id: None,
    };
    steady(&mut got, &held);
    assert_eq!(got.five_hour, Some(reading_at(94.0, RESET_EPOCH)));
    assert_eq!(got.seven_day, Some(reading_at(13.0, seven_d)));
}

// --- the wire body, as it crosses to a daemon ---

/// The body is the reading, addressed. Every field has to survive the round
/// trip, because the far end reconstructs the reading from nothing else.
#[test]
fn a_body_round_trips_through_its_own_serialization() {
    let reading = LiveUsage {
        observed_at_ms: 9_999,
        five_hour: Some(reading_at(42.7, RESET_EPOCH)),
        seven_day: Some(reading_at(14.9, RESET_EPOCH + 7 * 86_400)),
        session_id: Some("abc-123".to_string()),
    };
    let sent = StatuslineBody::new(&reading, credential_digest("live-access-token"));
    let wire = serde_json::to_string(&sent).unwrap();
    let got: StatuslineBody = serde_json::from_str(&wire).unwrap();

    assert_eq!(got, sent);
    assert_eq!(got.schema, STATUSLINE_SCHEMA);
    assert_eq!(got.five_hour, reading.five_hour);
    assert_eq!(got.seven_day, reading.seven_day);
    assert_eq!(got.session_id.as_deref(), Some("abc-123"));
}

/// `observed_at_ms` is stamped by whoever RECORDS a reading, never by whoever
/// reports one: a client clock minutes fast would otherwise pin a window
/// against every later reading the daemon receives.
#[test]
fn the_reporter_does_not_get_to_stamp_the_reading() {
    let sent = StatuslineBody::new(&live(Some(reading_at(42.0, RESET_EPOCH)), 1), String::new());
    let wire = serde_json::to_string(&sent).unwrap();
    assert!(
        !wire.contains("observed_at"),
        "the body carried a reporter timestamp: {wire}"
    );
}

/// A window the session has nothing to say about is left out of the body
/// entirely, rather than crossing as a null the far end has to special-case.
#[test]
fn a_window_with_no_reading_is_left_out_of_the_body() {
    let sent = StatuslineBody::new(
        &live(Some(reading_at(42.0, RESET_EPOCH)), 1),
        "d".repeat(64),
    );
    let wire = serde_json::to_string(&sent).unwrap();
    assert!(wire.contains("five_hour"));
    assert!(!wire.contains("seven_day"), "{wire}");
    assert!(!wire.contains("session_id"), "{wire}");
}

/// The digest is what identifies a reporting session, so it has to be exactly
/// what a daemon recomputing it from its own copy of the token would get: 64
/// lowercase hex characters, and different for different tokens.
#[test]
fn the_credential_digest_is_lowercase_hex_and_token_specific() {
    let got = credential_digest("sk-ant-oat01-example");
    assert_eq!(got.len(), 64);
    assert!(
        got.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{got}"
    );
    assert_ne!(got, credential_digest("sk-ant-oat01-another"));
    assert_eq!(got, credential_digest("sk-ant-oat01-example"));
}

// --- recording, wherever the reading came from ---

/// A profile in the roster on disk. `write_profile_cache` refuses to write a
/// cache for a name `profiles.toml` does not list, so a fixture that only saved
/// the profile file would record nothing and every assertion below would pass
/// for the wrong reason.
fn seeded_profile(name: &str) -> crate::profile::ProfileName {
    crate::profile::save_profile(&crate::profile::Profile::new(name.to_string(), None, None))
        .expect("save profile");
    crate::profile::save_app_state(&crate::profile::AppState {
        profiles: vec![name.into()],
        ..Default::default()
    })
    .expect("save app state");
    crate::profile::ProfileName::from(name)
}

/// `record` is the one write path, and the high-water rule has to hold across
/// calls rather than only inside one: the readings it exists to reorder arrive
/// in separate invocations, now from separate machines.
#[test]
fn recording_holds_the_mark_across_separate_calls() {
    let _home = crate::testutil::HomeSandbox::new();
    let name = seeded_profile("alpha");

    let mut first = live(Some(reading_at(94.0, RESET_EPOCH)), 1_000);
    record(&name, &mut first);
    let mut stale = live(Some(reading_at(92.0, RESET_EPOCH)), 2_000);
    record(&name, &mut stale);

    let stored: LiveUsage = crate::profile_cache::load_profile_cache(
        &name,
        crate::profile_cache::STATUSLINE_CACHE_FILE,
    )
    .expect("a recorded reading");
    assert_eq!(stored.five_hour, Some(reading_at(94.0, RESET_EPOCH)));
    // The dip was refused, not the reading: a stale stamp would hand the window
    // straight back to the poll's rounded figure.
    assert_eq!(stored.observed_at_ms, 2_000);
}

/// A step forward is always taken, so a remote reading that genuinely advances
/// the window lands even though it arrived after one this host recorded.
#[test]
fn recording_takes_a_step_forward_from_any_reporter() {
    let _home = crate::testutil::HomeSandbox::new();
    let name = seeded_profile("alpha");

    let mut first = live(Some(reading_at(94.0, RESET_EPOCH)), 1_000);
    record(&name, &mut first);
    let mut ahead = live(Some(reading_at(96.0, RESET_EPOCH)), 2_000);
    record(&name, &mut ahead);

    let stored: LiveUsage = crate::profile_cache::load_profile_cache(
        &name,
        crate::profile_cache::STATUSLINE_CACHE_FILE,
    )
    .expect("a recorded reading");
    assert_eq!(stored.five_hour, Some(reading_at(96.0, RESET_EPOCH)));
}
