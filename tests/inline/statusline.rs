#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `clauth statusline`: the payload shapes Claude Code actually emits, and the
//! two guards that decide whether a reading is allowed to move a window.
//!
//! The point of the feature is a single digit — `/usage` rounds a window to the
//! nearest whole percent while Claude Code floors the response header, so the
//! two disagree by one for half of every percent. These pin that the overlay
//! lands that digit, and that it stays inert for a reading it can't stand behind.

use super::*;

use crate::statusline_core::{LiveUsage, LiveWindow};
use crate::usage::{PlanInfo, PlanTier, UsageInfo, UsageWindow};

/// The 5h reset used throughout, in the two spellings the feature has to
/// reconcile: `/usage` reports sub-second truth, Claude Code rounds it to a
/// whole second.
const RESET_ISO: &str = "2026-09-02T11:19:59.541249+00:00";
const RESET_EPOCH: i64 = 1_788_348_000;

fn window(utilization: f64, resets_at: Option<&str>) -> UsageWindow {
    UsageWindow {
        utilization,
        resets_at: resets_at.map(str::to_string),
    }
}

fn info(five_h: Option<UsageWindow>, seven_d: Option<UsageWindow>) -> UsageInfo {
    UsageInfo {
        plan: Some(PlanInfo {
            tier: PlanTier::Pro,
            subscription_status: None,
        }),
        five_hour: five_h,
        seven_day: seven_d,
        ..UsageInfo::default()
    }
}

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

// --- payload parsing ---

/// The real shape, lifted from Claude Code's documented status-line schema.
fn payload_json(five_h: &str, seven_d: &str) -> String {
    format!(
        r#"{{"session_id":"abc-123","model":{{"id":"claude-opus-5"}},
            "rate_limits":{{"five_hour":{five_h},"seven_day":{seven_d}}}}}"#
    )
}

#[test]
fn reading_takes_both_windows_off_a_real_payload() {
    let raw = payload_json(
        r#"{"used_percentage":97.0,"resets_at":1788348000}"#,
        r#"{"used_percentage":14.0,"resets_at":1788703200}"#,
    );
    let payload: StatusLinePayload = serde_json::from_str(&raw).unwrap();
    let got = reading(&payload, 1_700).unwrap();

    assert_eq!(got.observed_at_ms, 1_700);
    assert_eq!(got.session_id.as_deref(), Some("abc-123"));
    assert_eq!(got.five_hour, Some(reading_at(97.0, 1_788_348_000)));
    assert_eq!(got.seven_day, Some(reading_at(14.0, 1_788_703_200)));
}

/// `rate_limits` is absent for API-key/Bedrock/Vertex sessions and for a
/// subscriber session before its first API response. Both are ordinary, so
/// neither may fail the hook — there is simply nothing to record.
#[test]
fn a_payload_without_rate_limits_records_nothing() {
    let payload: StatusLinePayload =
        serde_json::from_str(r#"{"session_id":"abc","model":{"id":"x"}}"#).unwrap();
    assert!(reading(&payload, 1).is_none());

    let empty: StatusLinePayload = serde_json::from_str(r#"{"rate_limits":{}}"#).unwrap();
    assert!(reading(&empty, 1).is_none());
}

/// Half a window is no window: a percentage with no `resets_at` can't be tied
/// to the window it came from, and `apply` would refuse it anyway. Dropping it
/// at the door keeps an unanchored figure off disk entirely.
#[test]
fn a_window_missing_either_half_is_dropped() {
    let raw = payload_json(r#"{"used_percentage":97.0}"#, r#"{"resets_at":1788703200}"#);
    let payload: StatusLinePayload = serde_json::from_str(&raw).unwrap();
    assert!(reading(&payload, 1).is_none());
}

/// A non-finite figure would poison every comparison downstream.
#[test]
fn a_non_finite_percentage_is_dropped() {
    let payload = StatusLinePayload {
        rate_limits: Some(RawRateLimits {
            five_hour: Some(RawLiveWindow {
                used_percentage: Some(f64::NAN),
                resets_at: Some(1_788_348_000.0),
            }),
            seven_day: None,
        }),
        session_id: None,
    };
    assert!(reading(&payload, 1).is_none());
}

/// Unknown keys arrive on every payload (`workspace`, `cost`, `context_window`,
/// whatever ships next) and must not break the parse.
#[test]
fn unrelated_payload_fields_are_ignored() {
    let raw = r#"{"cost":{"total_cost_usd":1.5},"worktree":{"name":"x"},
                  "rate_limits":{"five_hour":{"used_percentage":42.0,"resets_at":1788348000}}}"#;
    let payload: StatusLinePayload = serde_json::from_str(raw).unwrap();
    assert_eq!(
        reading(&payload, 9).unwrap().five_hour,
        Some(reading_at(42.0, 1_788_348_000))
    );
}

/// Stdin that isn't a payload is a wiring mistake, and only ever surfaces to
/// someone running the command by hand — so it fails rather than passing
/// silently.
#[test]
fn malformed_stdin_is_an_error() {
    assert!(ingest("not json at all").is_err());
}

// --- the overlay decision ---

/// The bug this exists for, in one assertion: `/usage` rounded a genuine 14.6
/// up to 15, Claude Code floored the same window's header to 14. The overlay
/// makes clauth agree with what the user is reading in Claude Code.
#[test]
fn overlay_replaces_the_rounded_figure_with_the_floored_one() {
    let mut got = info(Some(window(15.0, Some(RESET_ISO))), None);
    apply(&live(Some(reading_at(14.0, RESET_EPOCH)), 2_000), &mut got);
    assert_eq!(got.five_hour.unwrap().utilization, 14.0);
}

/// `/usage` reports `11:19:59.541249`; Claude Code rounds the same instant to
/// `11:20:00`. One window, two roundings — the tolerance has to absorb it or
/// the overlay never fires at all.
#[test]
fn a_sub_second_reset_difference_still_names_one_window() {
    assert!(same_window(
        &reading_at(14.0, RESET_EPOCH),
        &window(15.0, Some(RESET_ISO))
    ));
}

/// A reading from a window that has since rolled over describes spend that no
/// longer exists. Resets are hours apart, so an identity check on the stamp is
/// what keeps it — and a reading misattributed to another profile — inert.
#[test]
fn a_reading_from_another_window_is_refused() {
    let mut got = info(Some(window(3.0, Some(RESET_ISO))), None);
    apply(
        &live(Some(reading_at(99.0, RESET_EPOCH + 5 * 3600)), 2_000),
        &mut got,
    );
    assert_eq!(got.five_hour.unwrap().utilization, 3.0);
}

/// An unanchored window can't be matched, so it can't be overlaid.
#[test]
fn a_cached_window_with_no_reset_stamp_is_refused() {
    let mut got = info(Some(window(15.0, None)), None);
    apply(&live(Some(reading_at(14.0, RESET_EPOCH)), 2_000), &mut got);
    assert_eq!(got.five_hour.unwrap().utilization, 15.0);
}

/// A newer poll does NOT take a window the reading already holds.
///
/// This pinned the opposite until the flapping it caused was reported. The two
/// sources disagree by a point by construction, so letting "whichever measured
/// last" win made the display alternate between them frame after frame, and at
/// the top of a window that reads as spent quota coming back. Once a reading
/// exists for the current window it is the source until that window resets.
#[test]
fn a_newer_poll_does_not_take_back_a_window_the_reading_holds() {
    let mut got = info(Some(window(15.0, Some(RESET_ISO))), None);
    apply(&live(Some(reading_at(14.0, RESET_EPOCH)), 1_000), &mut got);
    assert_eq!(got.five_hour.unwrap().utilization, 14.0);
}

/// The reported symptom, exactly: `/usage` rounded a window to 100 while Claude
/// Code floored the same window to 99, and the tray showed a spent window
/// giving quota back once per frame.
///
/// Asserted across successive frames, because one frame cannot show a flap —
/// the bug was that the SECOND frame differed from the first.
#[test]
fn a_full_window_does_not_flap_between_a_hundred_and_ninety_nine() {
    let reading = live(Some(reading_at(99.0, RESET_EPOCH)), 1_000);
    for frame in 0..3 {
        // Each frame starts from what the poll published, which never stops
        // saying 100 — the reading has to win every time, not just the first.
        let mut got = info(Some(window(100.0, Some(RESET_ISO))), None);
        apply(&reading, &mut got);
        assert_eq!(
            got.five_hour.unwrap().utilization,
            99.0,
            "frame {frame} took the poll's figure back"
        );
    }
}

/// A window the reading does not cover is left to the poll, which is what
/// starts each new window on the polled figure until a session reports into it.
#[test]
fn the_next_window_starts_on_the_poll_again() {
    let mut got = info(Some(window(3.0, Some(RESET_ISO))), None);
    // The reading belongs to the window that has just rolled over.
    apply(
        &live(Some(reading_at(99.0, RESET_EPOCH - 5 * 3600)), 9_000),
        &mut got,
    );
    assert_eq!(
        got.five_hour.unwrap().utilization,
        3.0,
        "a reset hands the window back to the poll, however fresh the reading is"
    );
}

/// The overlay is an overlay: it corrects windows the poll established and
/// never conjures one the poll doesn't have, because it carries no plan, no
/// label, and no scoped windows to build one from.
#[test]
fn a_window_the_poll_never_established_is_not_invented() {
    let mut got = info(None, None);
    apply(&live(Some(reading_at(14.0, RESET_EPOCH)), 2_000), &mut got);
    assert!(got.five_hour.is_none());
}

/// Windows are decided one at a time: a 7d reading that matches must not be
/// held back by a 5h reading that doesn't, and vice versa.
#[test]
fn each_window_is_judged_on_its_own_stamp() {
    let seven_d_epoch = 1_788_703_200;
    let mut got = info(
        Some(window(42.0, Some(RESET_ISO))),
        Some(window(15.0, Some("2026-09-06T13:59:59.541279+00:00"))),
    );
    apply(
        &LiveUsage {
            observed_at_ms: 2_000,
            // 5h reading belongs to a window that has already rolled over.
            five_hour: Some(reading_at(99.0, RESET_EPOCH + 5 * 3600)),
            seven_day: Some(reading_at(14.0, seven_d_epoch)),
            session_id: None,
        },
        &mut got,
    );
    assert_eq!(got.five_hour.unwrap().utilization, 42.0);
    assert_eq!(got.seven_day.unwrap().utilization, 14.0);
}

/// The header reports past the cap when usage legitimately runs over (Claude
/// Code's own note), and clauth's display clamps its own range — so the overlay
/// must not clamp here and hide it.
#[test]
fn a_window_past_its_cap_survives_the_overlay() {
    let mut got = info(Some(window(100.0, Some(RESET_ISO))), None);
    apply(&live(Some(reading_at(101.0, RESET_EPOCH)), 2_000), &mut got);
    assert_eq!(got.five_hour.unwrap().utilization, 101.0);
}
