//! Inline tests for the generic usage engine — the JSON scanner
//! (bars/rows/plan), error-envelope rejection, and the one network leg worth a
//! listener (the 401 early-abort). Everything else `fetch` does is exercised
//! manually, not here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

// Real z.ai `/api/monitor/usage/quota/limit` shape (trimmed).
const ZAI_QUOTA: &str = r#"{
    "code":200,"msg":"Operation successful","success":true,
    "data":{"level":"pro","limits":[
        {"type":"TIME_LIMIT","percentage":0,"nextResetTime":1784489490994,
         "usage":1000,"currentValue":0,"remaining":1000},
        {"type":"TOKENS_LIMIT","unit":3,"number":5,"percentage":1,"nextResetTime":1781915527377}
    ]}
}"#;

#[test]
fn scan_zai_quota_shape_yields_bars_and_plan() {
    let value: serde_json::Value = serde_json::from_str(ZAI_QUOTA).unwrap();
    assert!(!is_error_envelope(&value));

    let (plan, bars, rows) = scan(&value);
    assert_eq!(plan.as_deref(), Some("pro"));
    assert_eq!(bars.len(), 2);
    assert_eq!(bars[0].label, "time limit");
    assert_eq!(bars[0].pct, 0.0);
    assert!(bars[0].resets_at.is_some());
    // Absolute amounts: `currentValue` → used, `used + remaining` → total (no
    // explicit ceiling field). Rendered as the bar's trailing `x / y`.
    assert_eq!(bars[0].used, Some(0.0));
    assert_eq!(bars[0].total, Some(1000.0));
    assert_eq!(bars[1].label, "tokens limit");
    assert_eq!(bars[1].pct, 1.0);
    // Percentage-only limit carries no absolute amounts.
    assert!(bars[1].used.is_none() && bars[1].total.is_none());
    assert!(rows.is_empty(), "bars present → no scalar rows harvested");
}

#[test]
fn scan_zai_200_error_envelope_is_rejected() {
    // z.ai returns this 200 body for unknown routes — must not parse as empty usage.
    let value: serde_json::Value =
        serde_json::from_str(r#"{"code":500,"msg":"404 NOT_FOUND","success":false}"#).unwrap();
    assert!(is_error_envelope(&value));
    let (plan, bars, rows) = scan(&value);
    assert!(plan.is_none() && bars.is_empty() && rows.is_empty());
}

#[test]
fn scan_scalar_balance_shape_yields_rows_not_bars() {
    // A provider returning balances (no percentages) → text rows.
    let body = r#"{"is_available":true,"balance_infos":[
        {"currency":"USD","total_balance":12.5,"granted_balance":5.0,"topped_up_balance":7.5}
    ]}"#;
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(!is_error_envelope(&value));

    let (plan, bars, rows) = scan(&value);
    assert!(bars.is_empty(), "no percentage field → no bars");
    assert!(plan.is_none());
    let values: Vec<&str> = rows.iter().map(|r| r.value.as_str()).collect();
    assert!(values.contains(&"12.50"));
    assert!(values.contains(&"7.50"));
    assert!(values.contains(&"5"));
}

#[test]
fn scan_cc_mirror_remaining_fraction_window_yields_one_bar() {
    // Real shunt `GET /usage` shape: Anthropic-mirror pool windows as
    // remaining FRACTIONS (0.93 left = 7% used), null for pools not in play.
    let body = r#"{"pool":{"status":"ok","windows":{
        "5h":{"remaining":null,"resets_at":null},
        "7d":{"remaining":0.93,"resets_at":1789476836},
        "fable":{"remaining":null,"resets_at":null}}}}"#;
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(!is_error_envelope(&value));

    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "null windows and the 7d bar only: {bars:?}");
    // Parent map key, verbatim: overview_windows, roster_rank and
    // window_duration_secs all match the literal `7d`.
    assert_eq!(bars[0].label, "7d");
    // (1.0 - 0.93) is not exact in f64.
    assert!((bars[0].pct - 7.0).abs() < 1e-6, "pct was {}", bars[0].pct);
    // 1789476836 is epoch SECONDS: the 10^12 ms-heuristic must pick seconds.
    assert_eq!(
        bars[0].resets_at.as_deref(),
        Some(crate::usage::epoch_secs_to_iso(1789476836).as_str())
    );
    assert!(bars[0].used.is_none() && bars[0].total.is_none());
    assert!(rows.is_empty(), "a bar formed → no scalar rows");
    assert!(plan.is_none());
}

#[test]
fn a_remaining_fraction_with_no_reset_sibling_is_not_a_window() {
    // A balance-looking object (`remaining` 0..=1, no reset) must not become a
    // window bar — the reset sibling is the discriminator.
    let value: serde_json::Value = serde_json::from_str(r#"{"data":{"remaining":0.5}}"#).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert!(bars.is_empty(), "no reset sibling → no bar: {bars:?}");
    assert!(plan.is_none());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "remaining");
    assert_eq!(rows[0].value, "0.50");
}

#[test]
fn a_remaining_above_one_is_not_a_window() {
    // z.ai carries `remaining` as an absolute TOKEN COUNT; only a fraction in
    // 0..=1 is a window. Here without a percentage key, so the remaining arm
    // is the one being guarded.
    let value: serde_json::Value =
        serde_json::from_str(r#"{"data":{"remaining":1000,"resets_at":1789476836}}"#).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert!(bars.is_empty(), "remaining above 1 → no bar: {bars:?}");
    assert!(plan.is_none());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value, "1000");
}

#[test]
fn array_nested_windows_are_labelled_by_each_elements_own_name_field() {
    // A provider reporting windows as an ARRAY: no element has a key of its
    // own, so the element's own `name` field must label its bar. Inheriting
    // the container key would label every element identically, and neither
    // bar would match the window machinery that keys on literal `5h`/`7d`.
    let body = r#"{"windows":[
        {"name":"5h","remaining":0.5,"resets_at":1789476836},
        {"name":"7d","remaining":0.93,"resets_at":1789553236}]}"#;
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 2, "{bars:?}");
    assert_eq!(bars[0].label, "5h");
    assert_eq!(bars[1].label, "7d");
    // Literal labels are what window_duration_secs parses; a container-key
    // label ("windows") matches none of it.
    assert_eq!(
        crate::usage::window_duration_secs(&bars[0].label),
        Some(5 * 3600)
    );
    assert_eq!(
        crate::usage::window_duration_secs(&bars[1].label),
        Some(7 * 86_400)
    );
    assert!((bars[0].pct - 50.0).abs() < 1e-6, "pct was {}", bars[0].pct);
    assert!((bars[1].pct - 7.0).abs() < 1e-6, "pct was {}", bars[1].pct);
    assert!(bars[0].resets_at.is_some() && bars[1].resets_at.is_some());
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn an_unnamed_array_nested_window_falls_back_to_usage() {
    // No name field and no key of its own: the generic fallback, same as a
    // root-level window. The container key is not the element's name.
    let value: serde_json::Value =
        serde_json::from_str(r#"{"windows":[{"remaining":0.5,"resets_at":1789476836}]}"#).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "usage");
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn a_case_variant_window_literal_name_stays_a_literal() {
    // `5H` in an array element's name field is the same window as a map
    // key's `5h`: normalised to the lowercase literal so the window
    // machinery parses it, never humanized to "5 h".
    let value: serde_json::Value = serde_json::from_str(
        r#"{"windows":[{"name":"5H","remaining":0.5,"resets_at":1789476836}]}"#,
    )
    .unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "5h");
    assert_eq!(
        crate::usage::window_duration_secs(&bars[0].label),
        Some(5 * 3600)
    );
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn a_map_nested_windows_key_beats_its_own_label_field() {
    // For a map entry the key IS the window name and stays the label even
    // when the object describes itself: literal `5h` is what the window
    // machinery parses, a free-form name is not.
    let value: serde_json::Value = serde_json::from_str(
        r#"{"5h":{"name":"five hour window","remaining":0.5,"resets_at":1789476836}}"#,
    )
    .unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "5h");
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn a_percentage_key_beats_the_remaining_fraction() {
    // No double-bar when a CC-mirror object carries both shapes: the
    // percentage key wins, the remaining arm fires only without one. The
    // map key labels the pct bar like it labels a fraction window.
    let body = r#"{"pool":{"windows":{"7d":{
        "percentage":42,"remaining":0.93,"resets_at":1789476836}}}}"#;
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1);
    assert!((bars[0].pct - 42.0).abs() < 1e-6, "pct was {}", bars[0].pct);
    assert_eq!(bars[0].label, "7d");
    assert!(rows.is_empty());
    assert!(plan.is_none());
}

#[test]
fn a_map_nested_percentage_window_key_beats_its_own_label_field() {
    // Both arms share the label chain: for a map entry the key IS the
    // window name, so a pct bar under `5h` labels `5h` even when the object
    // describes itself, engaging the same window machinery.
    let value: serde_json::Value = serde_json::from_str(
        r#"{"windows":{"5h":{"name":"five hour window","percentage":40,"resets_at":1789476836}}}"#,
    )
    .unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "5h");
    assert!((bars[0].pct - 40.0).abs() < 1e-6, "pct was {}", bars[0].pct);
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn an_array_under_a_window_literal_key_keeps_the_literal() {
    // `{"5h": [{…}]}`: the container key parses as a window literal, so it
    // IS the element's window name and passes through the array leg; a
    // non-literal container key ("windows") still does not.
    let value: serde_json::Value = serde_json::from_str(
        r#"{"5h":[{"remaining":0.5,"resets_at":1789476836}],"7d":[{"percentage":40,"resets_at":1789476836}]}"#,
    )
    .unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 2, "{bars:?}");
    assert_eq!(bars[0].label, "5h");
    assert_eq!(bars[1].label, "7d");
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn a_case_variant_map_key_normalizes_to_the_window_literal() {
    // `5H` as a map key is the same window as `5h`: the parent key
    // normalizes to the canonical literal, not passed through verbatim.
    let value: serde_json::Value =
        serde_json::from_str(r#"{"5H":{"remaining":0.5,"resets_at":1789476836}}"#).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "5h");
    assert_eq!(
        crate::usage::window_duration_secs(&bars[0].label),
        Some(5 * 3600)
    );
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn a_left_key_with_a_reset_sibling_is_a_window() {
    // `left` is the remaining-fraction arm's other key: same shape, same
    // pct derivation.
    let value: serde_json::Value =
        serde_json::from_str(r#"{"quota":{"left":0.25,"resets_at":1789476836}}"#).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "quota");
    assert!((bars[0].pct - 75.0).abs() < 1e-6, "pct was {}", bars[0].pct);
    assert!(bars[0].resets_at.is_some());
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn a_live_fraction_with_a_null_reset_is_not_a_window() {
    // A parseable reset sibling is the discriminator: null `resets_at` means
    // the window is not in play, so a live fraction falls through to a row.
    let value: serde_json::Value =
        serde_json::from_str(r#"{"windows":{"5h":{"remaining":0.5,"resets_at":null}}}"#).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert!(bars.is_empty(), "null reset → no bar: {bars:?}");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "remaining");
    assert_eq!(rows[0].value, "0.50");
    assert!(plan.is_none());
}

#[test]
fn a_root_level_window_uses_the_usage_fallback_label() {
    // No parent key and no name field: the fallback label is "usage".
    let value: serde_json::Value =
        serde_json::from_str(r#"{"remaining":0.5,"resets_at":1789476836}"#).unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "usage");
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn a_zero_percentage_key_beats_the_remaining_fraction() {
    // Percentage 0 is a real reading (a window nothing has drained), inside
    // the 0..=100 range, so it wins the arm race against a live fraction —
    // the fraction must not resurrect as the bar.
    let value: serde_json::Value = serde_json::from_str(
        r#"{"windows":{"5h":{"percentage":0,"remaining":0.1,"resets_at":1789476836}}}"#,
    )
    .unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert!((bars[0].pct - 0.0).abs() < 1e-6, "pct was {}", bars[0].pct);
    assert_eq!(bars[0].label, "5h");
    assert!(rows.is_empty() && plan.is_none());
}

#[test]
fn an_expiry_sibling_makes_a_fraction_a_window_and_bars_win() {
    // `expires_at` counts as a reset sibling, so a fractional balance with an
    // expiry becomes a bar — and bars present means NO scalar rows, even for
    // a sibling balance that would otherwise render as a row.
    let value: serde_json::Value =
        serde_json::from_str(r#"{"credits":{"left":0.3,"expires_at":1789476836},"balance":12.5}"#)
            .unwrap();
    let (plan, bars, rows) = scan(&value);
    assert_eq!(bars.len(), 1, "{bars:?}");
    assert_eq!(bars[0].label, "credits");
    assert!((bars[0].pct - 70.0).abs() < 1e-6, "pct was {}", bars[0].pct);
    assert!(
        rows.is_empty(),
        "bars present → the sibling balance row is suppressed: {rows:?}"
    );
    assert!(plan.is_none());
}

#[test]
fn humanize_label_handles_cases() {
    assert_eq!(humanize_label("TIME_LIMIT"), "time limit");
    assert_eq!(humanize_label("modelCode"), "model code");
    assert_eq!(humanize_label("total_balance"), "total balance");
}

/// A loopback listener answering up to `n` requests with 401. The request
/// count pins the probe's walk: an early abort leaves requests unserved.
///
/// The accept is BLOCKING, so the server thread sleeps in the kernel until
/// the client connects. It still needs CPU to answer, and a loaded windows
/// runner can starve it past the client's own budget (4 s connect + 8 s to
/// response headers): the client reads the hint as `Network`, walks the
/// candidates, and ends in `Status` for a probe that was never wrong. No
/// server-side deadline fixes that race; it only kept the listener alive
/// while the client's own timeouts decide the verdict. The hang guard moved
/// to `join_served`, and the hint test retries a `Status` verdict.
fn serve_401s(n: usize) -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = format!("http://{}", listener.local_addr().expect("local addr"));
    let server = std::thread::spawn(move || {
        let mut served = 0;
        while served < n {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            served += 1;
        }
    });
    (addr, server)
}

/// Join a `serve_401s` thread with a deadline. A server that served its
/// quota exits on its own, so the healthy join completes at once. The
/// deadline bounds only the regression case where the probe stops
/// connecting: the blocked `accept` would hold the join forever. That case
/// skips the join and the caller's verdict check still reds on a wrong
/// outcome; the abandoned thread dies with the process.
fn join_served(server: std::thread::JoinHandle<()>, answered: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !server.is_finished() {
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    server.join().expect(answered);
}

/// A HINT 401 is the key's verdict: that endpoint worked before, so its answer
/// is about the credential, not the route. The prober stops on the FIRST
/// request and hands the caller `AuthExpired` — which suppresses the profile —
/// rather than walking the rest of the list.
///
/// The verdict needs one delivered 401, and the delivery races the client's
/// timeouts on a loaded runner (see `serve_401s`). A `Status` verdict here
/// can only mean the 401 never arrived, so a bounded retry is exact: a real
/// regression that turned hint 401s into misses still reds on every attempt.
#[test]
fn a_hint_401_stops_the_probe_and_reads_auth_expired() {
    let mut last = None;
    for _ in 0..3 {
        let (addr, server) = serve_401s(1);
        let err = fetch(&addr, "sk-dead", Some("/api/usage")).expect_err("the key is dead");
        join_served(server, "the listener answered once");
        if matches!(err, ThirdPartyError::AuthExpired) {
            return;
        }
        last = Some(err);
    }
    panic!(
        "the hint 401 never read as auth-expired: {:?}",
        last.expect("every attempt produced an error")
    );
}

/// A CANDIDATE 401 is just another miss: hosts that 401 unmatched routes
/// exist, and reading one as a dead key would write a durable AuthExpired
/// record a key re-entry cannot clear (the fingerprint hashes the key). With
/// no hint the prober walks the whole candidate list and reports the generic
/// failure, which suppresses as Failed.
#[test]
fn a_candidate_401_is_just_another_miss() {
    let (addr, server) = serve_401s(CANDIDATE_PATHS.len());
    let err = fetch(&addr, "sk-dead", None).expect_err("no candidate worked");
    join_served(server, "every candidate was answered");
    assert!(matches!(err, ThirdPartyError::Status), "got {err:?}");
}
