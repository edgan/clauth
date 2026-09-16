#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `clauth statusline --to`: what gets stored, what refuses to be stored, and
//! the two rules that keep a status-line hook from becoming a load generator.
//!
//! The setup half runs against a [`HomeSandbox`] tempdir, so nothing here reads
//! or writes the operator's real `~/.clauth`. Nothing here opens a connection
//! either: [`forward`]'s decision to send is separated from the sending, and it
//! is the decision that has to be right — a hook fires several times a second,
//! in front of the user, and gets exactly one chance to be cheap.

use super::*;

use crate::statusline_core::{LiveUsage, LiveWindow};
use crate::testutil::HomeSandbox;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const RESET_EPOCH: i64 = 1_788_348_000;

fn args(to: Option<&str>, token_file: Option<&str>, forget: bool) -> StatuslineArgs {
    StatuslineArgs {
        to: to.map(str::to_string),
        token_file: token_file.map(PathBuf::from),
        forget,
    }
}

fn reading(pct: f64) -> LiveUsage {
    LiveUsage {
        observed_at_ms: 1_000,
        five_hour: Some(LiveWindow {
            used_percentage: pct,
            resets_at: RESET_EPOCH,
        }),
        seven_day: None,
        session_id: Some("session-a".to_string()),
    }
}

fn body(pct: f64) -> StatuslineBody {
    StatuslineBody::new(&reading(pct), "a".repeat(64))
}

// --- the origin has to be a name a certificate can carry ---

/// A bare hostname takes the daemon's own `--listen` default, so an operator
/// types the name and nothing else in the common case.
#[test]
fn a_bare_hostname_takes_the_default_port() {
    assert_eq!(
        parse_origin("boson.example.org").unwrap(),
        format!("boson.example.org:{DEFAULT_PORT}")
    );
    assert_eq!(
        parse_origin(" boson.example.org:9443 ").unwrap(),
        "boson.example.org:9443"
    );
}

/// The mistake this deployment invites, refused by name. The daemon serves its
/// own lego certificate, so an address fails verification whatever is
/// listening — and here that failure would land in a log file nobody is
/// tailing, behind a status line that says nothing.
#[test]
fn an_address_is_refused_before_it_can_become_a_handshake_error() {
    for raw in [
        "10.0.0.4",
        "10.0.0.4:8443",
        "::1",
        "[::1]:8443",
        "127.0.0.1:8443",
    ] {
        let err = parse_origin(raw).unwrap_err().to_string();
        assert!(
            err.contains("not an address"),
            "{raw} was not refused as an address: {err}"
        );
    }
}

/// Everything else that cannot be a hostname, including the ports that are not
/// ports.
#[test]
fn an_unusable_host_or_port_is_refused() {
    for raw in ["", "   ", "-boson.example.org", "boson..example.org", "b:0"] {
        assert!(parse_origin(raw).is_err(), "{raw:?} was accepted");
    }
}

// --- setup, and what it stores ---

/// The token is trimmed, not taken literally: a token file is usually written
/// by a shell redirect, which leaves a newline on the end.
#[test]
fn configure_stores_the_daemon_and_the_token_from_a_file() {
    let home = HomeSandbox::new();
    let token_file = home.home().join("token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();

    configure(&args(Some("boson.example.org"), token_file.to_str(), false)).unwrap();

    let stored = load().unwrap().expect("a stored daemon");
    assert_eq!(stored.origin, format!("boson.example.org:{DEFAULT_PORT}"));
    assert_eq!(stored.token, TOKEN);
}

/// A paste that is not a token is refused at setup, where someone is watching,
/// rather than becoming a 401 inside a hook that is forbidden to complain.
#[test]
fn a_mistyped_token_is_refused_where_someone_is_watching() {
    let home = HomeSandbox::new();
    let token_file = home.home().join("token");
    std::fs::write(&token_file, "not-a-token").unwrap();

    let err = configure(&args(Some("boson.example.org"), token_file.to_str(), false))
        .unwrap_err()
        .to_string();
    assert!(err.contains("hex characters"), "{err}");
    // Nothing stored: a refused setup must leave the host exactly as it was.
    assert!(load().unwrap().is_none());
}

/// Re-running with the same daemon spelled out is how an operator confirms it
/// or changes nothing else. Re-prompting there would be a papercut, and the
/// stored token means the same thing to the same host.
#[test]
fn the_same_daemon_reuses_the_stored_token() {
    let home = HomeSandbox::new();
    let token_file = home.home().join("token");
    std::fs::write(&token_file, TOKEN).unwrap();
    configure(&args(Some("boson.example.org"), token_file.to_str(), false)).unwrap();

    configure(&args(Some("boson.example.org:8443"), None, false)).unwrap();

    assert_eq!(load().unwrap().unwrap().token, TOKEN);
}

/// `--forget` re-arms the host: the readings go back to being recorded here.
#[test]
fn forget_removes_the_daemon_and_the_memo() {
    let home = HomeSandbox::new();
    let token_file = home.home().join("token");
    std::fs::write(&token_file, TOKEN).unwrap();
    configure(&args(Some("boson.example.org"), token_file.to_str(), false)).unwrap();
    save_state(&SendState {
        schema: 1,
        origin: Some(format!("boson.example.org:{DEFAULT_PORT}")),
        sent: Some(body(42.0)),
        rejected: None,
        failures: 3,
        failed_at_ms: 5,
    });

    forget().unwrap();

    assert!(load().unwrap().is_none());
    // The memo names what a DAEMON accepted. Left behind, it would suppress the
    // first POST to whichever daemon is configured next.
    assert_eq!(load_state(), SendState::default());
    forget().unwrap();
}

/// A file that exists but cannot be parsed is an error, never a silent "not
/// configured": recording only locally is exactly the bug the operator
/// configured this to fix, and it would look identical.
#[test]
fn an_unparseable_config_is_an_error_rather_than_a_silent_local_fallback() {
    let _home = HomeSandbox::new();
    let path = crate::profile::clauth_dir()
        .unwrap()
        .join("statusline.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{ not json").unwrap();
    assert!(load().is_err());
}

// --- what keeps a per-repaint hook cheap ---

/// A reading that has not moved is not sent again. Claude Code re-runs the
/// status-line command on every state change — several times a second while a
/// response streams — and a POST per fire would be a TLS handshake per frame
/// for a cache entry whose only changed field would be the ingest stamp.
#[test]
fn an_identical_reading_is_not_sent_twice() {
    let state = SendState {
        schema: 1,
        sent: Some(memo_of(&body(42.0))),
        ..SendState::default()
    };
    assert_eq!(state.sent.as_ref(), Some(&memo_of(&body(42.0))));
    assert_ne!(state.sent.as_ref(), Some(&memo_of(&body(43.0))));
}

/// Two sessions on one host report one account's one reading under different
/// session ids. The id is diagnostic only, so sending the second would buy the
/// daemon nothing — the memo compares without it.
#[test]
fn a_second_session_reporting_the_same_reading_is_still_a_duplicate() {
    let mut other = body(42.0);
    other.session_id = Some("session-b".to_string());
    assert_eq!(memo_of(&body(42.0)), memo_of(&other));
}

/// The backoff schedule: doubling from the floor, stopping at the ceiling.
///
/// The ceiling is what makes a daemon that has been down all day cost about a
/// dozen connections an hour instead of one per repaint.
#[test]
fn the_backoff_doubles_from_the_floor_and_stops_at_the_ceiling() {
    assert_eq!(backoff_secs(0), 0);
    assert_eq!(backoff_secs(1), BACKOFF_FLOOR_SECS);
    assert_eq!(backoff_secs(2), BACKOFF_FLOOR_SECS * 2);
    assert_eq!(backoff_secs(4), BACKOFF_FLOOR_SECS * 8);
    // 30 · 2^4 is 480, which the ceiling cuts to 300.
    for failures in [5, 40, u64::MAX] {
        assert_eq!(backoff_secs(failures), BACKOFF_CEILING_SECS);
    }
}

/// A failure suppresses the next POST for the backoff, and only for it.
#[test]
fn a_failure_suppresses_the_next_post_until_the_backoff_is_over() {
    let state = SendState {
        schema: 1,
        origin: None,
        sent: None,
        rejected: None,
        failures: 1,
        failed_at_ms: 100_000,
    };
    let wait_ms = BACKOFF_FLOOR_SECS * 1_000;
    assert!(!backoff_elapsed(&state, 100_000));
    assert!(!backoff_elapsed(&state, 100_000 + wait_ms - 1));
    assert!(backoff_elapsed(&state, 100_000 + wait_ms));
}

/// A clock that has gone backwards — a suspend, an NTP step — must not suppress
/// forever. One redundant POST against a daemon that may well be up is the safe
/// side of that trade.
#[test]
fn a_clock_that_went_backwards_does_not_suppress_forever() {
    let state = SendState {
        schema: 1,
        origin: None,
        sent: None,
        rejected: None,
        failures: 8,
        failed_at_ms: u64::MAX,
    };
    assert!(backoff_elapsed(&state, 1_000));
}

/// A host that was never pointed at a daemon opens no connection and writes no
/// memo, whatever it is handed.
#[test]
fn a_host_with_no_daemon_configured_forwards_nothing() {
    let _home = HomeSandbox::new();
    forward(&reading(42.0));
    assert_eq!(load_state(), SendState::default());
}

/// A session with no readable credential has nothing a daemon could attribute,
/// so it never opens a connection to say so. That covers api-key, Bedrock and
/// Vertex sessions, which carry no rate-limit headers to report either.
#[test]
fn a_session_with_no_credential_never_opens_a_connection() {
    let home = HomeSandbox::new();
    let token_file = home.home().join("token");
    std::fs::write(&token_file, OTHER_TOKEN).unwrap();
    configure(&args(Some("boson.example.org"), token_file.to_str(), false)).unwrap();

    // No `~/.claude/.credentials.json` in the sandbox, so there is no digest.
    forward(&reading(42.0));

    // Untouched: a send that never happened is neither a success to memoize nor
    // a failure to back off from.
    assert_eq!(load_state(), SendState::default());
}

/// A configuration error is not transient: it is there on every fire until
/// someone fixes it. So it goes through the same failure accounting as an
/// unreachable daemon, rather than writing a line per repaint.
#[test]
fn a_broken_config_backs_off_instead_of_logging_every_fire() {
    let _home = HomeSandbox::new();
    let path = crate::profile::clauth_dir()
        .unwrap()
        .join("statusline.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{ not json").unwrap();

    forward(&reading(42.0));
    let after_one = load_state();
    assert_eq!(after_one.failures, 1);

    // Still inside the backoff, so the second fire does not even try.
    forward(&reading(43.0));
    assert_eq!(load_state().failures, after_one.failures);
}

/// A daemon that does not have this account answers 404 for every reading under
/// the same credential, so the refusal is remembered against the CREDENTIAL and
/// not against the body. Otherwise each new percentage would be a fresh request
/// and a fresh log line for an answer that cannot change.
#[test]
fn a_rejected_credential_suppresses_every_later_reading_under_it() {
    let home = HomeSandbox::new();
    let token_file = home.home().join("token");
    std::fs::write(&token_file, TOKEN).unwrap();
    configure(&args(Some("boson.example.org"), token_file.to_str(), false)).unwrap();
    std::fs::create_dir_all(home.home().join(".claude")).unwrap();
    std::fs::write(
        home.home().join(".claude/.credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"tok","refreshToken":"rt"}}"#,
    )
    .unwrap();

    save_state(&SendState {
        schema: 1,
        origin: Some(format!("boson.example.org:{DEFAULT_PORT}")),
        sent: None,
        rejected: Some(crate::statusline_core::credential_digest("tok")),
        failures: 0,
        failed_at_ms: 0,
    });
    let before = load_state();

    // A reading this host has never sent — only the credential is the same.
    forward(&reading(43.0));

    // Nothing attempted: no failure recorded, and the memo is untouched.
    assert_eq!(load_state(), before);
}

/// The rejection is keyed on the token, so a rotation clears it: the next
/// access token is a different credential, and the daemon may well have it.
#[test]
fn a_rotated_credential_is_offered_to_the_daemon_again() {
    let state = SendState {
        schema: 1,
        origin: None,
        sent: None,
        rejected: Some(crate::statusline_core::credential_digest("old-token")),
        failures: 0,
        failed_at_ms: 0,
    };
    let fresh = crate::statusline_core::credential_digest("new-token");
    assert_ne!(state.rejected.as_deref(), Some(fresh.as_str()));
}
