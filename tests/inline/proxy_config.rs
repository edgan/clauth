#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `~/.clauth/proxy.json`: what counts as an origin, what counts as a cadence,
//! and what makes this host a replica.

#![cfg(unix)]

use super::*;

use crate::testutil::HomeSandbox;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// ── the origin ──────────────────────────────────────────────────────────────

/// A bare hostname gets the daemon's own default port, so an operator types the
/// name they already know and nothing else.
#[test]
fn a_bare_hostname_gets_the_default_port() {
    assert_eq!(
        parse_origin("boson.example.org").unwrap(),
        "boson.example.org:8443"
    );
}

#[test]
fn an_explicit_port_is_kept() {
    assert_eq!(
        parse_origin("boson.example.org:9443").unwrap(),
        "boson.example.org:9443"
    );
}

/// An address is refused BY NAME rather than left to fail later as an opaque
/// handshake error. The origin serves its own certificate, so dialing an
/// address can never verify -- and once `--listen` defaults to 0.0.0.0, reaching
/// for the IP is the natural mistake.
#[test]
fn an_ip_address_is_refused_with_an_explanation() {
    for addr in ["10.0.0.4", "10.0.0.4:8443", "::1", "[::1]:8443"] {
        let err = parse_origin(addr).expect_err("an address cannot be a certificate name");
        let msg = err.to_string();
        assert!(
            msg.contains("certificate"),
            "the error should say why {addr} cannot work: {msg}"
        );
    }
}

/// The value ends up in a URL, so anything that is not plausibly a hostname is
/// refused before it gets there.
#[test]
fn a_hostname_with_a_separator_or_a_space_is_refused() {
    for bad in ["boson/../etc", "boson example", "", "-boson.org", "a..b"] {
        assert!(
            parse_origin(bad).is_err(),
            "{bad:?} should not be accepted as an origin"
        );
    }
}

// ── the cadence ─────────────────────────────────────────────────────────────

/// The cap is the feature's real timing constraint, not a style preference:
/// past it the replica's access token can expire between pulls, and there is no
/// refresh token on that side to recover with.
#[test]
fn an_interval_above_the_cap_is_refused_and_says_why() {
    let err = validate_interval(ProxyArgs::MAX_INTERVAL_SECS + 1).expect_err("above the cap");
    let msg = err.to_string();
    assert!(msg.contains("cap"), "got {msg}");
    assert!(
        msg.contains("expiry") || msg.contains("expire"),
        "the error should explain the expiry window: {msg}"
    );
}

/// Refused, not clamped. An operator who asked for fifteen minutes has a
/// cadence in mind; silently serving five would leave them believing something
/// this build is not doing.
#[test]
fn an_over_cap_interval_is_not_quietly_clamped() {
    assert!(validate_interval(900).is_err());
    assert_eq!(
        validate_interval(ProxyArgs::MAX_INTERVAL_SECS).unwrap(),
        ProxyArgs::MAX_INTERVAL_SECS,
        "the cap itself is allowed"
    );
}

#[test]
fn a_zero_interval_is_refused() {
    assert!(validate_interval(0).is_err());
}

// ── the replica marker ──────────────────────────────────────────────────────

/// Presence of the file is the marker, so exactly one thing has to be true for
/// a host to be a replica and exactly one thing has to be removed to stop.
#[test]
fn a_host_is_a_replica_only_while_proxy_json_exists() {
    let _home = HomeSandbox::new();
    assert!(!is_replica(), "a fresh host is not a replica");

    save(&ProxyConfig {
        schema: 1,
        origin: "boson.example.org:8443".to_string(),
        token: TOKEN.to_string(),
        interval_secs: 60,
        mirrored: vec!["acme".into()],
    })
    .expect("save");
    assert!(is_replica());

    assert!(forget().expect("forget"), "forget reports it removed one");
    assert!(!is_replica(), "forget re-arms the host");
    assert!(
        !forget().expect("forget again"),
        "a second forget is a no-op"
    );
}

/// A corrupt file still marks the host a replica. The alternative -- treating an
/// unparseable file as "not mirroring" -- would re-arm the refresher behind the
/// operator's back, which is the one outcome this design exists to prevent.
#[test]
fn a_corrupt_proxy_json_still_marks_the_host_a_replica() {
    let _home = HomeSandbox::new();
    // `atomic_write_600` would create ~/.clauth on its way past; a raw
    // write does not, so make the dir the way clauth would.
    crate::profile::mkdir_700(&crate::profile::clauth_dir().unwrap()).expect("mkdir");
    std::fs::write(proxy_path().unwrap(), b"{ not json").expect("write");

    assert!(is_replica(), "existence is the marker, not parseability");
    assert!(
        load().is_err(),
        "but reading it is a hard error, not a default"
    );
}

/// The token is shape-checked on the way in, so a truncated paste fails here
/// with an explanation instead of arriving as an opaque 401 a minute later.
#[test]
fn a_malformed_token_is_refused_before_the_first_request() {
    let _home = HomeSandbox::new();
    let args = ProxyArgs {
        from: Some("boson.example.org".to_string()),
        token_file: None,
        once: true,
        interval: None,
        forget: false,
    };
    let err = resolve(&args, || Ok("too-short".to_string())).expect_err("bad token");
    assert!(err.to_string().contains("64 hex"), "got {err}");
}

/// After the first run a bare `clauth proxy` reuses the stored origin, token and
/// cadence: the operator pastes the token once, not once per restart.
#[test]
fn a_stored_config_makes_a_bare_run_work() {
    let _home = HomeSandbox::new();
    let first = ProxyArgs {
        from: Some("boson.example.org".to_string()),
        token_file: None,
        once: true,
        interval: Some(90),
        forget: false,
    };
    resolve(&first, || Ok(TOKEN.to_string())).expect("first run");

    let bare = ProxyArgs {
        from: None,
        token_file: None,
        once: true,
        interval: None,
        forget: false,
    };
    let config =
        resolve(&bare, || panic!("a stored token must not re-prompt")).expect("second run");
    assert_eq!(config.origin, "boson.example.org:8443");
    assert_eq!(config.token, TOKEN);
    assert_eq!(config.interval_secs, 90, "the stored cadence survives");
}

/// With nothing stored and no --from there is nothing to mirror, and the error
/// says what to run rather than what is missing.
#[test]
fn a_bare_run_with_no_stored_origin_explains_itself() {
    let _home = HomeSandbox::new();
    let bare = ProxyArgs {
        from: None,
        token_file: None,
        once: true,
        interval: None,
        forget: false,
    };
    let err = resolve(&bare, || Ok(TOKEN.to_string())).expect_err("no origin");
    assert!(err.to_string().contains("--from"), "got {err}");
}

/// A new origin re-prompts. The old origin's token means nothing to it, and
/// reusing it would surface as an opaque 401 rather than a prompt.
#[test]
fn pointing_at_a_new_origin_asks_for_its_token() {
    let _home = HomeSandbox::new();
    let first = ProxyArgs {
        from: Some("boson.example.org".to_string()),
        token_file: None,
        once: true,
        interval: None,
        forget: false,
    };
    resolve(&first, || Ok(TOKEN.to_string())).expect("first run");

    let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let moved = ProxyArgs {
        from: Some("gluon.example.org".to_string()),
        ..first
    };
    let config = resolve(&moved, || Ok(other.to_string())).expect("second origin");
    assert_eq!(config.origin, "gluon.example.org:8443");
    assert_eq!(config.token, other);
}

/// The file holds a bearer token, so it gets the same 0600 every other secret
/// in the tree does.
#[test]
fn proxy_json_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let _home = HomeSandbox::new();
    let args = ProxyArgs {
        from: Some("boson.example.org".to_string()),
        token_file: None,
        once: true,
        interval: None,
        forget: false,
    };
    resolve(&args, || Ok(TOKEN.to_string())).expect("resolve");

    let mode = std::fs::metadata(proxy_path().unwrap())
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "proxy.json carries a bearer token");
}
