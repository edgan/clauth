#![allow(clippy::unwrap_used, clippy::expect_used)]

//! What `/api/v1/mirror` puts on the wire.
//!
//! The invariant every test here defends is one sentence: a refresh token never
//! leaves the origin. Anthropic's refresh chain is single-use, so a second host
//! holding one can revoke the origin's copy just by using it, and clauth
//! answers the `invalid_grant` its loser gets with a quarantine only a re-login
//! lifts. A replica that never receives the token cannot enter that race at
//! all, whatever it or Claude Code decides to do.

#![cfg(unix)]

use super::*;

use crate::profile::{AppState, OAuthToken, Profile, save_app_state, save_profile};
use crate::testutil::HomeSandbox;

fn pair(access: &str, refresh: Option<&str>) -> ClaudeCredentials {
    ClaudeCredentials {
        claude_ai_oauth: Some(OAuthToken {
            access_token: access.to_string(),
            refresh_token: refresh.map(str::to_string),
            expires_at: Some(1_900_000_000_000),
            scopes: Some(vec!["user:inference".to_string()]),
            subscription_type: Some("Pro".to_string()),
            ..crate::profile::OAuthToken::default_extra()
        }),
    }
}

/// A profile on disk with a rotating pair, plus the app state naming it.
fn seed(name: &str) {
    let mut p = Profile::new(name.to_string(), None, None);
    p.credentials = Some(pair(
        &format!("{name}-access"),
        Some(&format!("{name}-refresh")),
    ));
    save_profile(&p).expect("save profile");
    save_app_state(&AppState {
        active_profile: Some(name.into()),
        profiles: vec![name.into()],
        ..Default::default()
    })
    .expect("save state");
}

// ── the strip ───────────────────────────────────────────────────────────────

/// The load-bearing line of the feature, in isolation.
#[test]
fn strip_refresh_token_clears_it_and_keeps_everything_else() {
    let before = pair("access-value", Some("refresh-value"));
    let after = strip_refresh_token(&before);

    let oauth = after.claude_ai_oauth.expect("the pair survives");
    assert_eq!(oauth.refresh_token, None, "the refresh token is gone");
    assert_eq!(
        oauth.access_token, "access-value",
        "the access token is what a replica actually spends"
    );
    assert_eq!(
        oauth.expires_at,
        Some(1_900_000_000_000),
        "the replica needs the expiry to know when its copy stops working"
    );
    assert_eq!(
        oauth.subscription_type.as_deref(),
        Some("Pro"),
        "the tier drives display on the replica and carries no secret"
    );
}

/// An account with no stored pair at all (an api-key profile) survives the
/// strip untouched rather than growing an empty one.
#[test]
fn strip_refresh_token_leaves_a_credential_free_profile_alone() {
    let empty = ClaudeCredentials {
        claude_ai_oauth: None,
    };
    assert!(strip_refresh_token(&empty).claude_ai_oauth.is_none());
}

// ── the body ────────────────────────────────────────────────────────────────

/// End to end through the real disk reader: what `from_disk` produces for a
/// profile whose stored credentials DO carry a refresh token.
#[test]
fn from_disk_strips_the_refresh_token_it_reads() {
    let _home = HomeSandbox::new();
    seed("acme");

    let body = MirrorBody::from_disk().expect("build a mirror body");
    let profile = body.profiles.first().expect("one profile");
    let oauth = profile
        .credentials
        .as_ref()
        .and_then(|c| c.claude_ai_oauth.as_ref())
        .expect("the pair crosses");

    assert_eq!(oauth.access_token, "acme-access");
    assert_eq!(
        oauth.refresh_token, None,
        "the stored refresh token must not reach the body"
    );
}

/// `config.toml` crosses verbatim rather than round-tripping through
/// `ProfileConfig`, so the replica reproduces the origin's own rendering
/// instead of a normalized one that would churn on every pull.
#[test]
fn from_disk_carries_config_toml_verbatim() {
    let _home = HomeSandbox::new();
    seed("acme");
    let on_disk = std::fs::read_to_string(
        crate::profile::profile_subpath(&"acme".into(), "config.toml").unwrap(),
    )
    .expect("read config.toml");

    let body = MirrorBody::from_disk().expect("build a mirror body");
    assert_eq!(body.profiles[0].config_toml, on_disk);
}

/// The account topology crosses; nothing else from `AppState` does. Mirroring a
/// theme or a switch threshold would overwrite the replica operator's own
/// settings to drive decisions a replica never makes.
#[test]
fn from_disk_carries_the_roster_and_the_active_marker() {
    let _home = HomeSandbox::new();
    seed("acme");

    let body = MirrorBody::from_disk().expect("build a mirror body");
    assert_eq!(body.active_profile.as_deref(), Some("acme"));
    assert_eq!(body.state.profiles, vec![ProfileName::from("acme")]);
    assert_eq!(body.schema, MIRROR_SCHEMA);

    // The serialized shape carries no display preference, checked by name so a
    // field added to AppState cannot quietly start crossing.
    let json = serde_json::to_string(&body).expect("serialize");
    for leaked in ["theme", "clock_format", "show_estimates", "reset_display"] {
        assert!(!json.contains(leaked), "{leaked} reached the wire: {json}");
    }
}

// ── the tag ─────────────────────────────────────────────────────────────────

/// The tag must ignore `generated_at`. Including it would change the value on
/// every request, so every conditional GET would miss and the 304 path would be
/// dead weight.
#[test]
fn the_etag_ignores_the_timestamp() {
    let _home = HomeSandbox::new();
    seed("acme");

    let mut first = MirrorBody::from_disk().expect("build");
    let tag = first.etag();
    first.generated_at = "1999-01-01T00:00:00Z".to_string();
    assert_eq!(first.etag(), tag, "time passing is not a content change");
}

/// A rotated access token has to change the tag, or a replica would sit on the
/// token it first pulled until its session died.
#[test]
fn the_etag_moves_when_a_credential_does() {
    let _home = HomeSandbox::new();
    seed("acme");
    let before = MirrorBody::from_disk().expect("build").etag();

    let mut rotated = Profile::new("acme".to_string(), None, None);
    rotated.credentials = Some(pair("acme-access-2", Some("acme-refresh-2")));
    save_profile(&rotated).expect("save the rotation");

    assert_ne!(
        MirrorBody::from_disk().expect("rebuild").etag(),
        before,
        "a new access token must be visible to a conditional GET"
    );
}

// ── the session-token sidecar ───────────────────────────────────────────────

/// A genuine `claude setup-token` mint crosses. It carries no refresh token by
/// definition, and it is what a switch installs for a CLA-SPLIT profile, so a
/// replica that did not receive it would run sessions on a different login than
/// the origin does.
#[test]
fn a_long_lived_session_token_is_mirrored() {
    let _home = HomeSandbox::new();
    seed("acme");
    crate::claude::write_session_token(
        &"acme".into(),
        "sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1_700_000_000_000,
    )
    .expect("write the sidecar");

    let body = MirrorBody::from_disk().expect("build");
    let sidecar = body.profiles[0]
        .session_token
        .as_ref()
        .and_then(|c| c.claude_ai_oauth.as_ref())
        .expect("the mint crosses");

    assert!(sidecar.access_token.starts_with("sk-ant-oat01-"));
    assert_eq!(sidecar.refresh_token, None);
}

/// A sidecar holding a ROTATING pair is a mis-fill, and the origin ignores it
/// too (`install_source_path` only takes a genuinely long-lived one). Mirroring
/// it would hand the replica a login this host is not itself using, and one that
/// dies in hours with nothing on that side to refresh it.
///
/// It is also the obvious leak path: the sidecar is a second file carrying a
/// refresh token, so a strip that only covered `credentials.json` would ship it.
#[test]
fn a_mis_filled_sidecar_is_neither_mirrored_nor_leaked() {
    let _home = HomeSandbox::new();
    seed("acme");
    let rotating = pair("sidecar-access", Some("sidecar-refresh"));
    crate::profile::atomic_write_600(
        &crate::profile::profile_subpath(&"acme".into(), "session-token.json").unwrap(),
        serde_json::to_vec_pretty(&rotating).unwrap(),
    )
    .expect("write a mis-filled sidecar");

    let body = MirrorBody::from_disk().expect("build");
    assert!(
        body.profiles[0].session_token.is_none(),
        "a sidecar the origin itself ignores must not be mirrored"
    );

    let json = serde_json::to_string(&body).expect("serialize");
    assert!(
        !json.contains("sidecar-refresh"),
        "the sidecar's refresh token reached the wire: {json}"
    );
    assert!(
        !json.contains("sidecar-access"),
        "and neither did its access token, since the sidecar is disengaged: {json}"
    );
}
