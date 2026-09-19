#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `POST /api/v1/statusline`: who a posted reading is filed against, and what
//! is refused before anything is written.
//!
//! Everything runs against a [`HomeSandbox`] tempdir, so the route writes into a
//! throwaway `~/.clauth` rather than the operator's. No network: the handler is
//! driven with the same `Request` the HTTP layer would hand it.

#![cfg(unix)]

use super::*;

use crate::profile::{
    AppConfig, AppState, ClaudeCredentials, ConfigHandle, OAuthToken, Profile, save_app_state,
    save_profile,
};
use crate::profile_cache::{STATUSLINE_CACHE_FILE, load_profile_cache};
use crate::statusline_core::{LiveUsage, LiveWindow, StatuslineBody, credential_digest};
use crate::testutil::HomeSandbox;

use super::super::http::Response;
use super::super::routes::API_PREFIX;
/// The router, not this module's handler: the bearer check and the method
/// check are the table's, so a test that asserted them against `handle`
/// directly would be asserting nothing.
use super::super::routes::handle as route;
use super::super::token::AuthToken;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const RESET_EPOCH: i64 = 1_788_348_000;

fn creds(access: &str) -> ClaudeCredentials {
    ClaudeCredentials {
        claude_ai_oauth: Some(OAuthToken {
            access_token: access.to_string(),
            refresh_token: Some(format!("{access}-refresh")),
            expires_at: None,
            scopes: None,
            subscription_type: None,
            ..crate::profile::OAuthToken::default_extra()
        }),
    }
}

/// A stored profile whose `credentials.json` is on disk, since that file is what
/// the route reads to recognise a credential.
fn stored_profile(name: &str, access: &str) -> Profile {
    let mut p = Profile::new(name.to_string(), None, None);
    p.credentials = Some(creds(access));
    save_profile(&p).expect("save profile");
    p
}

fn seeded(profiles: Vec<Profile>, active: &str) -> ConfigHandle {
    let names: Vec<crate::profile::ProfileName> = profiles.iter().map(|p| p.name.clone()).collect();
    let state = AppState {
        active_profile: Some(active.into()),
        profiles: names,
        ..Default::default()
    };
    save_app_state(&state).expect("save app state");
    std::sync::Arc::new(crate::lockorder::RankedMutex::new(AppConfig {
        state,
        profiles,
    }))
}

fn ctx_with(config: ConfigHandle) -> std::sync::Arc<ApiContext> {
    let status_path = crate::profile::clauth_dir()
        .expect("clauth dir")
        .join("status.json");
    ApiContext::new(config, status_path, AuthToken::from_plaintext(TOKEN), None)
}

fn reading(pct: f64, resets_at: i64) -> LiveUsage {
    LiveUsage {
        observed_at_ms: 0,
        five_hour: Some(LiveWindow {
            used_percentage: pct,
            resets_at,
        }),
        seven_day: None,
        session_id: Some("remote-session".to_string()),
    }
}

/// A POST as the HTTP layer would hand it to the router.
fn post(bearer: Option<&str>, body: &StatuslineBody) -> Request {
    Request {
        method: "POST".to_string(),
        path: format!("{API_PREFIX}/statusline"),
        query: String::new(),
        bearer: bearer.map(str::to_string),
        if_none_match: None,
        body: serde_json::to_vec(body).expect("serialize the body"),
        keep_alive: true,
    }
}

fn raw_post(bearer: Option<&str>, body: &str) -> Request {
    Request {
        method: "POST".to_string(),
        path: format!("{API_PREFIX}/statusline"),
        query: String::new(),
        bearer: bearer.map(str::to_string),
        if_none_match: None,
        body: body.as_bytes().to_vec(),
        keep_alive: true,
    }
}

fn body_json(resp: &Response) -> serde_json::Value {
    serde_json::from_slice(&resp.body).expect("response body is json")
}

fn recorded(name: &str) -> Option<LiveUsage> {
    load_profile_cache::<LiveUsage>(
        &crate::profile::ProfileName::from(name),
        STATUSLINE_CACHE_FILE,
    )
}

// --- the route is spelled once ---

/// The client builds a URL from the full path and the router matches on the
/// tail after the prefix. Nothing makes the two agree except this.
#[test]
fn the_client_url_and_the_matched_route_are_one_spelling() {
    assert_eq!(
        format!(
            "{API_PREFIX}{}",
            crate::daemon::api::statusline::ROUTE_SUFFIX
        ),
        crate::statusline_core::STATUSLINE_ROUTE
    );
}

// --- the token, and the method ---

#[test]
fn a_reading_needs_the_bearer_token() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(vec![stored_profile("alpha", "tok-alpha")], "alpha"));
    let body = StatuslineBody::new(&reading(42.0, RESET_EPOCH), credential_digest("tok-alpha"));

    assert_eq!(route(&ctx, &post(None, &body)).status, 401);
    assert_eq!(route(&ctx, &post(Some("wrong"), &body)).status, 401);
    assert!(recorded("alpha").is_none());
}

#[test]
fn the_route_refuses_a_get_with_405() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(vec![stored_profile("alpha", "tok-alpha")], "alpha"));
    let mut req = post(
        Some(TOKEN),
        &StatuslineBody::new(&reading(42.0, RESET_EPOCH), credential_digest("tok-alpha")),
    );
    req.method = "GET".to_string();
    assert_eq!(route(&ctx, &req).status, 405);
}

// --- attribution ---

/// The point of the route: a session this host has never seen posts a digest,
/// and the reading lands on the account that digest names.
#[test]
fn a_posted_reading_is_recorded_against_the_account_that_installs_the_credential() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(
        vec![
            stored_profile("alpha", "tok-alpha"),
            stored_profile("beta", "tok-beta"),
        ],
        "alpha",
    ));

    let body = StatuslineBody::new(&reading(42.0, RESET_EPOCH), credential_digest("tok-beta"));
    let resp = handle(&ctx, &post(Some(TOKEN), &body));

    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["profile"], "beta");
    let got = recorded("beta").expect("beta's reading");
    assert_eq!(got.five_hour.unwrap().used_percentage, 42.0);
    // Filed against beta and nothing else: a reading on the wrong account would
    // be inert at the overlay, but it would still be wrong on disk.
    assert!(recorded("alpha").is_none());
}

/// The reporter's clock has no say. A stamp from the future would pin the
/// window against every later reading this daemon receives.
#[test]
fn the_daemon_stamps_the_reading_itself() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(vec![stored_profile("alpha", "tok-alpha")], "alpha"));
    let before = crate::usage::now_ms();

    let body = StatuslineBody::new(&reading(42.0, RESET_EPOCH), credential_digest("tok-alpha"));
    assert_eq!(handle(&ctx, &post(Some(TOKEN), &body)).status, 200);

    let got = recorded("alpha").expect("alpha's reading");
    assert!(
        got.observed_at_ms >= before,
        "the reading kept a stamp it did not get here: {}",
        got.observed_at_ms
    );
}

/// A credential no enabled account here installs is an ANSWER, not an error:
/// the ordinary outcome for a host whose account this daemon does not have, and
/// for the seconds between a rotation here and the client picking it up.
#[test]
fn an_unknown_credential_is_404_and_writes_nothing() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(vec![stored_profile("alpha", "tok-alpha")], "alpha"));

    let body = StatuslineBody::new(&reading(42.0, RESET_EPOCH), credential_digest("tok-nobody"));
    let resp = handle(&ctx, &post(Some(TOKEN), &body));

    assert_eq!(resp.status, 404);
    assert!(recorded("alpha").is_none());
}

/// A disabled account is never attributed, however it matched. Its stored
/// credential is left on disk by the disable, so its token stays recognisable
/// long after the operator stopped using it.
#[test]
fn a_disabled_account_is_never_attributed() {
    let _home = HomeSandbox::new();
    let mut disabled = stored_profile("beta", "tok-beta");
    disabled.disabled = true;
    save_profile(&disabled).expect("save disabled profile");
    let ctx = ctx_with(seeded(
        vec![stored_profile("alpha", "tok-alpha"), disabled],
        "alpha",
    ));

    let body = StatuslineBody::new(&reading(42.0, RESET_EPOCH), credential_digest("tok-beta"));
    assert_eq!(handle(&ctx, &post(Some(TOKEN), &body)).status, 404);
    assert!(recorded("beta").is_none());
}

/// Two profiles can legitimately hold one account's credential — a duplicated
/// account — and the active one is the honest answer for a reading that names
/// no other.
#[test]
fn a_duplicated_account_attributes_to_the_active_one() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(
        vec![
            stored_profile("spare", "tok-shared"),
            stored_profile("live", "tok-shared"),
        ],
        "live",
    ));

    let body = StatuslineBody::new(&reading(42.0, RESET_EPOCH), credential_digest("tok-shared"));
    let resp = handle(&ctx, &post(Some(TOKEN), &body));

    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["profile"], "live");
}

// --- the high-water rule, across machines ---

/// The rule that makes several reporters safe, exercised through the route: a
/// stale reading from a second machine must not walk the window backwards.
#[test]
fn a_stale_remote_reading_does_not_walk_the_window_back() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(vec![stored_profile("alpha", "tok-alpha")], "alpha"));
    let digest = credential_digest("tok-alpha");

    let ahead = StatuslineBody::new(&reading(94.0, RESET_EPOCH), digest.clone());
    assert_eq!(handle(&ctx, &post(Some(TOKEN), &ahead)).status, 200);
    let behind = StatuslineBody::new(&reading(92.0, RESET_EPOCH), digest);
    assert_eq!(handle(&ctx, &post(Some(TOKEN), &behind)).status, 200);

    let got = recorded("alpha").expect("alpha's reading");
    assert_eq!(got.five_hour.unwrap().used_percentage, 94.0);
}

// --- bodies this build cannot act on ---

/// Each of these would otherwise become a cache entry nothing ever reads,
/// written under a name chosen by whoever posted it.
#[test]
fn a_body_this_build_cannot_act_on_is_400_and_writes_nothing() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(vec![stored_profile("alpha", "tok-alpha")], "alpha"));
    let digest = credential_digest("tok-alpha");

    for raw in [
        // not JSON at all
        "{ not json".to_string(),
        // a schema this build does not know: refuse rather than record half of it
        format!(
            r#"{{"schema":2,"credential_sha256":"{digest}",
                 "five_hour":{{"used_percentage":42.0,"resets_at":{RESET_EPOCH}}}}}"#
        ),
        // a digest that cannot be one
        format!(
            r#"{{"schema":1,"credential_sha256":"nope",
                 "five_hour":{{"used_percentage":42.0,"resets_at":{RESET_EPOCH}}}}}"#
        ),
        // no window: there is nothing to record
        format!(r#"{{"schema":1,"credential_sha256":"{digest}"}}"#),
    ] {
        let resp = handle(&ctx, &raw_post(Some(TOKEN), &raw));
        assert_eq!(resp.status, 400, "{raw} was not refused");
    }
    assert!(recorded("alpha").is_none());
}

/// Only a schema NEWER than this build's is refused. A lower one is acted on,
/// because every field this build reads means the same thing in it.
///
/// Note what this does not say: the field is not optional. `schema` carries no
/// serde default, so a body that omits it fails to parse and is refused as
/// malformed above — which is right, since `StatuslineBody::new` has always set
/// it and a body without one is not an older client but a broken one.
#[test]
fn an_older_schema_is_still_acted_on() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded(vec![stored_profile("alpha", "tok-alpha")], "alpha"));
    let digest = credential_digest("tok-alpha");
    let raw = format!(
        r#"{{"schema":0,"credential_sha256":"{digest}",
             "five_hour":{{"used_percentage":42.0,"resets_at":{RESET_EPOCH}}}}}"#
    );
    assert_eq!(handle(&ctx, &raw_post(Some(TOKEN), &raw)).status, 200);
    assert!(recorded("alpha").is_some());
}
