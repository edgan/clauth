#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Writing a pulled snapshot into this host's `~/.clauth`.
//!
//! Two things here are safety rather than behavior: every name the origin sends
//! is validated before it is joined into a path, and the prune only ever
//! removes profiles a previous pull created.

#![cfg(unix)]

use super::*;

use crate::profile::{AppState, OAuthToken, Profile, save_app_state, save_profile};
use crate::proxy::wire::{MIRROR_SCHEMA, MirrorState};
use crate::testutil::HomeSandbox;

fn creds(access: &str) -> crate::profile::ClaudeCredentials {
    crate::profile::ClaudeCredentials {
        claude_ai_oauth: Some(OAuthToken {
            access_token: access.to_string(),
            refresh_token: None,
            expires_at: Some(1_900_000_000_000),
            scopes: None,
            subscription_type: None,
        }),
    }
}

fn wire_profile(name: &str, access: &str) -> MirrorProfile {
    MirrorProfile {
        name: name.into(),
        config_toml: format!("# {name}\n"),
        credentials: Some(creds(access)),
        session_token: None,
        account_id: None,
        usage_cache: None,
        third_party_cache: None,
    }
}

fn body(active: &str, profiles: Vec<MirrorProfile>) -> MirrorBody {
    MirrorBody {
        schema: MIRROR_SCHEMA,
        generated_at: "2026-08-30T00:00:00Z".to_string(),
        active_profile: Some(active.into()),
        state: MirrorState {
            profiles: profiles.iter().map(|p| p.name.clone()).collect(),
            fallback_chain: profiles.iter().map(|p| p.name.clone()).collect(),
            auth_broken: Vec::new(),
        },
        profiles,
    }
}

// ── the path guard ──────────────────────────────────────────────────────────

/// `profile_dir` joins the raw name, so this validator is the only thing
/// between a hostile or compromised origin and a write outside the profiles
/// root. It runs over the WHOLE body first: one bad name aborts the snapshot
/// rather than letting the good half land.
#[test]
fn a_traversing_profile_name_is_refused_before_anything_is_written() {
    let _home = HomeSandbox::new();
    let hostile = body(
        "acme",
        vec![
            wire_profile("acme", "a"),
            wire_profile("../../etc/evil", "b"),
        ],
    );

    let err = apply(&hostile, &[]).expect_err("a traversing name must be refused");
    assert!(
        err.to_string().contains("unusable profile name"),
        "got {err}"
    );
    assert!(
        !crate::profile::profile_dir(&"acme".into())
            .unwrap()
            .exists(),
        "the good half of a rejected snapshot must not land either"
    );
}

#[test]
fn an_empty_or_dotted_profile_name_is_refused() {
    let _home = HomeSandbox::new();
    for bad in ["", ".hidden", "has/slash", "has space"] {
        let hostile = body("acme", vec![wire_profile(bad, "x")]);
        assert!(apply(&hostile, &[]).is_err(), "{bad:?} should be refused");
    }
}

// ── writing ─────────────────────────────────────────────────────────────────

#[test]
fn apply_writes_the_profiles_and_the_active_marker() {
    let _home = HomeSandbox::new();
    let applied = apply(
        &body(
            "acme",
            vec![wire_profile("acme", "a"), wire_profile("beta", "b")],
        ),
        &[],
    )
    .expect("apply");

    assert_eq!(applied.mirrored, vec!["acme", "beta"]);
    assert_eq!(applied.active.as_deref(), Some("acme"));
    for name in ["acme", "beta"] {
        assert!(crate::profile::profile_dir(&name.into()).unwrap().exists());
        assert!(
            crate::profile::profile_subpath(&name.into(), "credentials.json")
                .unwrap()
                .exists()
        );
    }
    let state = crate::profile::load_app_state().expect("state");
    assert_eq!(state.active_profile.as_deref(), Some("acme"));
}

/// Credentials and config carry secrets, so they land 0600 in a 0700 dir like
/// everything else clauth writes.
#[test]
fn mirrored_files_are_owner_only() {
    let _home = HomeSandbox::new();
    apply(&body("acme", vec![wire_profile("acme", "a")]), &[]).expect("apply");

    let violations = crate::testutil::owner_only_violations(&crate::profile::clauth_dir().unwrap());
    assert!(violations.is_empty(), "loose permissions: {violations:?}");
}

/// An unchanged tick must not rewrite `credentials.json`. Claude Code re-reads
/// its credentials when that file's mtime moves, so an unconditional write
/// would poke every running session once per interval for nothing.
#[test]
fn an_unchanged_profile_is_not_rewritten() {
    let _home = HomeSandbox::new();
    let snapshot = body("acme", vec![wire_profile("acme", "a")]);
    apply(&snapshot, &[]).expect("first apply");

    let path = crate::profile::profile_subpath(&"acme".into(), "credentials.json").unwrap();
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();

    let applied = apply(&snapshot, &["acme".into()]).expect("second apply");
    assert!(
        applied.written.is_empty(),
        "nothing changed, nothing written"
    );
    assert!(applied.is_quiet(), "a steady-state tick logs nothing");
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        before,
        "the mtime must not move when the bytes did not"
    );
}

/// A rotated access token does get written: this is the path that carries the
/// origin's rotation across, and it is what keeps a replica's sessions alive.
#[test]
fn a_rotated_credential_is_written_through() {
    let _home = HomeSandbox::new();
    apply(&body("acme", vec![wire_profile("acme", "first")]), &[]).expect("first");

    let applied = apply(
        &body("acme", vec![wire_profile("acme", "second")]),
        &["acme".into()],
    )
    .expect("rotation");

    assert_eq!(applied.written, vec!["acme"]);
    let stored = std::fs::read_to_string(
        crate::profile::profile_subpath(&"acme".into(), "credentials.json").unwrap(),
    )
    .unwrap();
    assert!(stored.contains("second"), "the new token landed: {stored}");
}

// ── the prune ───────────────────────────────────────────────────────────────

/// The manifest bounds the prune on both sides. A profile the operator created
/// on this machine is not the proxy's to delete, however little the origin
/// knows about it.
#[test]
fn a_local_only_profile_survives_a_prune() {
    let _home = HomeSandbox::new();
    let mut local = Profile::new("mine".to_string(), None, None);
    local.credentials = Some(creds("mine"));
    save_profile(&local).expect("save");
    save_app_state(&AppState {
        active_profile: Some("mine".into()),
        profiles: vec!["mine".into()],
        ..Default::default()
    })
    .expect("state");

    apply(&body("acme", vec![wire_profile("acme", "a")]), &[]).expect("apply");

    assert!(
        crate::profile::profile_dir(&"mine".into())
            .unwrap()
            .exists(),
        "a profile this proxy never created must not be removed"
    );
    let state = crate::profile::load_app_state().expect("state");
    assert!(
        state.profiles.iter().any(|n| n.as_str() == "mine"),
        "and it keeps its place in the roster: {:?}",
        state.profiles
    );
}

/// A profile this proxy did create, and the origin has since dropped, goes.
#[test]
fn a_dropped_mirrored_profile_is_pruned() {
    let _home = HomeSandbox::new();
    apply(
        &body(
            "acme",
            vec![wire_profile("acme", "a"), wire_profile("beta", "b")],
        ),
        &[],
    )
    .expect("first");

    let applied = apply(
        &body("acme", vec![wire_profile("acme", "a")]),
        &["acme".into(), "beta".into()],
    )
    .expect("second");

    assert_eq!(applied.pruned, vec!["beta"]);
    assert!(
        !crate::profile::profile_dir(&"beta".into())
            .unwrap()
            .exists()
    );
}

// ── the state merge ─────────────────────────────────────────────────────────

/// The origin owns the roster, the chain, the quarantine list and the active
/// marker. It does not own this host's display settings, and a mirror that
/// overwrote them would be changing things nobody asked it to touch.
#[test]
fn local_display_preferences_survive_a_pull() {
    let _home = HomeSandbox::new();
    save_app_state(&AppState {
        active_profile: None,
        profiles: Vec::new(),
        theme: Some(crate::profile::ThemeName::Compatible),
        show_pace: true,
        refresh_interval_ms: 45_000,
        ..Default::default()
    })
    .expect("seed local settings");

    apply(&body("acme", vec![wire_profile("acme", "a")]), &[]).expect("apply");

    let state = crate::profile::load_app_state().expect("state");
    assert_eq!(
        state.theme,
        Some(crate::profile::ThemeName::Compatible),
        "the replica operator's theme is theirs"
    );
    assert!(state.show_pace, "so is every other display toggle");
    assert_eq!(state.refresh_interval_ms, 45_000);
    assert_eq!(
        state.active_profile.as_deref(),
        Some("acme"),
        "but the origin still owns which account is active"
    );
}

/// A chain entry naming a profile that did not arrive would be a dangling
/// reference for every walk that reads it, so the merge filters to what exists.
#[test]
fn the_chain_is_filtered_to_profiles_that_actually_arrived() {
    let _home = HomeSandbox::new();
    let mut snapshot = body("acme", vec![wire_profile("acme", "a")]);
    snapshot.state.fallback_chain = vec!["acme".into(), "ghost".into()];
    snapshot.state.auth_broken = vec!["ghost".into()];

    apply(&snapshot, &[]).expect("apply");

    let state = crate::profile::load_app_state().expect("state");
    assert_eq!(
        state
            .fallback_chain
            .iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>(),
        vec!["acme"]
    );
    assert!(
        state.auth_broken.is_empty(),
        "a ghost quarantine is dropped too"
    );
}

/// An active profile the origin names but did not send would leave the live
/// slot pointing at nothing, so it is dropped rather than installed.
#[test]
fn an_active_profile_that_did_not_arrive_is_not_installed() {
    let _home = HomeSandbox::new();
    let mut snapshot = body("acme", vec![wire_profile("acme", "a")]);
    snapshot.active_profile = Some("ghost".into());

    apply(&snapshot, &[]).expect("apply");

    let state = crate::profile::load_app_state().expect("state");
    assert_eq!(state.active_profile, None);
}

// ── the live slot ───────────────────────────────────────────────────────────

/// The regression that made a working proxy stop following its origin.
///
/// Claude Code writes `~/.claude/.credentials.json` with unlink + write, so
/// clauth's symlink becomes a regular file. `link_profile_credentials` refuses
/// to replace a regular file whose bytes differ from the target, which is right
/// on a normal host (it may be an uncaptured re-login) and wrong here: the
/// origin owns every credential on a replica. Taking that refusal froze the
/// replica on whatever token it held, and because the symlink was gone even a
/// plain rotation could no longer reach the live slot.
#[test]
fn a_switch_reaches_a_live_slot_claude_code_turned_into_a_regular_file() {
    let _home = HomeSandbox::new();
    apply(&body("acme", vec![wire_profile("acme", "a")]), &[]).expect("first pull");

    // Stand in for Claude Code: replace the symlink with a regular file.
    let live = crate::profile::claude_dir()
        .unwrap()
        .join(".credentials.json");
    let carried = std::fs::read(&live).expect("the first pull installed a live login");
    std::fs::remove_file(&live).expect("unlink");
    std::fs::write(&live, &carried).expect("rewrite as a regular file");
    assert!(
        !std::fs::symlink_metadata(&live)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the fixture has to leave a regular file, or it proves nothing"
    );

    // The origin switches.
    let applied = apply(
        &body(
            "beta",
            vec![wire_profile("acme", "a"), wire_profile("beta", "b")],
        ),
        &["acme".into()],
    )
    .expect("second pull");

    assert!(applied.relinked, "the switch has to reach the live slot");
    let now = std::fs::read_to_string(&live).expect("read the live login");
    assert!(
        now.contains('b') && !now.contains("\"accessToken\":\"a\""),
        "the live login should be beta's: {now}"
    );
}

/// The same hazard without a switch: once the symlink is gone, a rotation of the
/// SAME account no longer reaches the live slot by itself, so the replica would
/// sit on an access token that expires in hours.
#[test]
fn a_rotation_reaches_a_regular_file_live_slot_too() {
    let _home = HomeSandbox::new();
    apply(&body("acme", vec![wire_profile("acme", "first")]), &[]).expect("first pull");

    let live = crate::profile::claude_dir()
        .unwrap()
        .join(".credentials.json");
    let carried = std::fs::read(&live).expect("installed");
    std::fs::remove_file(&live).expect("unlink");
    std::fs::write(&live, &carried).expect("rewrite as a regular file");

    apply(
        &body("acme", vec![wire_profile("acme", "second")]),
        &["acme".into()],
    )
    .expect("rotation pull");

    let now = std::fs::read_to_string(&live).expect("read the live login");
    assert!(
        now.contains("second"),
        "the rotated token has to reach the live slot: {now}"
    );
}

/// The relink must not fire on a tick that changed nothing, or a replica would
/// rewrite its live login every minute (and re-run the macOS Keychain write).
#[test]
fn an_unchanged_pull_leaves_the_live_slot_alone() {
    let _home = HomeSandbox::new();
    let snapshot = body("acme", vec![wire_profile("acme", "a")]);
    apply(&snapshot, &[]).expect("first pull");

    let applied = apply(&snapshot, &["acme".into()]).expect("second pull");
    assert!(!applied.relinked, "nothing moved, so nothing to install");
    assert!(applied.is_quiet());
}

/// The failure that made a working proxy stop following its origin, with the
/// symlink pointing at the right file the whole time.
///
/// Claude Code stats the LINK'S TARGET each request and re-reads only when that
/// mtime differs from the one it memoized (`runtime::touch_store`). The store an
/// origin switches TO was normally written on an earlier pull, and
/// `write_profile` does not rewrite bytes that already match, so its mtime can
/// equal the value Claude Code is holding for the store being left. The repoint
/// then succeeds and the session goes on authenticating as the old account.
///
/// Pinned by giving both stores the SAME mtime before the switch, which is the
/// state a steady-state proxy produces on its own.
#[test]
fn a_switch_moves_the_new_stores_mtime_so_claude_code_re_reads_it() {
    use std::time::SystemTime;
    let _home = HomeSandbox::new();

    apply(
        &body(
            "acme",
            vec![wire_profile("acme", "a"), wire_profile("beta", "b")],
        ),
        &[],
    )
    .expect("first pull");

    // Both stores stamped identically: the mtime Claude Code memoized for the
    // account it is on is also the mtime of the one it is about to be given.
    let acme = crate::profile::profile_subpath(&"acme".into(), "credentials.json").unwrap();
    let beta = crate::profile::profile_subpath(&"beta".into(), "credentials.json").unwrap();
    let frozen = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    for store in [&acme, &beta] {
        crate::testutil::set_mtime(store, frozen);
    }
    assert_eq!(
        crate::runtime::file_mtime(&acme),
        crate::runtime::file_mtime(&beta),
        "the fixture has to leave the two equal, or it proves nothing"
    );

    // The origin switches. Bytes are unchanged, so nothing rewrites beta.
    apply(
        &body(
            "beta",
            vec![wire_profile("acme", "a"), wire_profile("beta", "b")],
        ),
        &["acme".into(), "beta".into()],
    )
    .expect("switch pull");

    assert_ne!(
        crate::runtime::file_mtime(&beta),
        Some(frozen),
        "the store switched to must not keep the mtime Claude Code memoized, or \
         the session keeps authenticating as the old account"
    );
}

/// A mirrored switch has to clear `~/.claude.json`'s cached identity, or Claude
/// Code goes on NAMING the previous account even though it is authenticating as
/// the new one: the symlink is right, the token is right, and `/status` is
/// wrong. `finish_switch` strips it for the same reason (issue #17), and a
/// present-but-stale block never self-corrects.
#[test]
fn a_switch_clears_the_cached_identity_claude_code_reports() {
    let _home = HomeSandbox::new();
    let claude_json = crate::profile::home_dir().unwrap().join(".claude.json");
    std::fs::write(
        &claude_json,
        br#"{"oauthAccount":{"emailAddress":"edgan@example.org"},"other":"kept"}"#,
    )
    .expect("seed the cached identity");

    apply(
        &body(
            "beta",
            vec![wire_profile("acme", "a"), wire_profile("beta", "b")],
        ),
        &[],
    )
    .expect("switch pull");

    let after = std::fs::read_to_string(&claude_json).expect("read back");
    assert!(
        !after.contains("oauthAccount"),
        "the stale account block has to go, or /status keeps naming it: {after}"
    );
    assert!(
        after.contains("kept"),
        "and nothing else in the file may be disturbed: {after}"
    );
}

/// A mirrored switch has to install the account's settings, not just its
/// credentials. `finish_switch` writes the profile's env, model routing and
/// `apiKeyHelper` into `~/.claude/settings.json`; a replica that skipped it
/// would ignore model routing, fail outright for an api-key account, and worst
/// of all keep a previous profile's `ANTHROPIC_BASE_URL`, routing this host's
/// requests somewhere the origin is not.
#[test]
fn a_switch_installs_the_accounts_settings_and_clears_the_previous_ones() {
    let _home = HomeSandbox::new();
    let settings = crate::profile::claude_dir().unwrap().join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).expect("mkdir");
    // A leftover from whatever this host was on before.
    std::fs::write(
        &settings,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://stale.example.org","LEFTOVER":"1"}}"#,
    )
    .expect("seed stale settings");

    let mut oauth = wire_profile("acme", "a");
    oauth.config_toml = "[models]\ndefault = \"opusplan\"\n".to_string();
    apply(&body("acme", vec![oauth]), &[]).expect("pull");

    let after = std::fs::read_to_string(&settings).expect("read back");
    assert!(
        !after.contains("stale.example.org"),
        "a previous profile's base url must be cleared, or requests leave for the wrong \
         endpoint: {after}"
    );
    assert!(
        after.contains("opusplan"),
        "the mirrored account's model routing has to be installed: {after}"
    );
}

// ── Claude Code's first-run gate ────────────────────────────────────────────

/// The wiring, not the write: `claude_json`'s own tests pin what the seed does,
/// and this pins that applying a snapshot REACHES it. Without the call a fresh
/// replica gets perfectly good credentials and still cannot start Claude Code,
/// which is the whole bug — and nothing else in an apply would notice.
///
/// Unconditional on purpose. A first pull installs an account without moving it
/// from anywhere, so a seed folded into the relink branch would miss the one
/// case that matters: the machine that has never run Claude Code.
#[test]
fn applying_a_snapshot_clears_claude_codes_first_run_gate() {
    let home = HomeSandbox::new();
    let claude_json = home.home().join(".claude.json");
    save_app_state(&AppState::default()).expect("state");
    assert!(
        !claude_json.exists(),
        "precondition: Claude Code has never run on this replica"
    );

    apply(&body("a", vec![wire_profile("a", "tok-a")]), &[]).expect("apply");

    let seeded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claude_json).expect("read")).expect("parse");
    assert_eq!(
        seeded["hasCompletedOnboarding"],
        serde_json::json!(true),
        "a replica is handed a login it never typed; Claude Code must not ask for another"
    );
}

/// And it stays a no-op afterwards. Every pull that changes anything runs this
/// path, so a seed that rewrote the file each time would make the home copy win
/// `sync_once` on every tick and stomp a live session's runtime copy.
#[test]
fn a_second_apply_does_not_touch_claude_json_again() {
    let home = HomeSandbox::new();
    let claude_json = home.home().join(".claude.json");
    save_app_state(&AppState::default()).expect("state");

    apply(&body("a", vec![wire_profile("a", "tok-a")]), &[]).expect("first apply");
    let stamp = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    crate::testutil::set_mtime(&claude_json, stamp);

    apply(&body("a", vec![wire_profile("a", "tok-a2")]), &["a".into()]).expect("second apply");

    assert_eq!(
        std::fs::metadata(&claude_json)
            .expect("metadata")
            .modified()
            .expect("mtime"),
        stamp,
        "the flag was already true; rewriting it would hand `sync_once` a false winner"
    );
}
