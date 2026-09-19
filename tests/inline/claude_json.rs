use super::*;
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde_json::json;

use crate::testutil::{HomeSandbox, set_mtime};

// Every sync test holds a `HomeSandbox` even though its members live in a
// tempdir: the syncer resolves the operator's own `~/.claude.json` to decide
// which member gets CC's write style, and a test may not read that home.

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("serialize")).expect("write");
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read")).expect("parse")
}

/// Deterministic timestamps so mtime ordering is unambiguous in tests.
fn t(offset: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + offset)
}

#[test]
fn shared_fields_propagate_from_newest_to_others() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    write_json(
        &a,
        &json!({"numStartups": 2, "mcpServers": {"x": 1}, "oauthAccount": {"emailAddress": "a@x"}}),
    );
    write_json(
        &b,
        &json!({"numStartups": 1, "oauthAccount": {"emailAddress": "b@x"}}),
    );
    set_mtime(&a, t(10));
    set_mtime(&b, t(5));

    sync_paths(&[a.clone(), b.clone()]).expect("sync");

    let bj = read_json(&b);
    assert_eq!(bj["numStartups"], json!(2));
    assert_eq!(bj["mcpServers"], json!({"x": 1}));
    assert_eq!(bj["oauthAccount"]["emailAddress"], json!("b@x")); // per-profile identity kept
    assert_eq!(read_json(&a)["oauthAccount"]["emailAddress"], json!("a@x")); // winner not rewritten
}

#[test]
fn per_profile_fields_never_propagate() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    write_json(
        &a,
        &json!({
            "shared": 1,
            "oauthAccount": {"emailAddress": "a@x"},
            "passesLastSeenRemaining": 99,
            "overageCreditGrantCache": {"a": true}
        }),
    );
    write_json(
        &b,
        &json!({
            "shared": 0,
            "oauthAccount": {"emailAddress": "b@x"},
            "passesLastSeenRemaining": 0,
            "overageCreditGrantCache": {"b": true}
        }),
    );
    set_mtime(&a, t(10));
    set_mtime(&b, t(5));

    sync_paths(&[a, b.clone()]).expect("sync");

    let bj = read_json(&b);
    assert_eq!(bj["shared"], json!(1));
    assert_eq!(bj["oauthAccount"]["emailAddress"], json!("b@x"));
    assert_eq!(bj["passesLastSeenRemaining"], json!(0));
    assert_eq!(bj["overageCreditGrantCache"], json!({"b": true}));
}

/// A sync rewrites a member by rename, so the replacement inode takes the
/// writer's mode, not the old file's: a plain write reverts a runtime copy to
/// the umask on every tick, whatever the seed wrote. The home file is Claude
/// Code's own and keeps CC's posture — clauth must not chmod it either way.
#[cfg(unix)]
#[test]
fn sync_writes_runtime_copies_owner_only_and_leaves_the_home_file_alone() {
    use std::os::unix::fs::PermissionsExt;

    let home = HomeSandbox::new();
    let home_file = home.home().join(".claude.json");
    let winner = home.home().join(".clauth/profiles/p1/runtime/.claude.json");
    let loser = home.home().join(".clauth/profiles/p2/runtime/.claude.json");
    for path in [&winner, &loser] {
        #[allow(clippy::expect_used)]
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir runtime");
    }
    write_json(&home_file, &json!({"numStartups": 1}));
    write_json(&winner, &json!({"numStartups": 9}));
    write_json(&loser, &json!({"numStartups": 2}));
    fs::set_permissions(&home_file, fs::Permissions::from_mode(0o644)).expect("chmod home");
    set_mtime(&home_file, t(5));
    set_mtime(&winner, t(10));
    set_mtime(&loser, t(1));

    sync_paths(&[home_file.clone(), winner, loser.clone()]).expect("sync");

    let mode = |p: &Path| fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(
        read_json(&loser)["numStartups"],
        json!(9),
        "precondition: the loser was rewritten by this sync"
    );
    assert_eq!(
        mode(&loser),
        0o600,
        "a runtime .claude.json is clauth-owned; mode should be 0o600, got {:#o}",
        mode(&loser),
    );
    assert_eq!(
        read_json(&home_file)["numStartups"],
        json!(9),
        "precondition: the home file was rewritten by this sync"
    );
    assert_eq!(
        mode(&home_file),
        0o644,
        "~/.claude.json is Claude Code's own file; the syncer must not restyle its mode"
    );
}

#[test]
fn account_scoped_model_caches_stay_per_profile() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    write_json(
        &a,
        &json!({
            "numStartups": 2,
            "orgModelDefaultCache": {"model": "opus"},
            "modelAccessCache": {"opus": true},
            "additionalModelCostsCache": {"opus": 1},
            "additionalModelOptionsCache": {"opus": ["context-1m"]}
        }),
    );
    // b omits two of the caches entirely and carries its own values for the rest.
    write_json(
        &b,
        &json!({
            "numStartups": 1,
            "modelAccessCache": {"sonnet": true},
            "additionalModelCostsCache": {},
        }),
    );
    set_mtime(&a, t(10));
    set_mtime(&b, t(5));

    sync_paths(&[a, b.clone()]).expect("sync");

    let bj = read_json(&b);
    assert_eq!(bj["numStartups"], json!(2), "shared field still propagates");
    // a's account-scoped model state never bleeds into b
    assert!(
        bj.get("orgModelDefaultCache").is_none(),
        "absent per-profile key must not be injected from the winner"
    );
    assert!(bj.get("additionalModelOptionsCache").is_none());
    assert_eq!(bj["modelAccessCache"], json!({"sonnet": true}));
    assert_eq!(bj["additionalModelCostsCache"], json!({}));
}

/// `primaryApiKey` is a raw `/login`-managed API key Claude Code stores in
/// `.claude.json`; `customApiKeyResponses` is its per-key approval ledger. Both
/// are account-scoped, so a sync must never carry one profile's into another.
#[test]
fn the_login_managed_api_key_never_propagates() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    write_json(
        &a,
        &json!({
            "numStartups": 2,
            "primaryApiKey": "sk-ant-AAAA-a-account-key",
            "customApiKeyResponses": {"approved": ["hash-a"], "rejected": []}
        }),
    );
    // b holds its own key, and would otherwise inherit a's.
    write_json(
        &b,
        &json!({"numStartups": 1, "primaryApiKey": "sk-ant-BBBB-b-account-key"}),
    );
    set_mtime(&a, t(10));
    set_mtime(&b, t(5));

    sync_paths(&[a, b.clone()]).expect("sync");

    let bj = read_json(&b);
    assert_eq!(bj["numStartups"], json!(2), "shared field still propagates");
    assert_eq!(
        bj["primaryApiKey"],
        json!("sk-ant-BBBB-b-account-key"),
        "one account's raw /login key must never reach another profile"
    );
    assert!(
        bj.get("customApiKeyResponses").is_none(),
        "an absent per-profile key must not be injected from the winner: {bj}"
    );
}

#[test]
fn shared_key_absent_in_winner_is_removed_from_target() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    write_json(&a, &json!({"numStartups": 2}));
    write_json(
        &b,
        &json!({"numStartups": 1, "staleFeature": true, "oauthAccount": {"e": "b"}}),
    );
    set_mtime(&a, t(10));
    set_mtime(&b, t(5));

    sync_paths(&[a, b.clone()]).expect("sync");

    let bj = read_json(&b);
    assert_eq!(bj["numStartups"], json!(2));
    assert!(
        bj.get("staleFeature").is_none(),
        "a shared key the winner dropped must be removed from the target"
    );
    assert_eq!(bj["oauthAccount"]["e"], json!("b"));
}

#[test]
fn unparseable_file_is_skipped() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    let c = tmp.path().join("c.json");
    write_json(&a, &json!({"numStartups": 2, "oauthAccount": {"e": "a"}}));
    fs::write(&b, b"{ partial truncated write").expect("write garbage");
    write_json(&c, &json!({"numStartups": 1, "oauthAccount": {"e": "c"}}));
    set_mtime(&a, t(10));
    set_mtime(&b, t(20)); // newest by mtime but unparseable → skipped
    set_mtime(&c, t(5));

    let before_b = fs::read(&b).expect("read b");
    sync_paths(&[a, b.clone(), c.clone()]).expect("sync");

    // mid-write file never read from nor written to
    assert_eq!(fs::read(&b).expect("read b"), before_b);
    // `a` is the newest parseable member → `c` takes its shared field
    let cj = read_json(&c);
    assert_eq!(cj["numStartups"], json!(2));
    assert_eq!(cj["oauthAccount"]["e"], json!("c"));
}

#[test]
fn newest_mtime_wins_regardless_of_argument_order() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    write_json(&a, &json!({"v": "old"}));
    write_json(&b, &json!({"v": "new"}));
    set_mtime(&a, t(5));
    set_mtime(&b, t(10)); // b newer even though `a` is listed first

    sync_paths(&[a.clone(), b.clone()]).expect("sync");

    assert_eq!(read_json(&a)["v"], json!("new"));
    assert_eq!(read_json(&b)["v"], json!("new"));
}

#[test]
fn converged_target_is_not_rewritten() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    write_json(&a, &json!({"numStartups": 5, "oauthAccount": {"e": "a"}}));
    write_json(&b, &json!({"numStartups": 5, "oauthAccount": {"e": "b"}}));
    set_mtime(&a, t(10));
    set_mtime(&b, t(5));
    let before = fs::metadata(&b).unwrap().modified().unwrap();

    sync_paths(&[a, b.clone()]).expect("sync");

    assert_eq!(
        before,
        fs::metadata(&b).unwrap().modified().unwrap(),
        "a target already converged on shared fields must not be rewritten"
    );
}

#[test]
fn single_file_is_noop() {
    let _home = HomeSandbox::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a.json");
    write_json(&a, &json!({"numStartups": 1}));
    let before = fs::read(&a).expect("read");
    sync_paths(std::slice::from_ref(&a)).expect("sync");
    assert_eq!(fs::read(&a).expect("read"), before);
}

// ── strip_home_oauth_account (issue #17 switch-time delete) ───────────────

#[test]
fn strip_home_oauth_account_removes_key_and_preserves_the_rest() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    write_json(
        &path,
        &json!({
            "oauthAccount": {"emailAddress": "stale@x"},
            "numStartups": 3,
            "mcpServers": {"clauth": {"command": "clauth"}},
        }),
    );

    strip_home_oauth_account().expect("strip");

    let after = read_json(&path);
    assert!(
        after.get("oauthAccount").is_none(),
        "stale identity block must be gone"
    );
    assert_eq!(after["numStartups"], json!(3));
    assert_eq!(
        after["mcpServers"],
        json!({"clauth": {"command": "clauth"}})
    );
}

#[test]
fn strip_home_oauth_account_no_op_when_key_absent() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    write_json(&path, &json!({"numStartups": 3}));
    let before_bytes = fs::read(&path).expect("read");
    set_mtime(&path, t(1));
    let before_mtime = fs::metadata(&path).unwrap().modified().unwrap();

    strip_home_oauth_account().expect("strip");

    assert_eq!(
        fs::read(&path).expect("read"),
        before_bytes,
        "a file with no oauthAccount must not be rewritten"
    );
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        before_mtime,
        "an untouched file must not bump mtime (would make home win the next sync)"
    );
}

#[test]
fn strip_home_oauth_account_skips_unparseable_file() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    fs::write(&path, b"{ mid write, not valid json").expect("write garbage");
    let before = fs::read(&path).expect("read");

    strip_home_oauth_account().expect("strip must not fail on a CC mid-write file");

    assert_eq!(
        fs::read(&path).expect("read"),
        before,
        "an unparseable file must never be clobbered"
    );
}

#[test]
fn strip_home_oauth_account_skips_valid_json_that_is_not_an_object() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    fs::write(&path, b"[]").expect("write non-object json");
    let before = fs::read(&path).expect("read");

    strip_home_oauth_account().expect("strip must not fail on a non-object document");

    assert_eq!(
        fs::read(&path).expect("read"),
        before,
        "a parses-but-not-an-object file must be left untouched"
    );
}

#[test]
fn strip_home_oauth_account_skips_missing_file() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");

    strip_home_oauth_account().expect("strip must not fail when there is nothing to strip");

    assert!(!path.exists(), "a missing file must never be created");
}

/// Regression for a break that compiles clean: every session now runs out of its
/// own `runtime-<sid>/`, so a discovery hardcoded to `<profile>/runtime` finds
/// nothing and cross-profile `.claude.json` reconciliation silently dies for
/// every live session. Isolated copies stay excluded, as they were.
#[test]
fn known_paths_reach_per_session_copies_and_still_exclude_isolated() {
    let home = HomeSandbox::new();
    let global = home.home().join(".claude.json");
    let profiles = home.home().join(".clauth/profiles");
    let legacy = profiles.join("p1/runtime/.claude.json");
    let session = profiles.join("p1/runtime-4242-0/.claude.json");
    let sibling = profiles.join("p2/runtime-4242-1/.claude.json");
    let isolated = profiles.join("p1/runtime-isolated-4242-2/.claude.json");
    for path in [&global, &legacy, &session, &sibling, &isolated] {
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir");
        write_json(path, &json!({}));
    }

    let paths = known_paths().expect("known paths");

    assert!(
        paths.contains(&global),
        "the global file is always a member"
    );
    assert!(
        paths.contains(&session),
        "a live session's own runtime-<sid> copy must be a sync member"
    );
    assert!(
        paths.contains(&sibling),
        "another profile's session copy must be a member too"
    );
    assert!(
        paths.contains(&legacy),
        "a legacy unsuffixed runtime/ copy must stay a member"
    );
    assert!(
        !paths.contains(&isolated),
        "an isolated per-session copy must not be a sync member"
    );
    assert_eq!(paths.len(), 4, "no member beyond those four: {paths:#?}");
}

// ── Claude Code's first-run gate ─────────────────────────────────────────────
//
// A replica gets working credentials from `clauth proxy` and is never meant to
// log in. Claude Code still gated its first run on `hasCompletedOnboarding`
// rather than on whether it could authenticate, so a fresh replica asked for a
// login it did not need — with a token that demonstrably worked. These pin the
// seed that closes that, and the two ways it could do more harm than good:
// clobbering a file Claude Code is mid-write on, and touching a file that
// needed no change.

/// The reported case: a machine where Claude Code has never run. The file has
/// to be CREATED, because the flag is read on the first start — a seed that
/// waited for Claude Code to write the file would always be one run too late.
#[test]
fn a_machine_that_has_never_run_claude_code_is_given_the_flag() {
    use std::os::unix::fs::PermissionsExt;

    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    assert!(
        !path.exists(),
        "precondition: Claude Code has never run here"
    );

    seed_home_onboarding().expect("seed");

    assert_eq!(
        read_json(&path),
        json!({"hasCompletedOnboarding": true}),
        "the seeded file carries the flag and nothing else; Claude Code fills in the rest"
    );
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "owner-only for the window before Claude Code's first write, got {mode:#o}"
    );
}

/// Claude Code owns this file. Seeding one key must not cost any of the others,
/// nor reorder them — `serde_json`'s `preserve_order` is what keeps a rewritten
/// file recognisable, and a diff of the whole file is not a seed.
#[test]
fn seeding_keeps_every_other_key_and_its_order() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    write_json(
        &path,
        &json!({
            "numStartups": 7,
            "userID": "abc",
            "oauthAccount": {"emailAddress": "claude@example.org"},
            "projects": {"/tmp/x": {"allowedTools": []}},
        }),
    );

    seed_home_onboarding().expect("seed");

    let after = read_json(&path);
    assert_eq!(after["numStartups"], json!(7));
    assert_eq!(after["userID"], json!("abc"));
    assert_eq!(
        after["oauthAccount"]["emailAddress"],
        json!("claude@example.org")
    );
    assert_eq!(after["projects"]["/tmp/x"]["allowedTools"], json!([]));
    assert_eq!(after["hasCompletedOnboarding"], json!(true));

    let keys: Vec<&String> = after.as_object().expect("an object").keys().collect();
    assert_eq!(
        keys,
        vec![
            "numStartups",
            "userID",
            "oauthAccount",
            "projects",
            "hasCompletedOnboarding"
        ],
        "existing keys keep their order and the flag lands after them"
    );
}

/// The regression that matters. `sync_once` resolves by newest mtime, so a seed
/// that rewrote an already-correct file would make home win every tick and
/// stomp each runtime copy's own fields — on a replica that is every pull,
/// forever.
#[test]
fn an_already_onboarded_file_is_not_rewritten_at_all() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    write_json(
        &path,
        &json!({"hasCompletedOnboarding": true, "numStartups": 3}),
    );
    set_mtime(&path, t(5));

    seed_home_onboarding().expect("seed");

    let mtime = fs::metadata(&path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    assert_eq!(
        mtime,
        t(5),
        "an already-onboarded file must not be touched; a bumped mtime hands \
         `sync_once` a false winner"
    );
}

/// Claude Code rewrites this file in place, so a read can land mid-write. The
/// half-written bytes are Claude Code's, not ours to replace.
#[test]
fn a_claude_json_caught_mid_write_is_left_alone() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    fs::write(&path, b"{ \"numStartups\": 3, \"hasComp").expect("write");

    seed_home_onboarding().expect("seed is best-effort, never an error");

    assert_eq!(
        fs::read(&path).expect("read"),
        b"{ \"numStartups\": 3, \"hasComp",
        "a file that does not parse is left byte-for-byte alone"
    );
}

/// Valid JSON that is not an object has no place to put the flag. Replacing it
/// wholesale would be inventing state rather than seeding it.
#[test]
fn a_claude_json_that_is_not_an_object_is_left_alone() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    write_json(&path, &json!([1, 2, 3]));

    seed_home_onboarding().expect("seed");

    assert_eq!(read_json(&path), json!([1, 2, 3]));
}

/// `false` is what a half-finished onboarding leaves behind, and it is exactly
/// the state that keeps prompting. On a replica the login it asks for is one
/// this host cannot perform, so the flag is corrected rather than respected.
#[test]
fn a_half_finished_onboarding_is_completed() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    write_json(
        &path,
        &json!({"hasCompletedOnboarding": false, "numStartups": 1}),
    );

    seed_home_onboarding().expect("seed");

    assert_eq!(read_json(&path)["hasCompletedOnboarding"], json!(true));
    assert_eq!(read_json(&path)["numStartups"], json!(1));
}

/// The two writers of this file run in the same apply, one after the other. The
/// strip must take the identity block and leave the flag, or a replica would
/// re-prompt on the first switch the origin makes.
#[test]
fn stripping_the_identity_block_leaves_the_onboarding_flag() {
    let home = HomeSandbox::new();
    let path = home.home().join(".claude.json");
    write_json(&path, &json!({"numStartups": 2}));

    seed_home_onboarding().expect("seed");
    // Claude Code boots and caches the identity it derived from the token.
    let mut obj = read_json(&path);
    obj["oauthAccount"] = json!({"accountUuid": "uuid-1"});
    write_json(&path, &obj);

    strip_home_oauth_account().expect("strip");

    let after = read_json(&path);
    assert!(
        after.get("oauthAccount").is_none(),
        "the stale identity goes"
    );
    assert_eq!(
        after["hasCompletedOnboarding"],
        json!(true),
        "the onboarding flag stays; losing it would re-prompt on the next switch"
    );
}
