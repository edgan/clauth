//! Cross-profile `.claude.json` synchronizer.
//!
//! Claude Code keeps one large config file — `~/.claude.json` for normal use —
//! holding user-global state (`projects`, `mcpServers`, `tips`, `userID`)
//! alongside an account-specific `oauthAccount` block and a few billing/usage
//! caches. `clauth start <profile>` runs Claude Code against a per-profile
//! runtime tree with its OWN `.claude.json`, because a single shared file leaks
//! one account's identity into another: Claude Code trusts the cached
//! `oauthAccount` and does not re-derive it from the loaded token on a normal
//! startup (its bootstrap merge keeps the cached identity when the server
//! reports a different account).
//!
//! This module keeps every clauth-managed `.claude.json` (the global file plus
//! each profile runtime's copy) in sync EXCEPT for [`PER_PROFILE_FIELDS`], which
//! each file keeps as its own. Sync is "latest write wins" at file granularity:
//! each tick the newest parseable file is the source for the shared fields,
//! overlaid onto every other file while preserving that file's per-profile
//! fields. Atomic writes plus write-only-on-change make it convergent and safe
//! against Claude Code's concurrent in-place writes — a file caught mid-write
//! fails to parse and is simply skipped until the next tick. The merge itself
//! lives in [`crate::jsonsync`], shared with the `settings.json` reconciler.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::jsonsync::{KeyPath, KeyRule};
use crate::profile::{AccountId, atomic_write, atomic_write_600, home_dir};

/// Account-specific keys that must never propagate between profiles.
const PER_PROFILE_FIELDS: &[&str] = &[
    "oauthAccount",
    "overageCreditGrantCache",
    "passesEligibilityCache",
    "passesLastSeenRemaining",
    "cachedExtraUsageDisabledReason",
    // Account/org-scoped model caches Claude Code writes into `.claude.json`.
    // Syncing them would bleed one account's model access, org default, and
    // per-model cost/option tables into every other account. Each profile
    // re-fetches its own on first boot, so per-profile is lossless.
    "orgModelDefaultCache",
    "modelAccessCache",
    "additionalModelCostsCache",
    "additionalModelOptionsCache",
    // `/login`-managed API key and the per-key approval ledger. `primaryApiKey`
    // is a RAW KEY: Claude Code writes it into this file (verified on 2.1.215 —
    // the same accessor that reads `numStartups` and `oauthAccount`) and reads
    // it back as an auth source labelled "/login managed key". Propagating it
    // would hand one account's key to every other profile — the `.claude.json`
    // twin of the `apiKeyHelper` leak the settings syncer blocks.
    // `customApiKeyResponses` holds the approved/rejected hashes of those keys,
    // so it is scoped to the same account.
    "primaryApiKey",
    "customApiKeyResponses",
];

/// Newest mtime from the last [`sync_once`] that did work; the key for
/// [`crate::jsonsync::run_with_cache`]'s fast path.
static LAST_SYNCED: Mutex<Option<SystemTime>> = Mutex::new(None);

/// Every `.claude.json` clauth reconciles: the global file plus each SHARED
/// per-session runtime copy, via [`crate::jsonsync::runtime_files_under`].
fn known_paths() -> Result<Vec<PathBuf>> {
    Ok(crate::jsonsync::runtime_files_under(
        &home_dir()?,
        ".claude.json",
    ))
}

/// Reconcile all known `.claude.json` files once, behind the `LAST_SYNCED`
/// mtime fast path in [`crate::jsonsync::run_with_cache`].
pub(crate) fn sync_once() -> Result<()> {
    let paths = known_paths()?;
    crate::jsonsync::run_with_cache(&LAST_SYNCED, &paths, || {
        sync_paths(&paths)?;
        Ok(true)
    })
}

/// Reconcile the given `.claude.json` copies. Every field is shared except
/// [`PER_PROFILE_FIELDS`], which is a flat top-level set — no `env`-style nested
/// rule, unlike the `settings.json` reconciler.
fn sync_paths(paths: &[PathBuf]) -> Result<()> {
    let operator_file = home_dir().ok().map(|h| h.join(".claude.json"));
    crate::jsonsync::sync_paths(paths, operator_file.as_deref(), |path| match path {
        KeyPath::Top(key) if PER_PROFILE_FIELDS.contains(&key) => KeyRule::PerProfile,
        _ => KeyRule::Shared,
    })
}

/// CC's cached account uuid from `~/.claude.json`'s `oauthAccount.accountUuid`,
/// or `None` when the file, block, or value is absent/blank/unparseable.
/// Read-then-parse with the same discipline as [`strip_home_oauth_account`]: a
/// missing file is never created and a file caught mid-write by CC is left
/// untouched rather than clobbered. CC trusts this cached block and does not
/// re-derive it from a swapped credentials file — so a hit is "CC's last booted
/// identity", not fresh proof of the live token's account.
pub(crate) fn home_oauth_account_uuid() -> Option<AccountId> {
    let path = home_dir().ok()?.join(".claude.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return None; // missing — never create
    };
    let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(&bytes) else {
        return None; // unparseable (CC mid-write) — never clobber
    };
    obj.get("oauthAccount")
        .and_then(|a| a.get("accountUuid"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(AccountId::from)
}

/// Delete the stale `oauthAccount` identity block from the home
/// `~/.claude.json` on profile switch (issue #17). Claude Code trusts a
/// cached identity block and does not re-derive it from a relinked
/// credentials file on a normal startup; dropping the block instead lets it
/// self-heal — probed on CC 2.1.201: an
/// absent block re-derives the correct identity from the token within
/// seconds, a present-but-wrong one never self-corrects.
///
/// Read-then-parse first: a missing file is left uncreated, and a file that
/// fails to parse (CC mid-write) is left untouched rather than clobbered. A
/// write only happens when the key is actually present — an already-clean
/// file is never touched, because [`sync_once`] picks the newest-mtime member
/// as the sync winner; a pointless touch here would make home win the next
/// tick and stomp a runtime copy's own fields.
pub(crate) fn strip_home_oauth_account() -> Result<()> {
    let path = home_dir()?.join(".claude.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(()); // missing — never create
    };
    let Ok(Value::Object(mut obj)) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(()); // unparseable (CC mid-write) — never clobber
    };
    if obj.remove("oauthAccount").is_none() {
        return Ok(()); // already clean — avoid a pointless mtime bump
    }
    let bytes = serde_json::to_vec_pretty(&Value::Object(obj))
        .context("failed to serialize .claude.json after stripping oauthAccount")?;
    atomic_write(&path, &bytes).with_context(|| format!("failed to write {}", path.display()))
}

/// Record that Claude Code's first-run onboarding is done, so a replica can
/// actually start it.
///
/// A replica is handed a working login it never typed: `clauth login` is
/// refused there, and the mirrored pair carries no refresh token to log in
/// WITH. But Claude Code gates its first run on `hasCompletedOnboarding` in
/// `~/.claude.json`, not on whether it can authenticate — so on a machine that
/// has never run it, it asks for a login it does not need. Observed on a fresh
/// replica 2026-09-04: `oauthAccount` was populated from a SUCCESSFUL profile
/// fetch in the same second as `firstStartTime`, and it still prompted. Nothing
/// else in clauth writes this key, so every new replica would hit it.
///
/// Same read-then-parse discipline as [`strip_home_oauth_account`], with one
/// deliberate difference: this CREATES the file when it is absent, where the
/// strip never would. It has to. The flag is read on Claude Code's FIRST start,
/// so a seed that waited for Claude Code to write the file would always be one
/// run too late — which is the failure this exists to prevent. The created file
/// carries nothing but the flag; Claude Code's own bootstrap fills in the rest,
/// the way it already tolerates a file with no `oauthAccount`.
///
/// A file that already reads `true` is NOT rewritten, and that is load-bearing
/// rather than an optimisation: [`sync_once`] resolves by newest mtime, so a
/// touch on every pull would make home win every tick and stomp each runtime
/// copy's own fields — the same trap the strip documents.
///
/// The flag is not in [`PER_PROFILE_FIELDS`], so once it is here [`sync_once`]
/// carries it to the shared runtime copies and `runtime::seed_claude_json`
/// copies it into new ones: `clauth start` on a replica stops prompting too.
pub(crate) fn seed_home_onboarding() -> Result<()> {
    const FLAG: &str = "hasCompletedOnboarding";

    let path = home_dir()?.join(".claude.json");
    let Ok(bytes) = std::fs::read(&path) else {
        // Absent — create, unlike every other reader of this file. Owner-only
        // on the way in, matching `runtime::seed_claude_json`: Claude Code owns
        // the mode from its first write onward, so this only decides the window
        // before that.
        let mut obj = serde_json::Map::new();
        obj.insert(FLAG.to_string(), Value::Bool(true));
        let seeded = serde_json::to_vec_pretty(&Value::Object(obj))
            .context("failed to serialize a seeded .claude.json")?;
        return atomic_write_600(&path, &seeded)
            .with_context(|| format!("failed to write {}", path.display()));
    };
    let Ok(Value::Object(mut obj)) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(()); // unparseable (CC mid-write) or not an object — never clobber
    };
    if obj.get(FLAG) == Some(&Value::Bool(true)) {
        return Ok(()); // already onboarded — avoid a pointless mtime bump
    }
    // Absent, or the `false` a half-finished onboarding leaves behind. Either
    // way the login it would ask for is one this host cannot perform.
    obj.insert(FLAG.to_string(), Value::Bool(true));
    let bytes = serde_json::to_vec_pretty(&Value::Object(obj))
        .context("failed to serialize .claude.json after seeding the onboarding flag")?;
    atomic_write(&path, &bytes).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
#[path = "../tests/inline/claude_json.rs"]
mod tests;
