//! Write a pulled snapshot into this host's `~/.clauth`.
//!
//! Everything here runs under one `with_state_lock`, so a TUI or a `clauth
//! start` reading the tree never sees half a mirror: either the previous
//! snapshot or this one.
//!
//! The proxy installs credentials directly rather than going through
//! `switch_profile_noninteractive`. That is deliberate. The origin already ran
//! the AUTH-1 gate before publishing, and a replica's job is to install what it
//! was handed, not to re-litigate it against a refresh endpoint it cannot reach
//! with a token it does not have.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::actions::validate_profile_name;
use crate::claude::{
    LinkState, apply_profile_to_claude_settings, classify_credentials_link,
    clear_claude_credentials, force_link_profile_credentials, install_source_path,
};
use crate::lock::with_state_lock;
use crate::logline::logline;
use crate::profile::SlotOps as _;
use crate::profile::{
    ProfileName, atomic_write_600, load_app_state, mkdir_700, profile_dir, profile_subpath,
    save_app_state,
};
use crate::profile_cache::{
    ACCOUNT_ID_CACHE_FILE, THIRD_PARTY_CACHE_FILE, USAGE_CACHE_FILE, write_profile_cache,
};

use super::wire::{MirrorBody, MirrorProfile};

/// What one apply changed, for the caller's log line.
#[derive(Debug, Default)]
pub(crate) struct Applied {
    /// The new manifest: profiles this proxy now owns on this host.
    pub(crate) mirrored: Vec<ProfileName>,
    pub(crate) written: Vec<ProfileName>,
    pub(crate) pruned: Vec<ProfileName>,
    pub(crate) active: Option<ProfileName>,
    pub(crate) relinked: bool,
}

impl Applied {
    pub(crate) fn is_quiet(&self) -> bool {
        self.written.is_empty() && self.pruned.is_empty() && !self.relinked
    }
}

/// Apply `body`, replacing what the previous pull left.
///
/// `previously_mirrored` is the manifest from `proxy.json`: the prune only ever
/// removes names it contains, so a profile that was always local to this host
/// survives an origin that has never heard of it.
pub(crate) fn apply(body: &MirrorBody, previously_mirrored: &[ProfileName]) -> Result<Applied> {
    // Validate EVERY remote name before any of it is joined into a path.
    // `profile_dir` joins the raw name, so this is the only thing between a
    // hostile or compromised origin and a write outside the profiles root. It
    // runs over the whole body first: a bad name anywhere aborts the snapshot
    // rather than applying the good half of it.
    let incoming: Vec<&ProfileName> = body.profiles.iter().map(|p| &p.name).collect();
    for name in &incoming {
        validate_profile_name(name, &[], None)
            .with_context(|| format!("the origin offered an unusable profile name {name:?}"))?;
    }

    with_state_lock(|held| {
        let mut state = load_app_state()?;
        let prev_active = state.active_profile.clone().into_inner();
        let mut applied = Applied::default();

        // The install source for the profile that is about to be active, read
        // BEFORE the writes. Comparing bytes (not just the name) is what makes
        // a rotation reach the live slot on macOS and Windows, where the link
        // is a Keychain item and a copy respectively and neither follows a
        // rewritten target the way a Unix symlink does.
        let next_active = body.active_profile.clone();
        let before = next_active.as_ref().and_then(read_install_source);
        // Read BEFORE the writes, like `finish_switch` reads them before
        // reassigning the active profile: these are the keys to REMOVE from
        // `~/.claude/settings.json`, so they have to be the outgoing profile's.
        let prev_env_keys: Vec<String> = prev_active
            .as_ref()
            .and_then(|n| crate::profile::load_profile(n).ok())
            .map(|p| p.env.keys().cloned().collect())
            .unwrap_or_default();

        for profile in &body.profiles {
            if write_profile(profile)? {
                applied.written.push(profile.name.clone());
            }
        }

        let (pruned, kept) = prune(&incoming, previously_mirrored)?;
        applied.pruned = pruned;

        merge_state(&mut state, body, &incoming, previously_mirrored, held);
        save_app_state(&state)?;

        let after = next_active.as_ref().and_then(read_install_source);
        let active_moved = prev_active != next_active;
        match next_active.as_ref() {
            Some(active) => {
                // The other half of a switch. `finish_switch` installs the
                // profile's env, model routing and `apiKeyHelper` into
                // `~/.claude/settings.json`, and a mirrored switch has to as
                // well: without it an api-key account cannot authenticate here
                // at all, model routing is silently ignored, and a stale
                // `ANTHROPIC_BASE_URL` left by a previous profile is never
                // cleared, which would route this host's requests somewhere the
                // origin is not.
                //
                // Gated on the account moving or its files changing rather than
                // run every pull: `settings_sync` resolves by newest mtime, so
                // an idle rewrite would make home win every tick and stomp a
                // runtime copy's own fields.
                let active_touched = applied.written.iter().any(|n| n == active);
                if active_moved || active_touched {
                    match crate::profile::load_profile(active) {
                        Ok(profile) => {
                            if let Err(e) =
                                apply_profile_to_claude_settings(&profile, &prev_env_keys)
                            {
                                logline!("clauth proxy: could not apply '{active}'s settings: {e}");
                            }
                        }
                        Err(e) => {
                            logline!("clauth proxy: could not load '{active}' to apply it: {e}")
                        }
                    }
                }
                // Whether the live slot already holds what a switch would
                // install. This is the condition that matters, not just "did the
                // account move": Claude Code rewrites
                // `~/.claude/.credentials.json` with unlink + write, so the
                // symlink clauth created becomes a REGULAR FILE, and from then
                // on rewriting the profile's `credentials.json` no longer
                // reaches the live slot at all. Without this the replica freezes
                // on whichever token it held when that happened and dies at its
                // expiry.
                //
                // `after.is_some()` is load-bearing, not a cheap guard. An
                // api-key account stores no credential file, so its live slot is
                // legitimately absent and stays absent however often it is
                // repaired: without this the branch would relink, log, and count
                // the tick as non-quiet on every pull, forever.
                let live_stale = after.is_some()
                    && !matches!(classify_credentials_link(active), Ok(LinkState::LinkedTo));
                if active_moved || before != after || live_stale {
                    // BEFORE the repoint, and the reason the proxy needs it at
                    // all: Claude Code stats the LINK'S TARGET at the head of
                    // every request and re-reads only when that mtime differs
                    // from the one it memoized. The store being switched to was
                    // usually written on an earlier pull, and `write_profile`
                    // deliberately does not rewrite bytes that already match, so
                    // its mtime can sit at exactly the value Claude Code is
                    // holding. The repoint then lands and the session keeps
                    // authenticating as the old account, with the symlink
                    // pointing at the right file and nothing reporting a
                    // problem. See `runtime::touch_credential_store`.
                    if let Ok(store) = install_source_path(active)
                        && store.exists()
                    {
                        let memoized = prev_active
                            .as_ref()
                            .and_then(|n| install_source_path(n).ok())
                            .and_then(|p| crate::runtime::file_mtime(&p));
                        if let Err(e) =
                            crate::runtime::touch_credential_store(active, &store, memoized)
                        {
                            logline!("clauth proxy: could not stamp '{active}'s store: {e}");
                        }
                    }
                    // FORCE, unlike every other caller. `link_profile_credentials`
                    // refuses to replace a live file that differs from the
                    // profile, because on a normal host that file may be an
                    // unresolved Claude Code re-login the operator still wants to
                    // capture. A replica has no such thing to lose: the origin
                    // owns every credential here, `clauth login` is refused, and
                    // the live file carries no refresh token the origin's copy
                    // lacks. Taking the refusal would mean a replica silently
                    // stops following the origin the first time Claude Code
                    // rewrites that file, which is the whole failure this
                    // branch exists to prevent.
                    match force_link_profile_credentials(active) {
                        Ok(()) => {
                            applied.relinked = true;
                            // The other half of a switch, and it is not cosmetic.
                            // `~/.claude.json` caches the account Claude Code
                            // last derived; a present-but-stale block never
                            // self-corrects, so a session keeps REPORTING the
                            // old account (`/status`) even once it is
                            // authenticating as the new one. `finish_switch`
                            // strips it for exactly this reason (issue #17), and
                            // a mirrored switch is no different.
                            if let Err(e) = crate::claude_json::strip_home_oauth_account() {
                                logline!(
                                    "clauth proxy: installed '{active}' but could not clear the \
                                     cached identity, so Claude Code may still name the previous \
                                     account: {e}"
                                );
                            }
                        }
                        Err(e) => logline!(
                            "clauth proxy: could not install '{active}' as the live login, so \
                             this host is still on the previous one: {e}"
                        ),
                    }
                }
            }
            // The origin parked every account (its chain ran out, or a spend
            // ceiling was reached). Following that is the whole contract: left
            // linked, this host would keep spending an account the origin
            // deliberately stopped using, and on the budget path that is a bill
            // the operator was told could not happen.
            //
            // Only on the transition, which is what `switch_off` does too --
            // clearing every tick would re-run the macOS Keychain delete for as
            // long as the origin stays parked.
            None if prev_active.is_some() => match clear_claude_credentials() {
                Ok(()) => {
                    applied.relinked = true;
                    let _ = crate::claude_json::strip_home_oauth_account();
                    logline!("clauth proxy: the origin has no active account; live login cleared");
                }
                Err(e) => logline!("clauth proxy: could not clear the live credentials: {e}"),
            },
            None => {}
        }

        // Claude Code's first-run gate, which nothing else on this host can
        // satisfy. A replica is handed a login it never typed, and without this
        // flag Claude Code asks for one anyway the first time it runs here --
        // on credentials that already work. Unconditional rather than folded
        // into the relink branch above: it is a property of the host, not of
        // this snapshot, and it rewrites nothing once the flag reads true.
        //
        // Best-effort like the settings and identity writes above. A replica
        // that mirrored its accounts correctly must not fail the whole apply
        // because of a convenience flag.
        if let Err(e) = crate::claude_json::seed_home_onboarding() {
            logline!("clauth proxy: could not record Claude Code's onboarding as complete: {e}");
        }

        applied.active = next_active;
        // Kept names stay in the manifest so a later tick can still remove them.
        // Dropping one here would turn the live-session guard from a deferral
        // into a permanent leak: the next pull would no longer recognise the
        // profile as this proxy's, and nothing would ever clean it up.
        applied.mirrored = incoming.iter().map(|n| (*n).clone()).chain(kept).collect();
        Ok(applied)
    })
}

/// The bytes a switch would install for `name`, or `None` when there are none.
fn read_install_source(name: &ProfileName) -> Option<Vec<u8>> {
    std::fs::read(install_source_path(name).ok()?).ok()
}

/// Write one account. Reports whether anything on disk actually changed, so a
/// steady-state tick can stay silent instead of logging every 60 seconds.
fn write_profile(profile: &MirrorProfile) -> Result<bool> {
    let dir = profile_dir(&profile.name)?;
    mkdir_700(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let mut changed = false;

    changed |= write_if_changed(
        &profile_subpath(&profile.name, "config.toml")?,
        profile.config_toml.as_bytes(),
    )?;

    // credentials.json BEFORE config.toml would matter for a rotation; here
    // neither is single-use, because the mirrored pair carries no refresh
    // token. Order is just the order a reader expects.
    changed |= write_json_if_changed(
        &profile_subpath(&profile.name, "credentials.json")?,
        profile.credentials.as_ref(),
    )?;
    changed |= write_json_if_changed(
        &profile_subpath(&profile.name, "session-token.json")?,
        profile.session_token.as_ref(),
    )?;

    // The caches are best-effort, exactly as they are for the poller that
    // normally writes them: a cache that fails to land costs a blank column,
    // never a failed sync.
    for (file, value) in [
        (ACCOUNT_ID_CACHE_FILE, profile.account_id.as_ref()),
        (USAGE_CACHE_FILE, profile.usage_cache.as_ref()),
        (THIRD_PARTY_CACHE_FILE, profile.third_party_cache.as_ref()),
    ] {
        if let Some(value) = value {
            write_profile_cache(&profile.name, file, value);
        }
    }

    Ok(changed)
}

/// `atomic_write_600`, skipped when the bytes already match.
///
/// Skipping is not only an optimisation. Rewriting `credentials.json` with
/// identical bytes still moves its mtime, and Claude Code re-reads its
/// credentials when that value changes, so an unconditional write would poke
/// every running session once per tick for nothing.
fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool> {
    if std::fs::read(path).is_ok_and(|existing| existing == bytes) {
        return Ok(false);
    }
    atomic_write_600(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(true)
}

/// The same, for an optional JSON document. `None` removes the file, so a
/// profile that loses its session token on the origin loses it here too.
fn write_json_if_changed<T: serde::Serialize>(path: &Path, value: Option<&T>) -> Result<bool> {
    match value {
        Some(value) => {
            let bytes = serde_json::to_vec_pretty(value)?;
            write_if_changed(path, &bytes)
        }
        None if path.exists() => {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Remove profiles this proxy created that the origin no longer has.
///
/// Bounded by the manifest on both sides: a name is only removed if the last
/// pull put it here. A live session pins its profile — pulling an account out
/// from under a running `claude` would sign it out mid-task, and the origin
/// dropping an account is never urgent enough to justify that.
///
/// Returns `(removed, deferred)`. The deferred names go back into the manifest,
/// so the guard postpones a removal rather than cancelling it.
fn prune(
    incoming: &[&ProfileName],
    previously_mirrored: &[ProfileName],
) -> Result<(Vec<ProfileName>, Vec<ProfileName>)> {
    let keep: HashSet<&ProfileName> = incoming.iter().copied().collect();
    let mut pruned = Vec::new();
    let mut deferred = Vec::new();
    for name in previously_mirrored {
        if keep.contains(name) {
            continue;
        }
        if crate::runtime::has_live_session(name) {
            logline!("clauth proxy: '{name}' is gone from the origin but has a live session; kept");
            deferred.push(name.clone());
            continue;
        }
        let dir = profile_dir(name)?;
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("failed to remove {}", dir.display()))?;
        }
        pruned.push(name.clone());
    }
    Ok((pruned, deferred))
}

/// Take the origin's account topology; leave every local preference alone.
///
/// The origin owns the roster, the chain, the quarantine list and which account
/// is active. It does not own this host's theme, clock format, reset display or
/// switch thresholds — those are the replica operator's, and a mirror that
/// overwrote them would be changing settings nobody asked it to touch. They are
/// also policy for decisions a replica never makes.
fn merge_state(
    state: &mut crate::profile::AppState,
    body: &MirrorBody,
    incoming: &[&ProfileName],
    previously_mirrored: &[ProfileName],
    held: &crate::lock::StateLockHeld,
) {
    // Local-only accounts keep their place: anything here that the origin does
    // not list and this proxy did not create was put here by the operator.
    let from_origin: HashSet<&ProfileName> = incoming.iter().copied().collect();
    let ours: HashSet<&ProfileName> = previously_mirrored.iter().collect();
    let local_only: Vec<ProfileName> = state
        .profiles
        .iter()
        .filter(|n| !from_origin.contains(n) && !ours.contains(n))
        .cloned()
        .collect();

    state.profiles = incoming
        .iter()
        .map(|n| (*n).clone())
        .chain(local_only)
        .collect();

    let known: HashSet<&ProfileName> = state.profiles.iter().collect();
    state.fallback_chain = body
        .state
        .fallback_chain
        .iter()
        .filter(|n| known.contains(n))
        .map(|n| (*n).clone())
        .collect();
    state.auth_broken = body
        .state
        .auth_broken
        .iter()
        .filter(|n| known.contains(n))
        .map(|n| (*n).clone())
        .collect();
    // Through `set_active`, not the field: upstream gated the active marker
    // behind the state-flock witness so a write that is not under the lock is a
    // type error rather than a race nobody notices.
    state.set_active(
        body.active_profile
            .as_ref()
            .filter(|n| known.contains(*n))
            .cloned(),
        held,
    );
}

#[cfg(test)]
#[path = "../../tests/inline/proxy_apply.rs"]
mod tests;
