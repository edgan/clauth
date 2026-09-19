//! The `/api/v1/mirror` body, defined once and used by both ends.
//!
//! The origin builds one of these and the replica parses it, from the same
//! types, so the two sides cannot drift into disagreeing about a field. The
//! caches ride as opaque `serde_json::Value`: the mirror relays whatever the
//! cache schema is that day rather than re-declaring it, so a cache gaining a
//! field needs no change here.
//!
//! [`strip_refresh_token`] is the load-bearing line of the whole feature. Every
//! credential leaving this host goes through it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claude::has_session_token;
use crate::lock::with_state_lock;
use crate::profile::{
    ClaudeCredentials, ProfileName, SlotOps as _, load_app_state, profile_subpath,
};
use crate::profile_cache::{
    ACCOUNT_ID_CACHE_FILE, THIRD_PARTY_CACHE_FILE, USAGE_CACHE_FILE, load_profile_cache,
};
use crate::usage::{epoch_secs_to_iso, now_ms};

/// Bumped only on a breaking change to the body's shape. A replica refuses a
/// body newer than it knows rather than half-applying one.
pub(crate) const MIRROR_SCHEMA: u64 = 1;

/// The account-topology subset of `AppState`, and nothing else.
///
/// Everything else in `AppState` is either a display preference (`theme`,
/// `clock_format`, `show_estimates`) or a switch policy the replica never
/// evaluates. Mirroring those would clobber the replica operator's own settings
/// to no purpose, so the wire format cannot carry them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct MirrorState {
    pub(crate) profiles: Vec<ProfileName>,
    #[serde(default)]
    pub(crate) fallback_chain: Vec<ProfileName>,
    #[serde(default)]
    pub(crate) auth_broken: Vec<ProfileName>,
}

/// One account, as it crosses the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MirrorProfile {
    pub(crate) name: ProfileName,
    /// `config.toml` verbatim, so the replica reproduces the origin's rendering
    /// instead of round-tripping through a struct that might normalize it.
    pub(crate) config_toml: String,
    /// The rotating pair with its refresh token removed. See
    /// [`strip_refresh_token`].
    pub(crate) credentials: Option<ClaudeCredentials>,
    /// A `claude setup-token` mint, when the profile has one. Carries no
    /// refresh token by definition, so it crosses unchanged.
    #[serde(default)]
    pub(crate) session_token: Option<ClaudeCredentials>,
    #[serde(default)]
    pub(crate) account_id: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) usage_cache: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) third_party_cache: Option<serde_json::Value>,
}

/// One consistent snapshot of the origin's accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MirrorBody {
    pub(crate) schema: u64,
    pub(crate) generated_at: String,
    pub(crate) active_profile: Option<ProfileName>,
    pub(crate) state: MirrorState,
    pub(crate) profiles: Vec<MirrorProfile>,
}

impl MirrorBody {
    /// A digest over the CONTENT, deliberately excluding `generated_at`.
    ///
    /// Including the timestamp would change the tag on every request and make
    /// the whole conditional-GET path dead weight. What a replica wants to know
    /// is whether the accounts moved, not whether time passed.
    pub(crate) fn etag(&self) -> String {
        let content = (&self.active_profile, &self.state, &self.profiles);
        // On the (unreachable) serialization failure, digest the TIMESTAMP
        // instead. A constant fallback would hash every body to the same value,
        // so a replica would read 304 forever and sit on the access token it
        // first pulled until its sessions died. Missing is the safe direction.
        let bytes =
            serde_json::to_vec(&content).unwrap_or_else(|_| self.generated_at.as_bytes().to_vec());
        format!(
            "\"{}\"",
            hex::encode(<[u8; 32]>::from(Sha256::digest(bytes)))
        )
    }
}

impl MirrorBody {
    /// Read one consistent snapshot of this host's accounts off disk.
    ///
    /// Everything comes from inside a single `with_state_lock`, so a mirror can
    /// never straddle a switch and hand a replica an active profile whose
    /// credentials it did not also receive.
    ///
    /// It reads the files rather than serializing the daemon's in-memory
    /// `AppConfig` on purpose: `config.toml` crosses verbatim, so the replica
    /// reproduces the origin's own rendering instead of a round trip through a
    /// struct that would normalize comments and key order away.
    pub(crate) fn from_disk() -> Result<Self> {
        with_state_lock(|_held| {
            let state = load_app_state()?;
            let profiles = state
                .profiles
                .iter()
                .map(MirrorProfile::from_disk)
                .collect::<Result<Vec<_>>>()?;
            Ok(Self {
                schema: MIRROR_SCHEMA,
                generated_at: epoch_secs_to_iso((now_ms() / 1000) as i64),
                active_profile: state.active_profile.clone().into_inner(),
                state: MirrorState {
                    profiles: state.profiles.to_vec(),
                    fallback_chain: state.fallback_chain.to_vec(),
                    auth_broken: state.auth_broken.to_vec(),
                },
                profiles,
            })
        })
    }
}

impl MirrorProfile {
    /// One account, with every credential put through
    /// [`strip_refresh_token`] on its way out.
    ///
    /// Called only from [`MirrorBody::from_disk`], which already holds the
    /// state lock.
    fn from_disk(name: &ProfileName) -> Result<Self> {
        // Absent means absent; anything else is an error rather than an absent.
        // The distinction matters because the replica MIRRORS the answer: a
        // credential that reads as `None` because the file could not be opened
        // would delete the replica's own last-good copy, and a `config.toml`
        // that reads as empty would wipe that account's settings there. Failing
        // the pull leaves the replica on what it already has, which is right.
        let read_optional = |file: &str| -> Result<Option<String>> {
            let path = profile_subpath(name, file)?;
            match std::fs::read_to_string(&path) {
                Ok(body) => Ok(Some(body)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
            }
        };
        let read_creds = |file: &str| -> Result<Option<ClaudeCredentials>> {
            let Some(body) = read_optional(file)? else {
                return Ok(None);
            };
            serde_json::from_str(&body)
                .map(Some)
                .with_context(|| format!("failed to parse {name}/{file}"))
        };

        // The sidecar crosses ONLY when it is genuinely long-lived. A sidecar
        // holding a rotating pair is disengaged on the origin too
        // (`install_source_path` ignores it), so mirroring it would hand the
        // replica a login this host is not itself using -- and one that dies in
        // hours with nothing on that side to refresh it. The strip still runs
        // over it: a long-lived mint has no refresh token by definition, so
        // this only ever matters if that definition is wrong.
        let session_token = match has_session_token(name) {
            true => read_creds("session-token.json")?
                .as_ref()
                .map(strip_refresh_token),
            false => None,
        };

        Ok(Self {
            name: name.clone(),
            // A profile with no config.toml is legitimate (`load_profile` reads
            // that as the default set), so absent stays empty here.
            config_toml: read_optional("config.toml")?.unwrap_or_default(),
            credentials: read_creds("credentials.json")?
                .as_ref()
                .map(strip_refresh_token),
            session_token,
            account_id: load_profile_cache(name, ACCOUNT_ID_CACHE_FILE),
            usage_cache: load_profile_cache(name, USAGE_CACHE_FILE),
            third_party_cache: load_profile_cache(name, THIRD_PARTY_CACHE_FILE),
        })
    }
}

/// Every file the mirror body is built from, stat'd rather than read.
///
/// The long-poll's gate. Recomputing the body to answer "did anything move?"
/// would take the state lock and re-read every credential several times a
/// second per connected replica; this is a readdir plus a handful of stats, no
/// locks, no secrets. It can move when the CONTENT did not (an identical cache
/// rewritten by the poller bumps an mtime), which costs one wasted body build
/// that the etag comparison then discards. It cannot fail to move when the
/// content did, which is the direction that matters.
pub(crate) fn mirror_fingerprint() -> Vec<(String, Option<std::time::SystemTime>)> {
    let mut out = Vec::new();
    let Ok(dir) = crate::profile::clauth_dir() else {
        return out;
    };
    let mtime = |p: &std::path::Path| std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
    out.push((
        "profiles.toml".to_string(),
        mtime(&dir.join("profiles.toml")),
    ));

    let root = dir.join("profiles");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return out;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        for file in [
            "config.toml",
            "credentials.json",
            "session-token.json",
            ACCOUNT_ID_CACHE_FILE,
            USAGE_CACHE_FILE,
            THIRD_PARTY_CACHE_FILE,
        ] {
            out.push((format!("{name}/{file}"), mtime(&entry.path().join(file))));
        }
    }
    // readdir order is not stable, and this value is only ever compared with
    // itself a moment later.
    out.sort();
    out
}

/// Remove the refresh token, returning the credential a replica may hold.
///
/// This is the whole safety argument of `clauth proxy`, so it is one function
/// with one caller-visible job rather than a field someone remembers to clear.
///
/// Anthropic's refresh chain is single-use: whoever spends a refresh token
/// revokes the copy every other holder has. Two machines refreshing one chain
/// is the failure this codebase already carries scars from (see
/// `crate::claude`'s CLA-SPLIT notes on the 2026-07-16..18 revocations), and
/// clauth answers the `invalid_grant` its loser receives with a local
/// quarantine that only a re-login lifts. A replica that never receives a
/// refresh token cannot enter that race, whatever it or Claude Code decides to
/// do. The access token it does receive expires in hours and is replaced by the
/// next pull.
pub(crate) fn strip_refresh_token(creds: &ClaudeCredentials) -> ClaudeCredentials {
    let mut out = creds.clone();
    if let Some(oauth) = out.claude_ai_oauth.as_mut() {
        oauth.refresh_token = None;
    }
    out
}

#[cfg(test)]
#[path = "../../tests/inline/proxy_wire.rs"]
mod tests;
