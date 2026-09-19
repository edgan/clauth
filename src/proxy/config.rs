//! `~/.clauth/proxy.json` — the origin, its bearer token, and the follow cadence.
//!
//! Peer of `tls.json` and `auth_token.json` in `~/.clauth`, written 0600 like
//! every other secret in the tree. It carries a bearer token, which is why it
//! is a file with modes rather than a line in `profiles.toml`.
//!
//! **Its presence is what makes this host a replica.** One file, one meaning:
//! while it exists the background refresher stays down and the mutating
//! commands refuse, and `clauth proxy --forget` removes it to re-arm the host.
//! That check is deliberately existence, not a successful parse — a corrupt
//! file must not re-arm a refresher behind the operator's back.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::cli::ProxyArgs;
use crate::profile::{ProfileName, atomic_write_600, clauth_dir};

/// Peer of `status.json` / `auth_token.json` / `tls.json` in `~/.clauth`.
const PROXY_FILE: &str = "proxy.json";
/// Bumped only on a breaking change to the file's shape, like `status.json`.
const SCHEMA: u64 = 1;

/// `~/.clauth/proxy.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProxyConfig {
    pub(crate) schema: u64,
    /// Already normalized to `host:port` by [`parse_origin`].
    pub(crate) origin: String,
    /// The origin daemon's bearer token, 64 hex characters.
    pub(crate) token: String,
    pub(crate) interval_secs: u64,
    /// Profiles this proxy created here, so a prune only ever removes what the
    /// mirror put on disk. A profile that was always local is never touched.
    #[serde(default)]
    pub(crate) mirrored: Vec<ProfileName>,
}

pub(crate) fn proxy_path() -> Result<PathBuf> {
    Ok(clauth_dir()?.join(PROXY_FILE))
}

/// True when this host is a replica. Existence only — see the module docs for
/// why a parse failure still counts.
pub(crate) fn is_replica() -> bool {
    proxy_path().is_ok_and(|p| p.exists())
}

/// The stored config, or `None` when this host is not a replica.
///
/// A malformed file is a hard error, NOT a silent fall back to defaults — the
/// same call `tls.json` makes and for the same reason: quietly mirroring from
/// an origin the operator believes they moved away from is a worse failure than
/// refusing to start, and the error names the file.
pub(crate) fn load() -> Result<Option<ProxyConfig>> {
    let path = proxy_path()?;
    // Only an ABSENT file means "not a replica". A file that exists and cannot
    // be read is an error for the same reason an unparseable one is: treating it
    // as absent would send `resolve` down the first-run path, which prompts for
    // a token and then overwrites the origin the operator had configured.
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let parsed: ProxyConfig = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if parsed.schema > SCHEMA {
        // Written by a newer clauth. Every field this build reads means the
        // same thing either way, so take it and let the newer field set be —
        // the call `auth_token.json` and `tls.json` both make on a downgrade.
        crate::logline::logline!(
            "clauth proxy: {PROXY_FILE} is schema {} (this build knows {SCHEMA})",
            parsed.schema
        );
    }
    Ok(Some(parsed))
}

pub(crate) fn save(config: &ProxyConfig) -> Result<()> {
    let path = proxy_path()?;
    atomic_write_600(&path, serde_json::to_vec_pretty(config)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Remove the file, re-arming this host. Reports whether there was one.
pub(crate) fn forget() -> Result<bool> {
    let path = proxy_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// Normalize `HOST[:PORT]` to `host:port`, refusing anything that cannot be the
/// name on a certificate.
///
/// An address is rejected by name rather than left to fail later as an opaque
/// TLS error: the daemon serves this host's own lego certificate, so a client
/// dialing `10.0.0.4:8443` fails verification no matter what is listening, and
/// that is the mistake this deployment invites (`wiki/Daemon.md`). Catching it
/// here costs one parse and saves an operator the handshake dump.
pub(crate) fn parse_origin(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("no origin given; pass --from <fqdn>");
    }
    // Addresses are caught BEFORE the port split, because an IPv6 literal is
    // full of colons and `rsplit_once` would happily read `::1` as host `:` on
    // port 1 -- an unhelpful "not a usable hostname" instead of the real reason.
    // Anything bracketed, or carrying more than one colon, is an address or is
    // ambiguous enough that refusing it is the honest answer.
    let bare = raw.trim_start_matches('[');
    if raw.parse::<IpAddr>().is_ok()
        || raw.starts_with('[')
        || raw.matches(':').count() > 1
        || bare
            .split_once(']')
            .is_some_and(|(inside, _)| inside.parse::<IpAddr>().is_ok())
    {
        bail!(
            "the origin has to be the name on its certificate, not an address: {raw} would fail \
             verification whatever is listening. Use the FQDN `clauth daemon --listen` serves, and \
             make sure it resolves to the daemon from here"
        );
    }
    // Split a trailing `:port` only when the tail is really a port.
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let port: u16 = p
                .parse()
                .with_context(|| format!("{p:?} is not a usable port"))?;
            if port == 0 {
                bail!("port 0 is not a usable port");
            }
            (h, port)
        }
        _ => (raw, ProxyArgs::DEFAULT_PORT),
    };
    if host.parse::<IpAddr>().is_ok() {
        bail!(
            "the origin has to be the name on its certificate, not an address: {host} would fail \
             verification whatever is listening. Use the FQDN `clauth daemon --listen` serves, and \
             make sure it resolves to the daemon from here"
        );
    }
    let plausible = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && !host.ends_with(['-', '.'])
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !plausible {
        bail!("{host:?} is not a usable hostname");
    }
    Ok(format!("{host}:{port}"))
}

/// Clamp-check a requested interval. Refuses rather than clamping: an operator
/// who asked for 15 minutes has a cadence in mind, and silently serving them 5
/// would leave them believing something this build is not doing.
pub(crate) fn validate_interval(secs: u64) -> Result<u64> {
    if secs == 0 {
        bail!("--interval 0 would spin; give it at least a second");
    }
    if secs > ProxyArgs::MAX_INTERVAL_SECS {
        bail!(
            "--interval {secs} is above the {max}s cap. It is only the fallback cadence (a failed \
             pull, or an origin too old to hold a request), and on that path it has to stay tight: \
             the origin rotates an access token about \
             15 minutes before expiry and Claude Code refreshes its own within 5 minutes of it, so \
             a pull has roughly ten minutes to carry the new token across. A slower cadence builds \
             a replica whose sessions fail at expiry, with no refresh token on this side to \
             recover with",
            max = ProxyArgs::MAX_INTERVAL_SECS
        );
    }
    Ok(secs)
}

/// Build the config a run should use: flags win, the stored file fills in, and
/// what is left is the default. Returns the config to use, already saved.
pub(crate) fn resolve(
    args: &ProxyArgs,
    token_from_prompt: impl FnOnce() -> Result<String>,
) -> Result<ProxyConfig> {
    let stored = load()?;

    let origin = match (&args.from, &stored) {
        (Some(raw), _) => parse_origin(raw)?,
        (None, Some(cfg)) => cfg.origin.clone(),
        (None, None) => bail!(
            "no origin configured. Run `clauth proxy --from <fqdn>` once with the origin's token; \
             after that a bare `clauth proxy` reuses it"
        ),
    };

    // Checked BEFORE the token is asked for: a rejected flag should not cost the
    // operator a paste of a secret they then have to repeat.
    let interval_secs = match (args.interval, &stored) {
        (Some(secs), _) => validate_interval(secs)?,
        (None, Some(cfg)) => validate_interval(cfg.interval_secs)?,
        (None, None) => ProxyArgs::DEFAULT_INTERVAL_SECS,
    };

    // A token already on disk is reused unless the operator supplied one. That
    // is what makes a bare `clauth proxy` work, and it means an origin change
    // that keeps the same token needs no re-paste.
    let token = match (&args.token_file, &stored) {
        (Some(path), _) => {
            let body = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            body.trim().to_string()
        }
        // Keyed on the ORIGIN, not on whether --from was typed: re-running with
        // the same host spelled out is the common way to change only the
        // interval, and re-prompting there would be a papercut. A genuinely new
        // origin does prompt, since the old one's token means nothing to it and
        // reusing it would surface as an opaque 401.
        (None, Some(cfg)) if cfg.origin == origin => cfg.token.clone(),
        (None, _) => token_from_prompt()?,
    };
    if !crate::daemon::api::token::is_well_formed(&token) {
        bail!(
            "that does not look like a clauth API token (expected 64 hex characters, got {}). \
             Get it from `clauth daemon --print-token` on the origin",
            token.len()
        );
    }

    let config = ProxyConfig {
        schema: SCHEMA,
        origin,
        token,
        interval_secs,
        mirrored: stored.map(|c| c.mirrored).unwrap_or_default(),
    };
    save(&config)?;
    Ok(config)
}

#[cfg(test)]
#[path = "../../tests/inline/proxy_config.rs"]
mod tests;
