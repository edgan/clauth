//! The replica's end of `/api/v1/mirror`: one authenticated HTTPS GET.
//!
//! `ureq` is already in the tree and already builds rustls with the `ring`
//! provider, so this adds no dependency and no second crypto backend. The agent
//! follows the pattern in `crate::usage::fetch`: real timeouts, and
//! `http_status_as_error(false)` so a 401 or 403 arrives on the `Ok` response
//! where it can be turned into an answer instead of collapsing into "network
//! error".
//!
//! Certificate verification is ureq's default and is not relaxed here. The
//! origin serves its own lego certificate, so the replica has to dial the name
//! that certificate carries; [`crate::proxy::config::parse_origin`] refuses an
//! address up front so that mistake is caught before the handshake rather than
//! after it.
//!
//! The agent is built by [`agent`] and OWNED BY THE CALLER, not held in a
//! process-global `LazyLock`. `clauth proxy` is the longest-lived process this
//! crate has, and a multi-hour origin outage puts thousands of failed calls
//! through one agent — pooled sockets, TLS state, whatever a dependency keeps
//! per-agent — with nothing able to reset any of it. Handing ownership to the
//! follow loop lets it throw the agent away and start clean, which is the only
//! recovery available for state this module cannot see inside.

use std::io::Read as _;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::wire::{MIRROR_SCHEMA, MirrorBody};

/// Ceiling on a mirror body. Four accounts run about 20 KB; this is room for
/// two orders of magnitude more, and a bound on what a hostile or broken origin
/// can make this process buffer.
const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// How long to ask the origin to hold a request open with nothing to say.
///
/// This is not a latency. A change comes back the moment the origin sees it;
/// this is only how often an idle connection is renewed, so it wants to be long
/// enough that renewals are rare and short enough to sit inside the origin's own
/// 60s cap and its 120s connection lifetime.
pub(crate) const WAIT_SECS: u64 = 50;

/// Idle connections the pool may keep. The proxy talks to exactly one origin
/// and has exactly one request in flight at a time, so every slot above one is
/// a socket held open against the origin's 32-connection cap for nothing.
/// ureq's defaults (10, and 3 per host) are sized for a general-purpose client;
/// this client is not one.
const MAX_IDLE_CONNECTIONS: usize = 1;

/// How long an idle connection may sit before it is dropped rather than reused.
///
/// The value matters more than it looks: the origin closes a connection at
/// `daemon::api::Limits::DEFAULT.lifetime` (120s) however politely the client is
/// behaving, so reusing one older than that buys a guaranteed round trip spent
/// discovering it is dead. This is ureq's own default, pinned here so a
/// dependency changing it cannot quietly push the client past the origin's
/// lifetime.
const MAX_IDLE_AGE: Duration = Duration::from_secs(15);

/// The pull agent's configuration.
///
/// Split out so the test agent — which differs from the real one only in whom it
/// trusts and how it resolves — cannot drift from the timeouts the real one
/// runs with. `tls` is `None` everywhere but tests, which take ureq's default
/// root store.
fn config(tls: Option<ureq::tls::TlsConfig>) -> ureq::config::Config {
    let builder = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(8)))
        // Both of these have to clear WAIT_SECS, because a held request sends
        // nothing at all until the origin has something to say: a 20s response
        // timeout would abort every idle wait and turn the long poll back into a
        // 20s one. The margins are what is left for the round trip and the body.
        .timeout_recv_response(Some(Duration::from_secs(WAIT_SECS + 15)))
        // One bound over the whole call, body included. Without it a peer that
        // trickles bytes blocks `read_to_end` forever, and because the pull runs
        // on the loop's only thread that does not just fail a tick: the proxy
        // stops pulling entirely, and the replica's access tokens go stale until
        // its sessions die. The per-phase timeouts never covered the body.
        .timeout_global(Some(Duration::from_secs(WAIT_SECS + 30)))
        // Status codes belong on the Ok path: `pull` distinguishes 401 from 403
        // from 404, and each gets its own answer.
        .http_status_as_error(false)
        .max_idle_connections(MAX_IDLE_CONNECTIONS)
        .max_idle_connections_per_host(MAX_IDLE_CONNECTIONS)
        .max_idle_age(MAX_IDLE_AGE);
    match tls {
        Some(tls) => builder.tls_config(tls),
        None => builder,
    }
    .build()
}

/// A fresh agent for the follow loop. Cheap enough to rebuild — it holds
/// configuration and an empty pool, and the rustls provider it uses is
/// process-wide.
pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(config(None))
}

/// What one poll found.
pub(crate) enum Pull {
    /// The origin's accounts changed (or this is the first pull).
    Fetched(Box<MirrorBody>),
    /// `304 Not Modified` — the origin's content digest matched `etag`.
    Unchanged,
}

/// `GET https://<origin>/api/v1/mirror`, with the bearer token and an optional
/// conditional-GET tag.
///
/// With a tag this asks the origin to HOLD the request until the accounts move
/// (`?wait`), so a switch there reaches this host in about a round trip. An
/// origin too old to know `wait` just answers immediately, which is why the
/// caller measures how long the call took rather than assuming it waited.
pub(crate) fn pull(
    agent: &ureq::Agent,
    origin: &str,
    token: &str,
    etag: Option<&str>,
) -> Result<Pull> {
    // No tag means nothing to wait for: with nothing to compare against, every
    // answer is a change, so the request is served at once either way.
    let query = if etag.is_some() {
        format!("?wait={WAIT_SECS}")
    } else {
        String::new()
    };
    // Spelled from the daemon's own prefix constant, so a version bump there
    // moves both ends of this route at once.
    let route = format!("{}/mirror", crate::daemon::api::routes::API_PREFIX);
    let url = format!("https://{origin}{route}{query}");
    let mut req = agent
        .get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header(
            "User-Agent",
            concat!("clauth-proxy/", env!("CARGO_PKG_VERSION")),
        );
    if let Some(tag) = etag {
        req = req.header("If-None-Match", tag);
    }

    let mut response = req.call().map_err(|e| {
        // The two failures this deployment actually produces, named rather than
        // left as a bare handshake or connect error.
        anyhow::anyhow!(
            "could not reach the origin at {origin}: {e}\n  \
             If this is a certificate error, dial the FQDN the origin's certificate names, \
             not an address, and make sure it resolves to the daemon from here.\n  \
             If the connection was refused, check the origin is running \
             `clauth daemon --listen` and that CLAUTH_NO_API=1 is not set there"
        )
    })?;

    let status = response.status().as_u16();
    match status {
        200 => {}
        304 => return Ok(Pull::Unchanged),
        401 => bail!(
            "the origin rejected this token (401). Get the current one with \
             `clauth daemon --print-token` on {origin}, then re-run \
             `clauth proxy --from {origin}`. A `--rotate-token` there invalidates every copy"
        ),
        403 => bail!(
            "the origin refused {route} (403). Nothing in this build answers that, so \
             something between here and the daemon is: check for a reverse proxy in front of it"
        ),
        404 => bail!(
            "the origin has no {route} route (404): it is running a clauth too old for \
             `clauth proxy`. Upgrade the origin"
        ),
        other => bail!("the origin answered {other} for {route}"),
    }

    // +1 so a body exactly at the cap still trips the over-limit check, the
    // same shape `crate::status::fetch_feed` uses.
    let mut capped = response.body_mut().as_reader().take(MAX_BODY_BYTES + 1);
    let mut bytes = Vec::new();
    capped
        .read_to_end(&mut bytes)
        .context("failed to read the mirror body")?;
    if bytes.len() as u64 > MAX_BODY_BYTES {
        bail!("the mirror body is larger than {MAX_BODY_BYTES} bytes; refusing to buffer it");
    }

    let body: MirrorBody =
        serde_json::from_slice(&bytes).context("failed to parse the mirror body")?;
    if body.schema > MIRROR_SCHEMA {
        // Refuse rather than half-apply. A newer origin may express something
        // this build would silently drop, and dropping half an account's state
        // is worse than not moving.
        bail!(
            "the origin speaks mirror schema {} and this build knows {MIRROR_SCHEMA}; \
             upgrade clauth here",
            body.schema
        );
    }
    Ok(Pull::Fetched(Box::new(body)))
}

// ── test-only agent ──────────────────────────────────────────────────────────
//
// A test origin serves a certificate signed by a CA the machine has never heard
// of, under a name that resolves nowhere. Both are deliberate on the production
// path — `parse_origin` refuses an address precisely so an operator cannot dial
// past certificate verification — so the only way to drive the REAL client
// against a REAL local origin is to hand it its own roots and its own resolver.
//
// Neither seam relaxes anything. The test agent still verifies the chain; it
// just verifies it against the CA the fixture generated. That keeps the thing
// under test the same code the replica runs, which is the whole point: a test
// that stubbed `pull` out would not have been able to see the failure loop at
// all.
//
// `ureq::unversioned` is explicitly not semver-stable, which is why it is
// confined to this `cfg(test)` block and never reachable from a shipped build.

/// Resolves every name to one fixed address, so the client can dial the name on
/// the fixture's certificate and still land on `127.0.0.1:<ephemeral port>`.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct FixedResolver(pub(crate) std::net::SocketAddr);

#[cfg(test)]
impl ureq::unversioned::resolver::Resolver for FixedResolver {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let mut addrs = self.empty();
        addrs.push(self.0);
        Ok(addrs)
    }
}

/// An agent that trusts exactly `roots` and dials exactly `addr`, and is
/// identical to [`agent`] in every other respect.
#[cfg(test)]
pub(crate) fn test_agent(
    roots: Vec<ureq::tls::Certificate<'static>>,
    addr: std::net::SocketAddr,
) -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(roots.into())
        .build();
    ureq::Agent::with_parts(
        config(Some(tls)),
        ureq::unversioned::transport::DefaultConnector::new(),
        FixedResolver(addr),
    )
}
