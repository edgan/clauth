//! `POST /api/v1/statusline` — take a rate-limit reading from a Claude Code
//! session on another machine, and record it against the account here that
//! session is spending.
//!
//! # Why the daemon does the attributing
//!
//! A status-line payload names no account. The local hook resolves one by
//! matching the live `.credentials.json` against this host's stored profiles
//! (`crate::which::resolve_active`), which needs the profiles to be here. On a
//! machine running `claude` against accounts that live on this daemon, they are
//! not: it may hold no `~/.clauth/profiles` at all, and a mirrored login carries
//! no refresh token to match on even when it does.
//!
//! So the client sends the SHA-256 of the access token its session is
//! authenticating with, and [`attribute`] matches it against what each account
//! HERE would install. That is the same equality `crate::which` resolves by,
//! moved to the side that has the roster.
//!
//! # What a wrong digest can do
//!
//! Nothing worth defending against beyond the bearer token that already guards
//! every route. A digest cannot be spent, and anyone able to post one already
//! holds a token that can switch this host's active account. The failure mode of
//! a WRONG one is bounded by the overlay itself: a recorded reading only reaches
//! the display if its `resets_at` names the same window the poll established
//! (`crate::statusline::apply`), so a reading filed against the wrong account
//! lands on a window that does not match and stays inert.
//!
//! What the route does refuse is a body it cannot act on — a schema it does not
//! know, a malformed digest, a reading with no window in it — because each of
//! those would otherwise become a cache entry nothing ever reads, written under
//! a name chosen by a stranger.

use crate::profile::{ClaudeCredentials, ProfileName};
use crate::statusline_core::{STATUSLINE_SCHEMA, StatuslineBody, credential_digest, record};

use super::http::{Request, Response};
use super::routes::ApiContext;

/// The tail of `crate::statusline_core::STATUSLINE_ROUTE` after
/// [`super::routes::API_PREFIX`] — the form the router matches, since the table
/// there strips the prefix before dispatching. The two spellings are pinned
/// against each other by a test rather than by hand.
pub(crate) const ROUTE_SUFFIX: &str = "/statusline";

/// `POST /api/v1/statusline`.
///
/// Answers `200 {"ok":true,"profile":"<name>"}` when the reading was recorded,
/// `404 unknown_credential` when no enabled account here installs that
/// credential, and `400 bad_request` for a body this build cannot act on.
///
/// A 404 is deliberately an ANSWER and not an error: it is the ordinary outcome
/// for a host whose account this daemon does not have, and for the seconds
/// between a token rotation here and the client picking the new one up. The
/// client memoizes it exactly as it memoizes a success, so neither repeats.
pub(crate) fn handle(ctx: &ApiContext, req: &Request) -> Response {
    let Ok(body) = serde_json::from_slice::<StatuslineBody>(&req.body) else {
        return Response::error(400, "bad_request");
    };
    if body.schema > STATUSLINE_SCHEMA {
        // Refuse rather than record half of it: a newer client may express
        // something this build would silently drop.
        return Response::error(400, "bad_request");
    }
    if !digest_is_well_formed(&body.credential_sha256) {
        return Response::error(400, "bad_request");
    }
    // Checked before the roster is walked. A body with neither window records
    // nothing, so attributing it would be a pile of credential reads to reach
    // the same answer.
    let Some(mut reading) = to_reading(&body, crate::usage::now_ms()) else {
        return Response::error(400, "bad_request");
    };

    // Cloned out of the mutex, not held across it: everything after this reads
    // credential files off disk, which has no business running under the config
    // lock. Ranked CONFIG is outer to the record gate below, so the gate is
    // taken only once this is released.
    //
    // The ROSTER comes from the daemon's in-memory config, like the switch
    // route's does, rather than off disk like the mirror's. Only the names, the
    // active marker and the disabled flags come from here; the credential each
    // one installs is read from disk below, which is where it can actually
    // change under a running daemon. An account added by a CLI run since the
    // last reload is therefore not attributable until that reload — one missed
    // reading, and the next tick fixes it.
    let candidates = {
        #[allow(
            clippy::expect_used,
            reason = "config mutex poisoning is unrecoverable"
        )]
        let cfg = ctx.config.lock().expect("config mutex poisoned");
        let active = cfg.state.active_profile.as_ref().cloned();
        cfg.profiles
            .iter()
            // A disabled account is never attributed, however it matched —
            // the refusal `crate::which::resolve_profile` applies for the same
            // reason: a disabled profile's stored credential is left on disk, so
            // its token can still be recognised long after the disable.
            .filter(|p| !p.is_disabled())
            .map(|p| Candidate {
                active: Some(&p.name) == active.as_ref(),
                name: p.name.clone(),
            })
            .collect::<Vec<_>>()
    };

    let Some(name) = attribute(&candidates, &body.credential_sha256) else {
        return Response::error(404, "unknown_credential");
    };

    // One recorder at a time. `record` is a read-modify-write of one cache file,
    // and the high-water rule is the modify: two hosts posting against one
    // account at the same instant would otherwise both read the old mark and the
    // later write would drop the higher one. This closes the in-daemon half of
    // that; the cross-process half (a local hook racing the daemon) is the race
    // the feature already had, and is not made worse here.
    {
        // Poisoning is harmless for a `()` gate: there is no state to have been
        // left half-written, only the serialization itself.
        let _gate = ctx
            .statusline_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        record(&name, &mut reading);
    }

    // No republish. The main loop rewrites `status.json` every tick, and the
    // feed's windows are built through `profile_json`, which applies the
    // status-line overlay on the read — so a reader parked on
    // `GET /api/v1/status?wait=` is woken by the content change within a second.
    // A switch republishes because nothing else would; a reading does not need
    // to. (That overlay is the display half of this feature and lands with
    // `clauth statusline` itself, so on a build carrying only this route a
    // recorded reading is stored and not yet shown.)
    Response::json(
        200,
        &serde_json::json!({ "ok": true, "profile": name.as_str() }),
    )
}

/// Hex characters in a SHA-256 digest. The wire format's whole length check.
const DIGEST_LEN: usize = 64;

/// Whether a posted digest has the shape [`credential_digest`] emits. Anything
/// else is a client bug or a probe: it cannot match, so it is refused before the
/// roster is walked rather than after every credential has been read.
fn digest_is_well_formed(digest: &str) -> bool {
    digest.len() == DIGEST_LEN
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The reading a body carries, stamped `now_ms` by THIS host.
///
/// The client's clock has no say: it may be minutes off, and a stamp from the
/// future would pin a window against every later reading. `None` when the body
/// carries neither window — the same refusal `crate::statusline::reading` makes
/// locally, so a body that could only record nothing is refused at the door.
fn to_reading(body: &StatuslineBody, now_ms: u64) -> Option<crate::statusline_core::LiveUsage> {
    (body.five_hour.is_some() || body.seven_day.is_some()).then(|| {
        crate::statusline_core::LiveUsage {
            observed_at_ms: now_ms,
            five_hour: body.five_hour,
            seven_day: body.seven_day,
            session_id: body.session_id.clone(),
        }
    })
}

/// One account a posted reading could belong to.
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub(crate) name: ProfileName,
    /// Whether this is the host's active account. Ties break toward it.
    pub(crate) active: bool,
}

/// Which of `candidates` installs the credential `digest` names, if any.
pub(crate) fn attribute(candidates: &[Candidate], digest: &str) -> Option<ProfileName> {
    attribute_with(candidates, digest, &installed_access_token)
}

/// [`attribute`]'s decision over an injected reader, so the tie-break is
/// testable without a profile tree on disk.
///
/// Active-first, then first match — the same shape (and the same reason) as
/// `crate::which::match_by_session_token`: two profiles can legitimately hold
/// one account's credential, and the active one is the honest answer for a
/// reading that names no other.
fn attribute_with(
    candidates: &[Candidate],
    digest: &str,
    read: &dyn Fn(&ProfileName) -> Option<String>,
) -> Option<ProfileName> {
    if digest.is_empty() {
        return None;
    }
    let mut fallback = None;
    for candidate in candidates {
        let Some(token) = read(&candidate.name) else {
            continue;
        };
        if credential_digest(&token) != digest {
            continue;
        }
        if candidate.active {
            return Some(candidate.name.clone());
        }
        fallback.get_or_insert_with(|| candidate.name.clone());
    }
    fallback
}

/// The access token a switch would INSTALL for `name` — the very bytes a
/// session running this account on any host is authenticating with.
///
/// Read through `install_source_path` rather than `credentials.json` directly,
/// so an account served by a long-lived sidecar (a `claude setup-token` mint, or
/// a rolling stamp) attributes on the token that is actually live for it. A
/// profile whose file is missing or unreadable simply does not match, which is
/// the same outcome as not being the right account.
fn installed_access_token(name: &ProfileName) -> Option<String> {
    let path = crate::claude::install_source_path(name).ok()?;
    let body = std::fs::read_to_string(path).ok()?;
    let creds: ClaudeCredentials = serde_json::from_str(&body).ok()?;
    creds
        .access_token()
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
#[path = "../../../tests/inline/daemon_api_statusline.rs"]
mod tests;
