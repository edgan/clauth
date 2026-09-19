#![allow(clippy::unwrap_used, clippy::expect_used)]

//! What being a replica costs this host.
//!
//! The refusals are the visible half. The half that matters is that the usage
//! refresher does not start: the origin owns polling and rotation, and a second
//! scheduler on the same accounts is the double-refresh `clauth proxy` exists to
//! prevent. See `crate::usage::scheduler::spawn_refresher`.

#![cfg(unix)]

use super::*;

use crate::testutil::{HomeSandbox, SERVER_NAME};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn become_replica(origin: &str) {
    config::save(&config::ProxyConfig {
        schema: 1,
        origin: origin.to_string(),
        token: TOKEN.to_string(),
        interval_secs: 60,
        mirrored: Vec::new(),
    })
    .expect("save proxy.json");
}

/// A host that is not mirroring refuses nothing: every guard is a no-op until
/// `proxy.json` exists.
#[test]
fn a_normal_host_refuses_nothing() {
    let _home = HomeSandbox::new();
    assert!(!is_replica());
    assert!(refuse_if_replica("switch").is_ok());
}

/// Every refusal names the origin and says how to stop mirroring. "Not
/// supported here" without either is a dead end, and the operator's next move
/// is genuinely on another machine.
#[test]
fn a_refusal_names_the_origin_and_the_way_out() {
    let _home = HomeSandbox::new();
    become_replica("boson.example.org:8443");

    let err = refuse_if_replica("log in").expect_err("a replica refuses");
    let msg = err.to_string();
    assert!(msg.contains("boson.example.org"), "names the origin: {msg}");
    assert!(msg.contains("log in"), "names the action: {msg}");
    assert!(msg.contains("--forget"), "names the way out: {msg}");
}

/// A replica whose config cannot be parsed still refuses. Falling back to
/// "allowed" on a corrupt file would re-arm exactly the mutations this host
/// must not perform.
#[test]
fn a_replica_with_an_unreadable_config_still_refuses() {
    let _home = HomeSandbox::new();
    // `atomic_write_600` would create ~/.clauth on its way past; a raw
    // write does not, so make the dir the way clauth would.
    crate::profile::mkdir_700(&crate::profile::clauth_dir().unwrap()).expect("mkdir");
    std::fs::write(config::proxy_path().unwrap(), b"{ not json").expect("write");

    let err = refuse_if_replica("switch").expect_err("still a replica");
    assert!(
        err.to_string().contains("its origin"),
        "it cannot name the origin, but it still refuses: {err}"
    );
}

/// The enforcement, not a convention: the refresher checks the marker itself,
/// so neither the daemon nor the TUI can grow a path that starts polling a
/// mirrored account.
#[test]
fn the_usage_refresher_stays_down_on_a_replica() {
    let _home = HomeSandbox::new();
    assert!(
        !crate::proxy::is_replica(),
        "the gate spawn_refresher reads is open on a normal host"
    );
    become_replica("boson.example.org:8443");
    assert!(
        crate::proxy::is_replica(),
        "and closed on a replica, which is what stops the second rotator"
    );
}

// ── surviving an origin outage ───────────────────────────────────────────────
//
// The 2026-09-04 report: a replica following an origin was left in `screen`, the
// origin's daemon went away, and some hours into the retry loop the proxy died
// with a bare `Segmentation fault`. Nothing in this crate's own safe Rust can do
// that, so what these tests pin is the shape of the loop around the failure — the
// part that CAN be checked from here.
//
// The first pull is deliberately fatal (`run`), so the retry loop only exists
// after the origin has answered once. That is why the interesting case is not "an
// origin that was never there" but "an origin that answered and then stopped",
// and why the tests below drive that transition rather than a cold start.

/// The retry schedule. A daemon restart is over in seconds, so the first failure
/// must retry at the configured interval rather than paying a backed-off wait for
/// something that has already fixed itself; a dead origin must not be dialled
/// 1440 times a day; and nothing may climb past the cap that keeps a rotated
/// access token reaching this host inside its window.
#[test]
fn the_retry_schedule_starts_at_the_interval_and_stops_at_the_cap() {
    assert_eq!(
        backoff_secs(0, 60),
        60,
        "not yet failed: the plain interval"
    );
    assert_eq!(backoff_secs(1, 60), 60, "one blip costs no extra wait");
    assert_eq!(backoff_secs(2, 60), 120);
    assert_eq!(backoff_secs(3, 60), 240);

    let cap = ProxyArgs::MAX_INTERVAL_SECS;
    for failures in 4..1_000 {
        assert_eq!(
            backoff_secs(failures, 60),
            cap,
            "a long outage must sit at the cap, never above it ({failures} failures)"
        );
    }
}

/// The cap is the same one `validate_interval` enforces, and for the same
/// reason: past it a rotated access token stops reaching this host inside the
/// window it has to arrive in. A backoff that grew past the ceiling would break
/// that contract silently, and only during an outage — the worst possible time to
/// discover it.
#[test]
fn no_interval_and_no_failure_count_can_climb_past_the_cap() {
    let cap = ProxyArgs::MAX_INTERVAL_SECS;
    for base in [1, 2, 59, 60, 299, cap] {
        for failures in 0..64 {
            let waited = backoff_secs(failures, base);
            assert!(
                waited <= cap,
                "base {base}, {failures} failures produced {waited}s, over the {cap}s cap"
            );
        }
    }
    // And the shift cannot overflow into a tiny wait on an absurd failure count.
    assert_eq!(backoff_secs(u64::MAX, 60), cap);
}

/// An outage says so once, not once per pull. A multi-hour outage at the 300s
/// cap is well over a hundred failures, and one line each is how the evidence for
/// the crash that prompted these tests came to be buried in its own retry log.
#[test]
fn a_steady_outage_is_reported_once_and_then_only_periodically() {
    let mut outage = Outage::default();

    let first = outage
        .failed("connection refused")
        .expect("the first speaks");
    assert!(
        first.contains("connection refused"),
        "names the reason: {first}"
    );

    // Everything up to the next periodic line stays quiet.
    for n in 2..LOUD_EVERY {
        assert!(
            outage.failed("connection refused").is_none(),
            "failure {n} repeated an unchanged reason and should have stayed quiet"
        );
    }
    let periodic = outage
        .failed("connection refused")
        .expect("an unchanging outage still checks in periodically");
    assert!(
        periodic.contains(&format!("{LOUD_EVERY} in a row")),
        "the periodic line carries the count: {periodic}"
    );
}

/// A reason that CHANGES always speaks, however deep into an outage it lands.
/// "Connection refused" becoming "certificate expired" is the operator's next
/// move changing, and suppressing it to keep the log tidy would hide the one line
/// worth reading.
#[test]
fn a_changed_reason_is_never_suppressed() {
    let mut outage = Outage::default();
    outage
        .failed("connection refused")
        .expect("the first speaks");
    assert!(
        outage.failed("connection refused").is_none(),
        "a repeat is quiet"
    );

    let changed = outage
        .failed("certificate expired")
        .expect("a new reason always speaks");
    assert!(
        changed.contains("certificate expired"),
        "and carries the new reason: {changed}"
    );
}

/// Recovery is an event in its own right. Without it the log simply goes quiet,
/// which reads identically to the process having died — the exact ambiguity the
/// crash report had to be untangled from.
#[test]
fn recovery_reports_what_the_outage_cost_and_resets_the_schedule() {
    let mut outage = Outage::default();
    assert!(
        outage.recovered().is_none(),
        "a pull that never failed has no recovery to announce"
    );

    for _ in 0..3 {
        outage.failed("connection refused");
    }
    assert_eq!(outage.failures, 3);

    let line = outage.recovered().expect("ending an outage speaks");
    assert!(line.contains('3'), "names what the outage cost: {line}");
    assert!(
        line.contains("answered again"),
        "and says the replica is following again: {line}"
    );

    // Reset, so the next blip starts from the configured interval rather than
    // inheriting the last outage's ceiling.
    assert_eq!(outage.failures, 0);
    assert_eq!(backoff_secs(outage.failures, 60), 60);
    assert!(outage.recovered().is_none(), "and does not announce twice");
}

/// Descriptors this process holds that are sockets on `port`, or `None` where
/// that cannot be counted (Linux only, by construction).
///
/// Deliberately NOT a count of `/proc/self/fd`. That file is per-process, and
/// under `cargo test` every other test in this binary is a thread in this same
/// process — measured that way a neighbour holding a couple of hundred
/// descriptors is indistinguishable from the leak this is looking for, and in
/// this suite one does. Narrowing to sockets whose local or remote port is the
/// caller's own ephemeral listener makes the count exact and unreachable by
/// anything else in the binary.
///
/// Descriptors, not socket-table rows: a leak is a descriptor nobody closed.
/// Sockets lingering in `TIME_WAIT` hold no descriptor and so cannot inflate
/// this, which is what makes it stable across runs.
fn fds_on_port(port: u16) -> Option<usize> {
    // `/proc/net/tcp` renders ports as four uppercase hex digits.
    let want = format!(":{port:04X}");
    let mut ours = std::collections::HashSet::new();
    for table in ["/proc/self/net/tcp", "/proc/self/net/tcp6"] {
        let Ok(body) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in body.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // 1 = local_address, 2 = rem_address, 9 = inode.
            let (Some(local), Some(remote), Some(inode)) =
                (fields.get(1), fields.get(2), fields.get(9))
            else {
                continue;
            };
            if local.ends_with(&want) || remote.ends_with(&want) {
                ours.insert(format!("socket:[{inode}]"));
            }
        }
    }
    let mut held = 0;
    for entry in std::fs::read_dir("/proc/self/fd").ok()? {
        let Ok(entry) = entry else { continue };
        if let Ok(target) = std::fs::read_link(entry.path())
            && ours.contains(target.to_string_lossy().as_ref())
        {
            held += 1;
        }
    }
    Some(held)
}

/// The reported crash was hours into a retry loop, which is the shape of
/// something accumulating. This drives the REAL client through hundreds of failed
/// pulls against a socket that accepts and hangs up, and pins that the loop holds
/// no more descriptors at the end than at the start.
///
/// Hundreds rather than the thousands a real outage would see: enough that a
/// per-pull leak is unmissable (it would be hundreds of descriptors), while
/// keeping the test to a second or so.
///
/// Counted with [`fds_on_port`], which sees only sockets on this test's own
/// listener — see there for why a process-wide count cannot be used.
#[test]
fn a_long_outage_leaks_no_descriptors() {
    // An origin whose daemon has died but whose host is still up: the connection
    // is accepted by the kernel and then goes nowhere. That reaches further into
    // the client than a refused connect, which never opens anything.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = std::sync::Arc::clone(&done);
    let hangup = std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            drop(stream);
        }
    });

    const PULLS: usize = 300;

    let Some(before) = fds_on_port(addr.port()) else {
        eprintln!("SKIPPED a_long_outage_leaks_no_descriptors: no /proc/self here");
        return;
    };

    let agent = client::test_agent(Vec::new(), addr);
    // The steady state: the listener, plus whatever one in-flight pull holds.
    let mut settled = before;
    for i in 0..PULLS {
        let outcome = client::pull(&agent, SERVER_NAME, TOKEN, Some("\"tag\""));
        assert!(
            outcome.is_err(),
            "a hung-up origin cannot produce a snapshot (iteration {i})"
        );
        // Measured after the pool has reached its steady state rather than at
        // iteration zero, so the baseline is not the one connection the client
        // legitimately holds.
        if i == 20 {
            settled = fds_on_port(addr.port()).expect("socket count mid-run");
        }
    }

    let after = fds_on_port(addr.port()).expect("socket count at the end");
    assert!(
        after <= settled,
        "{} further failed pulls left descriptors open on the origin's port: \
         {settled} -> {after} (entered holding {before}); a per-pull leak is what \
         turns a long outage fatal",
        PULLS - 20
    );

    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = std::net::TcpStream::connect(addr);
    let _ = hangup.join();
}

/// The transition the crash report describes, end to end over real TLS: the
/// origin answers a pull, then the daemon goes away. What is pinned is that the
/// client turns the second half into an ordinary `Err` — the loop's survivable
/// case — rather than anything worse.
#[test]
fn an_origin_that_answers_then_dies_leaves_the_client_returning_errors() {
    let _home = HomeSandbox::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((paths, ca_crt)) = crate::testutil::generate_chain(dir.path()).expect("fixture")
    else {
        eprintln!(
            "SKIPPED an_origin_that_answers_then_dies_leaves_the_client_returning_errors: \
             openssl is not usable here"
        );
        return;
    };
    let server_tls = crate::daemon::api::tls::server_config_from(&paths).expect("server config");

    let body = wire::MirrorBody {
        schema: wire::MIRROR_SCHEMA,
        generated_at: "2026-09-04T00:00:00+00:00".to_string(),
        active_profile: None,
        state: wire::MirrorState::default(),
        profiles: Vec::new(),
    };
    let json = serde_json::to_vec(&body).expect("serialize");

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    // Serves exactly one request and then drops the listener — the origin
    // answering once and then being stopped.
    let origin = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut conn = rustls::ServerConnection::new(server_tls).expect("server connection");
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        let mut scratch = [0_u8; 4096];
        let _ = std::io::Read::read(&mut tls, &mut scratch);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            json.len()
        );
        let _ = std::io::Write::write_all(&mut tls, head.as_bytes());
        let _ = std::io::Write::write_all(&mut tls, &json);
        let _ = std::io::Write::flush(&mut tls);
    });

    let roots = vec![
        ureq::tls::Certificate::from_pem(&std::fs::read(&ca_crt).expect("read ca"))
            .expect("parse ca"),
    ];
    let agent = client::test_agent(roots, addr);

    // The origin is up: a real snapshot crosses real TLS.
    let pulled = client::pull(&agent, SERVER_NAME, TOKEN, None).expect("the origin answers");
    assert!(
        matches!(pulled, client::Pull::Fetched(_)),
        "a 200 with a well-formed body is a snapshot"
    );
    let _ = origin.join();

    // The daemon is gone. Every pull from here is an error the follow loop can
    // sit on, and the message points at what the operator has to go fix.
    for i in 0..20 {
        // Matched rather than `expect_err`: that would need `Debug` on `Pull`,
        // and `Pull::Fetched` carries mirrored credentials — not a type to give
        // a derived formatter to for a test's convenience.
        let Err(err) = client::pull(&agent, SERVER_NAME, TOKEN, Some("\"tag\"")) else {
            panic!("iteration {i}: a dead origin cannot answer");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("could not reach the origin"),
            "iteration {i} should name the unreachable origin: {msg}"
        );
    }
}
