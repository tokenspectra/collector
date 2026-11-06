//! The Collector against a mock Fleet (spec §15): enrolment, the outbound
//! channel, signed config, seeds, a cut channel and the mTLS ingest.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fleet.rs"]
mod fleet_mock;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use collector::capture::{derive_secret, CaptureConfig};
use collector::client::{client_config, read_roots, Endpoint};
use collector::fleet::{Channel, Fleet, FleetError, FleetOptions, StubEvidence, CONFIG_CONTEXT, STATE};
use collector::manifest::{verify_log, LOG};
use collector::mh;
use collector::ship::{pending_lines, ship_pending};
use collector::sign::{hex, KeyProvider, SoftwareKey};
use ed25519_dalek::SigningKey;
use fleet_mock::{now_s, seal_seed, sign, Answer, MockFleet, MEMBER, SITE, TOKEN};
use serde_json::{json, Value};

const SIGNING: [u8; 32] = [5; 32];

fn options(mock: &MockFleet, dir: &Path) -> FleetOptions {
    FleetOptions {
        url: mock.url.clone(),
        ca: mock.ca_path().to_path_buf(),
        root: mock.root_public(),
        dir: dir.to_path_buf(),
        join_token: Some(TOKEN.to_string()),
        signing_key: SoftwareKey::from_seed(SIGNING).public_key(),
        evidence: Box::new(StubEvidence),
        dev_plain_http: false,
    }
}

fn enrol(mock: &MockFleet, dir: &Path) -> Arc<Fleet> {
    Fleet::open(options(mock, dir)).unwrap()
}

/// Waits until `done`, or fails the test.
fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn sealed(fleet: &Fleet, w: u64) -> (CaptureConfig, collector::fleet::Stamp) {
    let mut capture = CaptureConfig::default();
    let stamp = fleet.seal(w, &mut capture);
    (capture, stamp)
}

#[test]
fn enrolment_binds_the_keys_and_nonce_and_brings_what_the_run_needs() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let fleet = enrol(&mock, dir.path());
    assert_eq!((fleet.member().as_str(), fleet.site().as_str()), (MEMBER, SITE));
    assert_eq!(fleet.seeds().latest(), Some(1));

    let attested = mock.state.lock().unwrap().attested.clone();
    assert_eq!(attested.len(), 1);
    assert_eq!(attested[0].member, None, "a first enrolment names no member");
    assert!(!attested[0].client_cert);
    assert_eq!(
        attested[0].keys["signing"],
        hex(&SoftwareKey::from_seed(SIGNING).public_key())
    );

    let (capture, stamp) = sealed(&fleet, 0);
    assert_eq!(capture.rate, 1.0);
    assert_eq!(stamp.capture.epoch, Some(1));
    assert!(!stamp.observed.channel_cut);
    let payload = sign(&mock.root, CONFIG_CONTEXT, &mock.state.lock().unwrap().config).payload;
    assert_eq!(stamp.identity.config, mh::of(payload.as_bytes()));

    // Nothing secret is at rest in the clear: seeds stay sealed.
    let state = std::fs::read_to_string(dir.path().join(STATE)).unwrap();
    assert!(!state.contains(&hex(&[7; 32])));
}

#[test]
fn a_second_start_uses_what_it_kept_and_needs_no_channel() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let first = enrol(&mock, dir.path());
    let config = sealed(&first, 0).1.identity.config;
    drop(first);

    mock.set_cut(true);
    let mut opts = options(&mock, dir.path());
    opts.join_token = None;
    let fleet = Fleet::open(opts).unwrap();
    assert_eq!(fleet.member(), MEMBER);
    assert_eq!(sealed(&fleet, 0).1.identity.config, config);
    assert_eq!(fleet.seeds().epoch_of(0).unwrap().1, [7; 32]);
    assert_eq!(mock.state.lock().unwrap().attested.len(), 1);
}

#[test]
fn keys_survive_a_restart() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    enrol(&mock, dir.path());
    std::fs::remove_file(dir.path().join(STATE)).unwrap();
    enrol(&mock, dir.path());
    let attested = mock.state.lock().unwrap().attested.clone();
    assert_eq!(attested[0].keys, attested[1].keys);
    assert_ne!(attested[0].nonce, attested[1].nonce);
}

#[test]
fn a_collector_the_fleet_will_not_have_does_not_start() {
    type Expected = fn(&FleetError) -> bool;
    let cases: [(Answer, Expected); 4] = [
        (Answer::Pending, |e| matches!(e, FleetError::Pending)),
        (Answer::Refuse, |e| {
            matches!(e, FleetError::Refused { status: 403, .. })
        }),
        (Answer::ForgedCert, |e| matches!(e, FleetError::Bad(_))),
        (Answer::OtherKeyCert, |e| matches!(e, FleetError::Bad(_))),
    ];
    for (answer, expected) in cases {
        let mock = MockFleet::start();
        mock.state.lock().unwrap().answer = answer;
        let dir = tempfile::tempdir().unwrap();
        let err = Fleet::open(options(&mock, dir.path())).unwrap_err();
        assert!(expected(&err), "{err}");
        assert!(!dir.path().join(STATE).exists(), "{err}");
    }
}

#[test]
fn enrolment_needs_a_join_token_and_a_fleet_it_can_trust() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(&mock, dir.path());
    opts.join_token = None;
    assert!(matches!(Fleet::open(opts), Err(FleetError::NoToken)));

    let mut opts = options(&mock, dir.path());
    opts.join_token = Some("wrong".into());
    assert!(matches!(
        Fleet::open(opts),
        Err(FleetError::Refused { status: 403, .. })
    ));

    // Another CA: the server's certificate doesn't chain to it.
    let other = MockFleet::start();
    let mut opts = options(&mock, dir.path());
    opts.ca = other.ca_path().to_path_buf();
    assert!(matches!(Fleet::open(opts), Err(FleetError::Client(_))));

    // Another Fleet key: nothing the Fleet signs checks out.
    let mut opts = options(&mock, dir.path());
    opts.root = other_key().verifying_key().to_bytes();
    assert!(matches!(Fleet::open(opts), Err(FleetError::Bad(_))));

    let mut opts = options(&mock, dir.path());
    opts.url = mock.url.replace("https://", "http://");
    assert!(matches!(Fleet::open(opts), Err(FleetError::Plain(_))));
}

fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

#[test]
fn the_channel_heartbeats_and_only_a_newer_signed_config_is_applied() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let fleet = enrol(&mock, dir.path());
    let channel = Channel::spawn(fleet.clone()).unwrap();
    wait_for("a heartbeat", || !mock.state.lock().unwrap().pulls.is_empty());
    {
        let s = mock.state.lock().unwrap();
        assert_eq!(s.pulls[0]["member"], MEMBER);
        assert_eq!(s.pulls[0]["config_version"], 1);
        assert_eq!(s.pulls[0]["seed_epoch"], 1);
    }
    let start = sealed(&fleet, 0).1.identity.config;
    let hand = |signed| {
        mock.state.lock().unwrap().next_config = Some(signed);
        wait_for("the pull", || mock.state.lock().unwrap().next_config.is_none());
        // One more, so the one that took it has been applied.
        let seen = mock.state.lock().unwrap().pulls.len();
        wait_for("the next pull", || {
            mock.state.lock().unwrap().pulls.len() > seen + 1
        });
    };

    // Not newer, not the Fleet's, not this member's, out of range: left alone.
    hand(mock.signed_config(json!({ "version": 1, "capture_rate": 0.5 })));
    hand(sign(
        &other_key(),
        CONFIG_CONTEXT,
        &json!({ "version": 9, "member": MEMBER, "ingest": mock.ingest_url, "capture_rate": 0.5,
                 "truncate_to": 1, "alarm_cap": 1 }),
    ));
    hand(mock.signed_config(json!({ "version": 9, "member": "someone-else", "capture_rate": 0.5 })));
    hand(mock.signed_config(json!({ "version": 9, "capture_rate": 7.0 })));
    hand(mock.signed_config(json!({ "version": 9, "ingest": "http://plain/" })));
    let (capture, stamp) = sealed(&fleet, 0);
    assert_eq!(
        (capture.rate, stamp.identity.config.as_str()),
        (1.0, start.as_str())
    );

    let newer = mock.signed_config(json!({ "version": 2, "capture_rate": 0.25, "truncate_to": 64 }));
    hand(newer.clone());
    let (capture, stamp) = sealed(&fleet, 0);
    assert_eq!((capture.rate, capture.truncate_to), (0.25, 64));
    assert_eq!(stamp.identity.config, mh::of(newer.payload.as_bytes()));
    wait_for("the new version in a heartbeat", || {
        mock.state.lock().unwrap().pulls.last().unwrap()["config_version"] == 2
    });
    channel.finish();

    // A restart keeps it, and an older one still doesn't pass.
    drop(fleet);
    let fleet = enrol(&mock, dir.path());
    assert_eq!(sealed(&fleet, 0).0.rate, 0.25);
}

#[test]
fn a_new_seed_epoch_derives_the_secret_and_a_forged_one_is_refused() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let fleet = enrol(&mock, dir.path());
    let hpke = mock.state.lock().unwrap().hpke_key.unwrap();
    let channel = Channel::spawn(fleet.clone()).unwrap();

    // Sealed to the right key by someone else: HPKE alone would take it.
    mock.state.lock().unwrap().next_seeds = vec![
        seal_seed(&other_key(), &hpke, MEMBER, 2, 1000, &[66; 32]),
        seal_seed(&mock.root, &hpke, "someone-else", 2, 1000, &[66; 32]),
    ];
    wait_for("the pull", || mock.state.lock().unwrap().next_seeds.is_empty());
    let seen = mock.state.lock().unwrap().pulls.len();
    wait_for("the next pull", || {
        mock.state.lock().unwrap().pulls.len() > seen + 1
    });
    assert_eq!(fleet.seeds().latest(), Some(1));

    mock.state.lock().unwrap().next_seeds = vec![seal_seed(&mock.root, &hpke, MEMBER, 2, 1000, &[8; 32])];
    wait_for("the epoch", || fleet.seeds().latest() == Some(2));
    channel.finish();

    let capture = CaptureConfig {
        seeds: Some(fleet.seeds()),
        ..CaptureConfig::default()
    };
    // What the control plane recomputes from the seed it handed out.
    assert_eq!(capture.window_secret(999), Some(derive_secret(&[7; 32], 999)));
    assert_eq!(capture.window_secret(1000), Some(derive_secret(&[8; 32], 1000)));
    assert_eq!(sealed(&fleet, 999).1.capture.epoch, Some(1));
    assert_eq!(sealed(&fleet, 1000).1.capture.epoch, Some(2));

    // Kept sealed across a restart, from the same window on.
    drop(fleet);
    let fleet = enrol(&mock, dir.path());
    assert_eq!(fleet.seeds().epoch_of(1000).unwrap(), (2, [8; 32]));
}

#[test]
fn renewal_takes_fresh_evidence_and_keeps_the_member() {
    let mock = MockFleet::start();
    mock.state.lock().unwrap().cert_to = 5; // past two thirds of its life at once
    mock.state.lock().unwrap().cert_from = -3600;
    let dir = tempfile::tempdir().unwrap();
    let fleet = enrol(&mock, dir.path());
    mock.state.lock().unwrap().cert_to = 3600;
    let channel = Channel::spawn(fleet.clone()).unwrap();
    wait_for("a renewal", || mock.state.lock().unwrap().attested.len() >= 2);
    wait_for("a pull on the new certificate", || {
        let s = mock.state.lock().unwrap();
        s.pulls
            .last()
            .is_some_and(|p| p["cert_not_after"].as_i64().unwrap() > now_s() + 1000)
    });
    channel.finish();
    let attested = mock.state.lock().unwrap().attested.clone();
    assert_eq!(attested.len(), 2, "renewed once");
    assert_eq!(attested[1].member.as_deref(), Some(MEMBER));
    assert!(attested[1].client_cert, "renewal proves it holds the certificate");
    assert_ne!(attested[1].nonce, attested[0].nonce);
    assert_eq!(attested[1].keys, attested[0].keys);
}

#[test]
fn a_certificate_that_ran_out_is_renewed_without_it() {
    let mock = MockFleet::start();
    mock.state.lock().unwrap().cert_to = -1;
    mock.state.lock().unwrap().cert_from = -3600;
    let dir = tempfile::tempdir().unwrap();
    let fleet = enrol(&mock, dir.path());
    mock.state.lock().unwrap().cert_to = 3600;
    let channel = Channel::spawn(fleet.clone()).unwrap();
    wait_for("a renewal", || mock.state.lock().unwrap().attested.len() >= 2);
    channel.finish();
    let attested = mock.state.lock().unwrap().attested.clone();
    assert!(!attested[1].client_cert);
    assert_eq!(attested[1].member.as_deref(), Some(MEMBER));
}

#[test]
fn a_cut_channel_flags_the_manifest_and_changes_nothing_else() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let fleet = enrol(&mock, dir.path());
    let channel = Channel::spawn(fleet.clone()).unwrap();
    wait_for("a heartbeat", || !mock.state.lock().unwrap().pulls.is_empty());
    let (before, stamp) = sealed(&fleet, 0);
    assert!(!stamp.observed.channel_cut);

    mock.set_cut(true);
    wait_for("the cut to show", || fleet.channel_cut());
    let (during, cut) = sealed(&fleet, 10);
    assert!(cut.observed.channel_cut);
    assert_eq!(cut.identity.config, stamp.identity.config);
    assert_eq!(cut.capture.epoch, stamp.capture.epoch);
    assert_eq!(during.rate, before.rate);

    // Windows wait in the log for the ingest, cut off with the channel.
    std::fs::write(
        dir.path().join(LOG),
        "{\"collector\":\"c\",\"window_start_ns\":10}\n",
    )
    .unwrap();
    assert!(ship_pending(dir.path(), &fleet.ingest(), Duration::from_secs(1)).is_err());
    assert_eq!(pending_lines(dir.path()).unwrap(), 1);

    mock.set_cut(false);
    wait_for("the channel to come back", || !fleet.channel_cut());
    assert!(!sealed(&fleet, 20).1.observed.channel_cut);
    channel.finish();
    let shipped = ship_pending(dir.path(), &fleet.ingest(), Duration::from_secs(5)).unwrap();
    assert_eq!(shipped.sent, 1);
}

#[test]
fn the_ingest_wants_the_fleets_certificate() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let fleet = enrol(&mock, dir.path());
    std::fs::write(
        dir.path().join(LOG),
        "{\"collector\":\"c\",\"window_start_ns\":0}\n",
    )
    .unwrap();

    // No client certificate: refused, and the line stays.
    let anon = client_config(read_roots(mock.ca_path()).unwrap(), None).unwrap();
    let anon = Endpoint::tls(&mock.ingest_url, anon).unwrap();
    assert!(ship_pending(dir.path(), &anon, Duration::from_secs(5)).is_err());
    assert_eq!(pending_lines(dir.path()).unwrap(), 1);

    let shipped = ship_pending(dir.path(), &fleet.ingest(), Duration::from_secs(5)).unwrap();
    assert_eq!(shipped.sent, 1);
    assert!(mock.state.lock().unwrap().windows.contains_key("c/0"));
}

fn cli(mock: &MockFleet, out: &Path) -> Command {
    let token = out.with_extension("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_collector"));
    cmd.args(["-q", "--fleet", &mock.url, "--fleet-ca"])
        .arg(mock.ca_path())
        .args(["--fleet-root", &hex(&mock.root_public()), "--join-token-file"])
        .arg(&token);
    cmd
}

fn files(cmd: &mut Command, out: &Path) {
    cmd.args(["files", "-o"])
        .arg(out)
        .args(collect::fixture_paths(&["openai_h1_json.pcapng"]));
}

fn manifests(out: &Path) -> Vec<Value> {
    std::fs::read_to_string(out.join(LOG))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn a_run_enrols_ships_over_mtls_and_says_what_it_ran_under() {
    let mock = MockFleet::start();
    mock.state.lock().unwrap().config["capture_rate"] = json!(0.0);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let mut cmd = cli(&mock, &out);
    files(&mut cmd, &out);
    let run = cmd.output().unwrap();
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stdout));

    let lines = manifests(&out);
    assert!(!lines.is_empty());
    let config = sign(&mock.root, CONFIG_CONTEXT, &mock.state.lock().unwrap().config).payload;
    for m in &lines {
        assert_eq!(m["site"], SITE);
        assert_eq!(m["collector"], MEMBER);
        assert_eq!(m["identity"]["config"], mh::of(config.as_bytes()));
        assert_eq!(m["capture"]["epoch"], 1);
        assert_eq!(m["observed"]["channel_cut"], false);
    }
    // The config's rate of 0 cut the Workunit, with no --capture-rate.
    assert!(lines
        .iter()
        .any(|m| m["totals"]["truncated_bytes"].as_u64().unwrap() > 0));

    // The fields are signed: the chain still verifies.
    let key = SoftwareKey::open_or_create(&out.join("signing.key")).unwrap();
    let log = std::fs::read(out.join(LOG)).unwrap();
    assert_eq!(verify_log(&log, key.public_key()).unwrap().len(), lines.len());

    let held = mock.state.lock().unwrap().windows.clone();
    assert_eq!(held.len(), lines.len());
}

#[test]
fn a_rerun_under_another_config_repeats_the_windows() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let run = |mock: &MockFleet| {
        let mut cmd = cli(mock, &out);
        files(&mut cmd, &out);
        let run = cmd.output().unwrap();
        assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stdout));
    };
    run(&mock);
    let n = manifests(&out).len();
    let next = mock.signed_config(json!({ "version": 2 }));
    mock.state.lock().unwrap().next_config = Some(next);
    run(&mock);
    assert!(
        mock.state.lock().unwrap().next_config.is_none(),
        "pulled before capture"
    );
    assert_eq!(manifests(&out).len(), n);
}

#[test]
fn plain_http_is_refused_without_the_dev_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let run = |extra: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_collector"));
        cmd.args(extra);
        files(&mut cmd, &out);
        cmd.output().unwrap()
    };
    let refused = run(&["--ingest", "http://127.0.0.1:9/ingest"]);
    assert!(!refused.status.success());
    let text = String::from_utf8_lossy(&refused.stdout);
    assert!(text.contains("--dev-plain-http"), "{text}");
    assert!(!out.exists(), "refused before anything was written");

    // Nothing without a Fleet certificate either.
    assert!(!run(&["--ingest", "https://127.0.0.1:9/ingest"]).status.success());
    assert!(
        !run(&["--ingest", "https://127.0.0.1:9/ingest", "--dev-plain-http"])
            .status
            .success()
    );

    let allowed = run(&[
        "-q",
        "--dev-plain-http",
        "--ship-wait-s",
        "0",
        "--ingest",
        "http://127.0.0.1:9/ingest",
    ]);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stdout)
    );
}

#[test]
fn the_capture_key_is_a_dev_flag_a_fleet_run_does_not_take() {
    let mock = MockFleet::start();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let mut cmd = cli(&mock, &out);
    cmd.args(["--capture-key", &hex(&[1; 32])]);
    files(&mut cmd, &out);
    assert!(!cmd.output().unwrap().status.success());
}
