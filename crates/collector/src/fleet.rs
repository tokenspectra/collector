//! The Collector's side of the Fleet (TS-39, verification-pipeline §6c):
//! enrolment, and the outbound channel that keeps it going. Spec §15 has
//! the wire format.
//!
//! **Enrolment.** The Collector proves what it is, then gets what it needs.
//! Its keys are made inside the boundary, behind [`KeyProvider`] and
//! [`HpkeKey`]: the signing key of the manifests, a TLS key and an HPKE key.
//! It says hello, gets a nonce, and sends [`Evidence`] whose report data is
//! the hash of its public keys and the nonce, with the site join token. It
//! gets back its member id, a Fleet certificate for the signing key, a
//! short-lived mTLS certificate, signed config and sealed seed epochs.
//!
//! [`StubEvidence`] is the only evidence today: it proves nothing, says so
//! in its `kind`, and a real Fleet must refuse it. A TPM quote or a TDX or
//! SEV-SNP report goes behind [`Evidence`].
//!
//! **The channel** only ever goes out: the control plane never connects in.
//! Each poll is a heartbeat that brings back newer config and new seed
//! epochs. The mTLS certificate is renewed with fresh evidence, by the same
//! hello and enrolment; one that ran out while the channel was cut is
//! renewed the same way, without the client certificate.
//!
//! **What is trusted.** Nothing the channel brings counts unless the Fleet
//! key signed it, TLS or not: config, certificates and seeds alike. HPKE
//! base mode doesn't say who encrypted, so an unsigned seed could be the
//! Operator's, who could then predict the Capture Rate draw. Signed items
//! name the member, so one Collector's can't be replayed to another. Config
//! is applied only if newer.
//!
//! **A cut channel changes nothing but a flag.** What [`STATE`] holds is
//! checked again on start, and seeds stay sealed there, so a restart with
//! the channel down carries on too. The run keeps capturing with its last
//! config and current seed epoch, windows wait in the log and the spool, and
//! each manifest sealed meanwhile says `observed.channel_cut`.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::capture::{CaptureConfig, SeedBook};
use crate::client::{self, ClientError, Endpoint};
use crate::manifest::{CaptureInfo, Identity, Observed};
use crate::mh;
use crate::sign::{hex, parse_hex, HpkeKey, KeyProvider, SoftwareHpkeKey, SoftwareKey};

/// What this member is, in the Fleet's terms.
pub const KIND: &str = "collector";

/// What the Collector keeps of its enrolment, in the Fleet directory.
pub const STATE: &str = "state.json";

/// The Fleet key's signature contexts, so a signature on one thing can't
/// pass for another.
pub const CONFIG_CONTEXT: &[u8] = b"tokenspectra/fleet/config/v1\n";
pub const CERT_CONTEXT: &[u8] = b"tokenspectra/fleet/member-cert/v1\n";
pub const SEED_CONTEXT: &[u8] = b"tokenspectra/fleet/seed/v1\n";

/// HPKE `info` of a seed.
pub const SEED_INFO: &[u8] = b"tokenspectra/fleet/seed/v1";

const TIMEOUT: Duration = Duration::from_secs(10);
/// The most of a Fleet response that is read.
const MAX_RESPONSE: usize = 1 << 20;
/// Polls in a row that can fail before the channel counts as cut.
const CUT_AFTER_POLLS: u32 = 3;

#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("Fleet: {0}")]
    Client(#[from] ClientError),
    #[error("Fleet: {0}")]
    Io(#[from] io::Error),
    #[error("Fleet: enrolment is pending a Fleet admin; run again once approved")]
    Pending,
    #[error("Fleet: refused: HTTP {status}: {body}")]
    Refused { status: u16, body: String },
    /// The Fleet's reply can't be trusted or read.
    #[error("Fleet: {0}")]
    Bad(String),
    #[error("Fleet: not enrolled: the first run needs --join-token-file")]
    NoToken,
    #[error("Fleet: {0}: plain http:// needs --dev-plain-http")]
    Plain(String),
}

fn bad(what: impl fmt::Display) -> FleetError {
    FleetError::Bad(what.to_string())
}

/// Attestation evidence, as sent to the Fleet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Quote {
    /// `stub`, or the real thing: `tpm`, `tdx`, `sev-snp`.
    pub kind: String,
    /// The quote or report, in hex.
    pub quote: String,
}

/// Produces attestation evidence over `report_data`.
pub trait Evidence: Send + Sync {
    fn quote(&self, report_data: &[u8; 32]) -> io::Result<Quote>;
}

/// Evidence that proves nothing: the report data, unsigned. It stands in
/// until a TEE or TPM provider exists.
pub struct StubEvidence;

impl Evidence for StubEvidence {
    fn quote(&self, report_data: &[u8; 32]) -> io::Result<Quote> {
        Ok(Quote {
            kind: "stub".into(),
            quote: hex(report_data),
        })
    }
}

/// What the evidence binds: the hash of the public keys and the nonce.
pub fn report_data(signing: &[u8; 32], tls: &[u8; 32], hpke: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(signing).update(tls).update(hpke).update(nonce);
    *h.finalize().as_bytes()
}

/// Something the Fleet key signed: exact bytes and the signature over them
/// and a context, so nothing is ever re-serialized.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signed {
    /// A JSON document, as a string.
    pub payload: String,
    /// Ed25519, 128 hex digits.
    pub sig: String,
}

impl Signed {
    fn verify<T: DeserializeOwned>(&self, root: &VerifyingKey, context: &[u8]) -> Result<T, FleetError> {
        let sig = parse_hex::<64>(&self.sig).ok_or_else(|| bad("signature is not 128 hex digits"))?;
        root.verify_strict(
            &[context, self.payload.as_bytes()].concat(),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| bad("signature is not the Fleet key's"))?;
        serde_json::from_str(&self.payload).map_err(bad)
    }
}

/// Signed config: what the Collector acts on. It may hold more; all of it
/// counts towards the hash the manifest reports.
#[derive(Clone, Debug, Deserialize)]
struct Config {
    version: u64,
    member: String,
    ingest: String,
    capture_rate: f64,
    truncate_to: u32,
    alarm_cap: u64,
    #[serde(default = "default_poll_ms")]
    poll_ms: u64,
}

fn default_poll_ms() -> u64 {
    30_000
}

/// A seed epoch, as the Fleet signs it. `enc` and `ct` are in hex.
#[derive(Deserialize)]
struct SealedSeed {
    member: String,
    epoch: u64,
    from_ns: u64,
    enc: String,
    ct: String,
}

/// The Fleet certificate for the signing key.
#[derive(Deserialize)]
struct MemberCert {
    member: String,
    site: String,
    signing_key: String,
}

/// What enrolment and renewal bring back.
#[derive(Deserialize)]
struct Issued {
    member: String,
    site: String,
    fleet_cert: Signed,
    /// The mTLS certificate and its chain, DER in hex, leaf first.
    tls_chain: Vec<String>,
    /// Its validity, in Unix seconds.
    not_before: u64,
    not_after: u64,
    config: Signed,
    seeds: Vec<Signed>,
}

#[derive(Deserialize)]
struct Hello {
    nonce: String,
}

#[derive(Serialize)]
struct Keys {
    signing: String,
    tls: String,
    hpke: String,
}

/// A poll's reply.
#[derive(Deserialize)]
struct Pulled {
    #[serde(default)]
    config: Option<Signed>,
    #[serde(default)]
    seeds: Vec<Signed>,
}

/// A seed epoch held: still sealed, with the window start it covers from
/// here ([`SeedBook::add`]).
#[derive(Clone, Serialize, Deserialize)]
struct HeldSeed {
    seed: Signed,
    from_ns: u64,
}

/// The [`STATE`] file. Everything in it is signed, public or sealed.
#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    member: String,
    site: String,
    fleet_cert: Signed,
    tls_chain: Vec<String>,
    not_before: u64,
    not_after: u64,
    config: Signed,
    seeds: Vec<HeldSeed>,
}

/// How to reach the Fleet and who to be.
pub struct FleetOptions {
    /// `https://host[:port][/path]`.
    pub url: String,
    /// PEM file of the CA the Fleet's and the ingest's TLS chain to.
    pub ca: PathBuf,
    /// The Fleet's Ed25519 public key.
    pub root: [u8; 32],
    /// Where the keys and [`STATE`] live.
    pub dir: PathBuf,
    /// Needed for the first enrolment.
    pub join_token: Option<String>,
    /// The public key of the manifest signing key.
    pub signing_key: [u8; 32],
    pub evidence: Box<dyn Evidence>,
    /// Development: let the Fleet URL and the ingest be plain `http://`.
    pub dev_plain_http: bool,
}

/// The config in force and what follows from it.
struct Running {
    stored: Stored,
    config: Config,
    /// The multihash of the signed payload.
    config_hash: String,
    ingest: Endpoint,
    /// Trusts the Fleet's CA and presents the mTLS certificate.
    tls: Arc<ClientConfig>,
}

/// An enrolled Collector, shared by the run, the shipper and the channel.
pub struct Fleet {
    url: String,
    roots: RootCertStore,
    root: VerifyingKey,
    dir: PathBuf,
    join_token: Option<String>,
    signing_key: [u8; 32],
    tls_key: Arc<dyn KeyProvider>,
    hpke: Box<dyn HpkeKey>,
    evidence: Box<dyn Evidence>,
    dev_plain_http: bool,
    seeds: Arc<SeedBook>,
    running: Mutex<Running>,
    last_contact: Mutex<Instant>,
    stopping: AtomicBool,
}

impl fmt::Debug for Fleet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fleet")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// What a sealed window's manifest says about the Fleet.
#[derive(Clone, Debug)]
pub struct Stamp {
    pub identity: Identity,
    pub capture: CaptureInfo,
    pub observed: Observed,
}

impl Fleet {
    /// Picks up the enrolment kept in `opts.dir`, or enrols if there is
    /// none. Kept state needs no network, so a Collector that restarts
    /// with the channel cut goes on capturing.
    pub fn open(opts: FleetOptions) -> Result<Arc<Self>, FleetError> {
        make_private_dir(&opts.dir)?;
        let root =
            VerifyingKey::from_bytes(&opts.root).map_err(|_| bad("--fleet-root is not an Ed25519 key"))?;
        let tls_key: Arc<dyn KeyProvider> = Arc::new(SoftwareKey::open_or_create(&opts.dir.join("tls.key"))?);
        let hpke: Box<dyn HpkeKey> = Box::new(SoftwareHpkeKey::open_or_create(&opts.dir.join("hpke.key"))?);
        let roots = client::read_roots(&opts.ca)?;
        let enrolment = Enrolment {
            url: &opts.url,
            roots: &roots,
            root: &root,
            signing_key: &opts.signing_key,
            tls_key: &tls_key,
            hpke: &*hpke,
            evidence: &*opts.evidence,
            join_token: opts.join_token.as_deref(),
            dev_plain_http: opts.dev_plain_http,
        };
        let seeds = Arc::new(SeedBook::default());
        let stored = match std::fs::read(opts.dir.join(STATE)) {
            Ok(text) => serde_json::from_slice::<Stored>(&text).map_err(bad)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if opts.join_token.is_none() {
                    return Err(FleetError::NoToken);
                }
                let plain = client::client_config(roots.clone(), None)?;
                let deadline = Instant::now() + TIMEOUT;
                let issued = enrolment.attest(None, plain, &mut || deadline)?;
                info!(member = %issued.member, site = %issued.site, "enrolled in the Fleet");
                enrolment.first_state(issued)?
            }
            Err(e) => return Err(e.into()),
        };
        let mut running = enrolment.running(stored.clone())?;
        // Seeds are checked and opened here, as when they arrived.
        running.stored.seeds.clear();
        for held in &stored.seeds {
            let open = open_seed(&held.seed, &root, &stored.member, &*hpke)?;
            let from_ns = seeds
                .add(open.epoch, held.from_ns, open.seed)
                .ok_or_else(|| bad("seed epochs out of order"))?;
            running.stored.seeds.push(HeldSeed {
                seed: held.seed.clone(),
                from_ns,
            });
        }
        if seeds.latest().is_none() {
            return Err(bad("no seed epoch"));
        }
        write_state(&opts.dir, &running.stored)?;
        Ok(Arc::new(Fleet {
            url: opts.url,
            roots,
            root,
            dir: opts.dir,
            join_token: opts.join_token,
            signing_key: opts.signing_key,
            tls_key,
            hpke,
            evidence: opts.evidence,
            dev_plain_http: opts.dev_plain_http,
            seeds,
            running: Mutex::new(running),
            last_contact: Mutex::new(Instant::now()),
            stopping: AtomicBool::new(false),
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Running> {
        self.running.lock().expect("fleet state")
    }

    /// The Fleet's name for this Collector: `{collector}` in object keys.
    pub fn member(&self) -> String {
        self.lock().stored.member.clone()
    }

    /// The `{site}` of object keys.
    pub fn site(&self) -> String {
        self.lock().stored.site.clone()
    }

    pub fn seeds(&self) -> Arc<SeedBook> {
        self.seeds.clone()
    }

    /// The ingest, as the config in force names it, with the current
    /// certificate.
    pub fn ingest(&self) -> Endpoint {
        self.lock().ingest.clone()
    }

    /// Whether the channel has failed for long enough to count as cut.
    pub fn channel_cut(&self) -> bool {
        let poll = Duration::from_millis(self.lock().config.poll_ms);
        self.last_contact.lock().expect("fleet contact").elapsed() > poll * CUT_AFTER_POLLS
    }

    /// Called as window `window_start_ns` is sealed: puts the config in
    /// force into `capture` and says what the manifest should report. A
    /// window is cut when it is sealed, so one config covers all of it.
    pub fn seal(&self, window_start_ns: u64, capture: &mut CaptureConfig) -> Stamp {
        let config_hash = {
            let running = self.lock();
            capture.rate = running.config.capture_rate;
            capture.truncate_to = running.config.truncate_to;
            capture.alarm_cap_bytes = running.config.alarm_cap;
            running.config_hash.clone()
        };
        Stamp {
            identity: Identity { config: config_hash },
            capture: CaptureInfo {
                epoch: self.seeds.epoch_of(window_start_ns).map(|(epoch, _)| epoch),
            },
            observed: Observed {
                channel_cut: self.channel_cut(),
            },
        }
    }

    fn enrolment(&self) -> Enrolment<'_> {
        Enrolment {
            url: &self.url,
            roots: &self.roots,
            root: &self.root,
            signing_key: &self.signing_key,
            tls_key: &self.tls_key,
            hpke: &*self.hpke,
            evidence: &*self.evidence,
            join_token: self.join_token.as_deref(),
            dev_plain_http: self.dev_plain_http,
        }
    }

    fn until(&self) -> impl FnMut() -> Instant + '_ {
        let deadline = Instant::now() + TIMEOUT;
        move || {
            if self.stopping.load(Ordering::Relaxed) {
                Instant::now()
            } else {
                deadline
            }
        }
    }

    /// One heartbeat, bringing back what is new.
    fn pull(&self) -> Result<(), FleetError> {
        let (body, tls, member) = {
            let running = self.lock();
            let body = serde_json::json!({
                "member": running.stored.member,
                "config_version": running.config.version,
                "config_hash": running.config_hash,
                "seed_epoch": self.seeds.latest(),
                "cert_not_after": running.stored.not_after,
            });
            (body, running.tls.clone(), running.stored.member.clone())
        };
        let endpoint = self.enrolment().endpoint(tls)?;
        let pulled: Pulled = call(&endpoint, "/pull", &body, &mut self.until())?;
        debug!(member = %member, "heartbeat");
        self.take(pulled.config, pulled.seeds)
    }

    /// Applies what the Fleet sent. Anything that fails its checks is left
    /// out and logged: the run goes on with what it has.
    fn take(&self, config: Option<Signed>, seeds: Vec<Signed>) -> Result<(), FleetError> {
        let mut running = self.lock();
        let mut changed = false;
        if let Some(signed) = config {
            match self.enrolment().newer(&running, signed) {
                Ok(Some(next)) => {
                    info!(version = next.config.version, hash = %next.config_hash, "new config");
                    *running = next;
                    changed = true;
                }
                Ok(None) => debug!("config not newer; left alone"),
                Err(e) => error!(error = %e, "config refused"),
            }
        }
        let member = running.stored.member.clone();
        for signed in seeds {
            let open = match open_seed(&signed, &self.root, &member, &*self.hpke) {
                Ok(open) => open,
                Err(e) => {
                    error!(error = %e, "seed epoch refused");
                    continue;
                }
            };
            // `None` is an epoch already held: the Fleet may send it again.
            if let Some(from_ns) = self.seeds.add(open.epoch, open.from_ns, open.seed) {
                info!(epoch = open.epoch, from_ns, "new seed epoch");
                running.stored.seeds.push(HeldSeed {
                    seed: signed,
                    from_ns,
                });
                changed = true;
            }
        }
        if changed {
            write_state(&self.dir, &running.stored)?;
        }
        Ok(())
    }

    /// Renews the mTLS certificate with fresh evidence. A certificate that
    /// has run out can't open the connection, so that one goes without.
    fn renew(&self) -> Result<(), FleetError> {
        let (member, expired, tls) = {
            let running = self.lock();
            let expired = now_s() >= running.stored.not_after;
            (running.stored.member.clone(), expired, running.tls.clone())
        };
        let tls = if expired {
            client::client_config(self.roots.clone(), None)?
        } else {
            tls
        };
        let enrolment = self.enrolment();
        let issued = enrolment.attest(Some(&member), tls, &mut self.until())?;
        if issued.member != member {
            return Err(bad(format!("renewal is for another member, {}", issued.member)));
        }
        let cert: MemberCert = issued.fleet_cert.verify(&self.root, CERT_CONTEXT)?;
        enrolment.check_cert(&cert, &issued)?;
        let (config, seeds) = (issued.config.clone(), issued.seeds.clone());
        {
            let mut running = self.lock();
            let mut stored = running.stored.clone();
            stored.fleet_cert = issued.fleet_cert;
            stored.tls_chain = issued.tls_chain;
            stored.not_before = issued.not_before;
            stored.not_after = issued.not_after;
            running.tls = enrolment.tls(&stored)?;
            running.ingest = enrolment.reach(&running.config.ingest, running.tls.clone())?;
            running.stored = stored;
            write_state(&self.dir, &running.stored)?;
            info!(not_after = running.stored.not_after, "mTLS certificate renewed");
        }
        self.take(Some(config), seeds)
    }

    /// Past two thirds of the certificate's life.
    fn renewal_due(&self) -> bool {
        let running = self.lock();
        let (from, to) = (running.stored.not_before, running.stored.not_after);
        now_s() >= from + to.saturating_sub(from) / 3 * 2
    }

    fn tick(&self) -> Result<(), FleetError> {
        if self.renewal_due() {
            if let Err(e) = self.renew() {
                warn!(error = %e, "mTLS certificate not renewed; retrying");
            }
        }
        self.pull()
    }
}

/// What enrolling and checking its results take.
struct Enrolment<'a> {
    url: &'a str,
    roots: &'a RootCertStore,
    root: &'a VerifyingKey,
    signing_key: &'a [u8; 32],
    tls_key: &'a Arc<dyn KeyProvider>,
    hpke: &'a dyn HpkeKey,
    evidence: &'a dyn Evidence,
    join_token: Option<&'a str>,
    dev_plain_http: bool,
}

impl Enrolment<'_> {
    fn endpoint(&self, tls: Arc<ClientConfig>) -> Result<Endpoint, FleetError> {
        self.reach(self.url, tls)
    }

    /// `url` over `tls`; plain only in development.
    fn reach(&self, url: &str, tls: Arc<ClientConfig>) -> Result<Endpoint, FleetError> {
        if url.starts_with("http://") {
            if !self.dev_plain_http {
                return Err(FleetError::Plain(url.to_string()));
            }
            return Ok(Endpoint::plain(url)?);
        }
        Ok(Endpoint::tls(url, tls)?)
    }

    /// Hello, nonce, evidence: for a first enrolment and for each renewal.
    fn attest(
        &self,
        member: Option<&str>,
        tls: Arc<ClientConfig>,
        until: &mut dyn FnMut() -> Instant,
    ) -> Result<Issued, FleetError> {
        let endpoint = self.endpoint(tls)?;
        let hello: Hello = call(
            &endpoint,
            "/hello",
            &serde_json::json!({ "kind": KIND, "member": member }),
            until,
        )?;
        let nonce = decode_hex(&hello.nonce).ok_or_else(|| bad("nonce is not hex"))?;
        let (tls_public, hpke_public) = (self.tls_key.public_key(), self.hpke.public_key());
        let data = report_data(self.signing_key, &tls_public, &hpke_public, &nonce);
        let quote = self.evidence.quote(&data)?;
        if quote.kind == "stub" {
            warn!("attestation evidence is a stub: a real Fleet refuses it");
        }
        let keys = Keys {
            signing: hex(self.signing_key),
            tls: hex(&tls_public),
            hpke: hex(&hpke_public),
        };
        call(
            &endpoint,
            "/enrol",
            &serde_json::json!({
                "kind": KIND,
                "member": member,
                "nonce": hello.nonce,
                "keys": keys,
                "evidence": quote,
                "join_token": self.join_token,
            }),
            until,
        )
    }

    fn check_cert(&self, cert: &MemberCert, issued: &Issued) -> Result<(), FleetError> {
        if cert.member != issued.member || cert.site != issued.site {
            return Err(bad("Fleet certificate is for another member"));
        }
        if cert.signing_key != hex(self.signing_key) {
            return Err(bad("Fleet certificate is for another signing key"));
        }
        Ok(())
    }

    /// What a first enrolment leaves, checked as a whole: one that fails
    /// any check leaves nothing behind.
    fn first_state(&self, issued: Issued) -> Result<Stored, FleetError> {
        let cert: MemberCert = issued.fleet_cert.verify(self.root, CERT_CONTEXT)?;
        self.check_cert(&cert, &issued)?;
        let mut seeds = Vec::with_capacity(issued.seeds.len());
        for seed in issued.seeds {
            let from_ns = open_seed(&seed, self.root, &issued.member, self.hpke)?.from_ns;
            seeds.push(HeldSeed { seed, from_ns });
        }
        Ok(Stored {
            member: issued.member,
            site: issued.site,
            fleet_cert: issued.fleet_cert,
            tls_chain: issued.tls_chain,
            not_before: issued.not_before,
            not_after: issued.not_after,
            config: issued.config,
            seeds,
        })
    }

    fn tls(&self, stored: &Stored) -> Result<Arc<ClientConfig>, FleetError> {
        let chain = stored
            .tls_chain
            .iter()
            .map(|c| decode_hex(c).map(CertificateDer::from))
            .collect::<Option<Vec<_>>>()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| bad("mTLS certificate is not hex DER"))?;
        Ok(client::client_config(
            self.roots.clone(),
            Some((chain, self.tls_key.clone())),
        )?)
    }

    /// Checks config that was stored or just received, and builds what
    /// runs on it.
    fn running(&self, stored: Stored) -> Result<Running, FleetError> {
        let cert: MemberCert = stored.fleet_cert.verify(self.root, CERT_CONTEXT)?;
        if cert.member != stored.member || cert.signing_key != hex(self.signing_key) {
            return Err(bad("kept Fleet certificate is for another member or key"));
        }
        let config = self.config(&stored.config, &stored.member)?;
        let tls = self.tls(&stored)?;
        Ok(Running {
            config_hash: mh::of(stored.config.payload.as_bytes()),
            ingest: self.reach(&config.ingest, tls.clone())?,
            config,
            tls,
            stored,
        })
    }

    fn config(&self, signed: &Signed, member: &str) -> Result<Config, FleetError> {
        let config: Config = signed.verify(self.root, CONFIG_CONTEXT)?;
        if config.member != member {
            return Err(bad(format!("config is for another member, {}", config.member)));
        }
        if !(0.0..=1.0).contains(&config.capture_rate) {
            return Err(bad(format!(
                "capture_rate {} is not between 0 and 1",
                config.capture_rate
            )));
        }
        if config.poll_ms == 0 {
            return Err(bad("poll_ms is zero"));
        }
        Ok(config)
    }

    /// What runs on `signed`, if it passes and is newer than what runs now.
    fn newer(&self, running: &Running, signed: Signed) -> Result<Option<Running>, FleetError> {
        let config = self.config(&signed, &running.stored.member)?;
        if config.version <= running.config.version {
            return Ok(None);
        }
        Ok(Some(Running {
            config_hash: mh::of(signed.payload.as_bytes()),
            ingest: self.reach(&config.ingest, running.tls.clone())?,
            config,
            tls: running.tls.clone(),
            stored: Stored {
                config: signed,
                ..running.stored.clone()
            },
        }))
    }
}

/// A seed epoch out of its seal.
struct OpenSeed {
    epoch: u64,
    from_ns: u64,
    seed: [u8; 32],
}

/// What `signed` holds, once its signature, its member and its seal check
/// out.
fn open_seed(
    signed: &Signed,
    root: &VerifyingKey,
    member: &str,
    hpke: &dyn HpkeKey,
) -> Result<OpenSeed, FleetError> {
    let sealed: SealedSeed = signed.verify(root, SEED_CONTEXT)?;
    if sealed.member != member {
        return Err(bad(format!("seed is for another member, {}", sealed.member)));
    }
    let enc = decode_hex(&sealed.enc).ok_or_else(|| bad("seed enc is not hex"))?;
    let ct = decode_hex(&sealed.ct).ok_or_else(|| bad("seed ct is not hex"))?;
    let aad = seed_aad(member, sealed.epoch);
    let seed = hpke.open(SEED_INFO, aad.as_bytes(), &enc, &ct)?;
    let seed = <[u8; 32]>::try_from(seed).map_err(|_| bad("seed is not 32 bytes"))?;
    Ok(OpenSeed {
        epoch: sealed.epoch,
        from_ns: sealed.from_ns,
        seed,
    })
}

/// HPKE `aad` of a seed.
pub fn seed_aad(member: &str, epoch: u64) -> String {
    format!("{member}/{epoch}")
}

/// One POST to the Fleet, its reply read as `T`.
fn call<T: DeserializeOwned>(
    endpoint: &Endpoint,
    suffix: &str,
    body: &impl Serialize,
    until: &mut dyn FnMut() -> Instant,
) -> Result<T, FleetError> {
    let body = serde_json::to_vec(body).map_err(bad)?;
    let headers = [("Content-Type", "application/json")];
    let (status, reply) = endpoint.post(suffix, &headers, &body, MAX_RESPONSE, until)?;
    match status {
        200 => serde_json::from_slice(&reply).map_err(bad),
        202 => Err(FleetError::Pending),
        408 | 429 | 500..=599 => Err(ClientError::Unavailable(format!("HTTP {status}")).into()),
        _ => Err(FleetError::Refused {
            status,
            body: String::from_utf8_lossy(&reply).chars().take(200).collect(),
        }),
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| parse_hex::<1>(s.get(2 * i..2 * i + 2)?).map(|[b]| b))
        .collect()
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn make_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Replaces [`STATE`] in `dir` atomically, synced.
fn write_state(dir: &Path, stored: &Stored) -> io::Result<()> {
    let tmp = dir.join(format!("{STATE}.tmp"));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = opts.open(&tmp)?;
    file.write_all(&serde_json::to_vec_pretty(stored)?)?;
    file.sync_all()?;
    std::fs::rename(&tmp, dir.join(STATE))?;
    File::open(dir)?.sync_all()
}

/// The channel's thread: heartbeats until told to stop. It never ends the
/// run: a channel that fails is a cut channel, and that shows in the
/// manifests.
pub struct Channel {
    fleet: Arc<Fleet>,
    stop: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

impl Channel {
    /// Polls once, so the run starts on the latest config and even a short
    /// run is heard from, then goes on in the background. With the channel
    /// down that poll can hold the start back by one request timeout.
    pub fn spawn(fleet: Arc<Fleet>) -> io::Result<Self> {
        let mut down = false;
        beat(&fleet, &mut down);
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::Builder::new().name("fleet-channel".into()).spawn({
            let fleet = fleet.clone();
            move || run(&fleet, down, &stopped)
        })?;
        Ok(Channel { fleet, stop, thread })
    }

    /// Stops the channel, cutting a request in flight short.
    pub fn finish(self) {
        self.fleet.stopping.store(true, Ordering::Relaxed);
        drop(self.stop);
        let _ = self.thread.join();
    }
}

/// One poll, logging only when the channel goes down or comes back.
fn beat(fleet: &Fleet, down: &mut bool) {
    match fleet.tick() {
        Ok(()) => {
            *fleet.last_contact.lock().expect("fleet contact") = Instant::now();
            if std::mem::take(down) {
                info!("Fleet channel back");
            }
        }
        Err(e) => {
            if !std::mem::replace(down, true) {
                warn!(error = %e, "Fleet channel down; capturing on with the last config");
            }
        }
    }
}

fn run(fleet: &Fleet, mut down: bool, stopped: &mpsc::Receiver<()>) {
    loop {
        let poll = Duration::from_millis(fleet.lock().config.poll_ms);
        match stopped.recv_timeout(poll) {
            Err(RecvTimeoutError::Timeout) => beat(fleet, &mut down),
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_binds_every_key_and_the_nonce() {
        let base = report_data(&[1; 32], &[2; 32], &[3; 32], b"nonce");
        assert_ne!(base, report_data(&[9; 32], &[2; 32], &[3; 32], b"nonce"));
        assert_ne!(base, report_data(&[1; 32], &[9; 32], &[3; 32], b"nonce"));
        assert_ne!(base, report_data(&[1; 32], &[2; 32], &[9; 32], b"nonce"));
        assert_ne!(base, report_data(&[1; 32], &[2; 32], &[3; 32], b"other"));
    }

    #[test]
    fn hex_is_strict() {
        assert_eq!(decode_hex("00ff"), Some(vec![0, 255]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("0G"), None);
        assert_eq!(decode_hex("é0"), None);
    }
}
