//! A stand-in for the control plane's Fleet (spec §15) and its ingest,
//! over real TLS: a CA, the Fleet key, enrolment that checks the nonce, the
//! report data and the join token, and an ingest that wants a client
//! certificate.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use collector::fleet::{
    report_data, seed_aad, Signed, CERT_CONTEXT, CONFIG_CONTEXT, SEED_CONTEXT, SEED_INFO,
};
use collector::sign::{hex, parse_hex};
use ed25519_dalek::{Signer, SigningKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeS, Serializable};
use rcgen::{CertificateParams, Issuer, KeyPair, PublicKeyData, SignatureAlgorithm, PKCS_ED25519};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};

pub const TOKEN: &str = "join-token";
pub const MEMBER: &str = "member-1";
pub const SITE: &str = "site-a";

/// How the Fleet answers an enrolment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Issue,
    Pending,
    Refuse,
    /// A Fleet certificate signed by some other key.
    ForgedCert,
    /// A Fleet certificate for some other signing key.
    OtherKeyCert,
}

/// One accepted attestation, as the Fleet saw it.
#[derive(Clone, Debug)]
pub struct Attested {
    pub member: Option<String>,
    pub nonce: String,
    pub client_cert: bool,
    pub keys: Value,
}

pub struct State {
    pub answer: Answer,
    pub nonces: HashSet<String>,
    pub attested: Vec<Attested>,
    /// The mTLS validity to issue, as seconds from now, in the leaf and in
    /// the reply.
    pub cert_from: i64,
    pub cert_to: i64,
    pub config: Value,
    /// What the next pull brings.
    pub next_config: Option<Signed>,
    pub next_seeds: Vec<Signed>,
    pub seeds: Vec<(u64, u64, [u8; 32])>,
    pub pulls: Vec<Value>,
    pub windows: BTreeMap<String, Vec<u8>>,
    pub hpke_key: Option<[u8; 32]>,
}

pub struct MockFleet {
    pub url: String,
    pub ingest_url: String,
    pub ca: PathBuf,
    pub root: SigningKey,
    pub state: Arc<Mutex<State>>,
    /// Connections are dropped at once: the Operator cut the channel.
    pub cut: Arc<AtomicBool>,
    client_ca: Arc<(CertificateParams, KeyPair)>,
    _dir: tempfile::TempDir,
}

struct RawEd25519(Vec<u8>);

impl PublicKeyData for RawEd25519 {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

pub fn sign(root: &SigningKey, context: &[u8], payload: &Value) -> Signed {
    let payload = payload.to_string();
    let sig = root.sign(&[context, payload.as_bytes()].concat()).to_bytes();
    Signed {
        payload,
        sig: hex(&sig),
    }
}

/// A seed epoch sealed to `hpke_key` and signed by `root`.
pub fn seal_seed(
    root: &SigningKey,
    hpke_key: &[u8; 32],
    member: &str,
    epoch: u64,
    from_ns: u64,
    seed: &[u8; 32],
) -> Signed {
    let public = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(hpke_key).unwrap();
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &public,
        SEED_INFO,
        seed,
        seed_aad(member, epoch).as_bytes(),
    )
    .unwrap();
    let payload = json!({
        "member": member, "epoch": epoch, "from_ns": from_ns,
        "enc": hex(&enc.to_bytes()), "ct": hex(&ct),
    });
    sign(root, SEED_CONTEXT, &payload)
}

pub fn now_s() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

impl MockFleet {
    pub fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, ca_cert.pem()).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server_cert = {
            let issuer = Issuer::from_params(&ca_params, &ca_key);
            CertificateParams::new(vec!["127.0.0.1".to_string()])
                .unwrap()
                .signed_by(&server_key, &issuer)
                .unwrap()
        };
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca_cert.der().to_vec())).unwrap();
        let provider = Arc::new(aws_lc_rs::default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .allow_unauthenticated()
            .build()
            .unwrap();
        let tls = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(server_cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("https://127.0.0.1:{port}/fleet");
        let ingest_url = format!("https://127.0.0.1:{port}/ingest/windows");
        let root = SigningKey::from_bytes(&[42; 32]);
        let state = Arc::new(Mutex::new(State {
            answer: Answer::Issue,
            nonces: HashSet::new(),
            attested: Vec::new(),
            cert_from: -60,
            cert_to: 3600,
            config: json!({
                "version": 1, "member": MEMBER, "ingest": ingest_url,
                "capture_rate": 1.0, "truncate_to": 128, "alarm_cap": 1 << 24, "poll_ms": 20,
            }),
            next_config: None,
            next_seeds: Vec::new(),
            seeds: vec![(1, 0, [7; 32])],
            pulls: Vec::new(),
            windows: BTreeMap::new(),
            hpke_key: None,
        }));
        let cut = Arc::new(AtomicBool::new(false));
        let client_ca = Arc::new((ca_params, ca_key));
        let server = Server {
            root: root.clone(),
            state: state.clone(),
            client_ca: client_ca.clone(),
        };
        let (tls, down) = (Arc::new(tls), cut.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                if down.load(Ordering::Relaxed) {
                    let _ = conn.shutdown(Shutdown::Both);
                    continue;
                }
                let (tls, server) = (tls.clone(), server.clone());
                std::thread::spawn(move || {
                    let _ = server.serve(conn, tls);
                });
            }
        });
        MockFleet {
            url,
            ingest_url,
            ca,
            root,
            state,
            cut,
            client_ca,
            _dir: dir,
        }
    }

    pub fn root_public(&self) -> [u8; 32] {
        self.root.verifying_key().to_bytes()
    }

    pub fn ca_path(&self) -> &Path {
        &self.ca
    }

    pub fn set_cut(&self, cut: bool) {
        self.cut.store(cut, Ordering::Relaxed);
    }

    /// A config of the Fleet's, signed: the current one with `changes`.
    pub fn signed_config(&self, changes: Value) -> Signed {
        let mut config = self.state.lock().unwrap().config.clone();
        for (k, v) in changes.as_object().unwrap() {
            config[k] = v.clone();
        }
        sign(&self.root, CONFIG_CONTEXT, &config)
    }
}

#[derive(Clone)]
struct Server {
    root: SigningKey,
    state: Arc<Mutex<State>>,
    client_ca: Arc<(CertificateParams, KeyPair)>,
}

impl Server {
    fn serve(&self, conn: TcpStream, tls: Arc<ServerConfig>) -> std::io::Result<()> {
        let mut tls = StreamOwned::new(ServerConnection::new(tls).map_err(std::io::Error::other)?, conn);
        // The handshake, so the peer's certificate is known.
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock)?;
        }
        let client_cert = tls.conn.peer_certificates().is_some();
        let mut reader = BufReader::new(&mut tls);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let (mut key, mut len) = (String::new(), 0usize);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    "idempotency-key" => key = value.trim().to_string(),
                    "content-length" => len = value.trim().parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        let mut body = vec![0; len];
        reader.read_exact(&mut body)?;
        drop(reader);
        let path = request_line.split(' ').nth(1).unwrap_or("").to_string();
        let (status, text) = self.route(&path, &key, &body, client_cert);
        write!(
            tls,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        )?;
        tls.conn.send_close_notify();
        tls.flush()
    }

    fn route(&self, path: &str, key: &str, body: &[u8], client_cert: bool) -> (&'static str, String) {
        let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        // Exact routes under either root, as a real server's would be: a
        // doubled slash is a 404.
        match path.strip_prefix("/fleet").unwrap_or(path) {
            "/hello" => {
                let mut nonce = [0u8; 32];
                getrandom::fill(&mut nonce).unwrap();
                let nonce = hex(&nonce);
                self.state.lock().unwrap().nonces.insert(nonce.clone());
                ("200 OK", json!({ "nonce": nonce }).to_string())
            }
            "/enrol" => self.enrol(&v, client_cert),
            "/pull" if !client_cert => ("403 Forbidden", "no client certificate".into()),
            "/pull" => {
                let mut s = self.state.lock().unwrap();
                s.pulls.push(v);
                let reply = json!({
                    "config": s.next_config.take(),
                    "seeds": std::mem::take(&mut s.next_seeds),
                });
                ("200 OK", reply.to_string())
            }
            "/ingest/windows" if !client_cert => ("403 Forbidden", "no client certificate".into()),
            "/ingest/windows" => {
                self.state
                    .lock()
                    .unwrap()
                    .windows
                    .insert(key.to_string(), body.to_vec());
                ("200 OK", "accepted".into())
            }
            _ => ("404 Not Found", "no such path".into()),
        }
    }

    fn enrol(&self, v: &Value, client_cert: bool) -> (&'static str, String) {
        let mut s = self.state.lock().unwrap();
        let nonce = v["nonce"].as_str().unwrap_or("").to_string();
        // A nonce works once.
        if !s.nonces.remove(&nonce) {
            return ("403 Forbidden", "unknown nonce".into());
        }
        let member = v["member"].as_str().map(String::from);
        if member.is_none() && v["join_token"] != TOKEN {
            return ("403 Forbidden", "bad join token".into());
        }
        let key = |name: &str| parse_hex::<32>(v["keys"][name].as_str().unwrap_or("")).unwrap();
        let (signing, tls_key, hpke_key) = (key("signing"), key("tls"), key("hpke"));
        let nonce_bytes = parse_hex::<32>(&nonce).unwrap();
        let bound = report_data(&signing, &tls_key, &hpke_key, &nonce_bytes);
        if v["evidence"]["kind"] != "stub" || v["evidence"]["quote"] != hex(&bound) {
            return (
                "403 Forbidden",
                "evidence does not bind the keys and nonce".into(),
            );
        }
        match s.answer {
            Answer::Pending => return ("202 Accepted", json!({ "status": "pending" }).to_string()),
            Answer::Refuse => return ("403 Forbidden", "not allowlisted".into()),
            _ => {}
        }
        s.hpke_key = Some(hpke_key);
        s.attested.push(Attested {
            member,
            nonce,
            client_cert,
            keys: v["keys"].clone(),
        });

        let cert_key = if s.answer == Answer::OtherKeyCert {
            [0; 32]
        } else {
            signing
        };
        let cert_payload = json!({ "member": MEMBER, "site": SITE, "signing_key": hex(&cert_key) });
        let signer = if s.answer == Answer::ForgedCert {
            SigningKey::from_bytes(&[1; 32])
        } else {
            self.root.clone()
        };
        let fleet_cert = sign(&signer, CERT_CONTEXT, &cert_payload);

        let (ca_params, ca_key) = &*self.client_ca;
        let issuer = Issuer::from_params(ca_params, ca_key);
        let now = now_s();
        let at = |s: i64| rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs((now + s) as u64);
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        (leaf.not_before, leaf.not_after) = (at(s.cert_from), at(s.cert_to));
        let leaf = leaf.signed_by(&RawEd25519(tls_key.to_vec()), &issuer).unwrap();
        let reply = json!({
            "member": MEMBER,
            "site": SITE,
            "fleet_cert": fleet_cert,
            "tls_chain": [hex(leaf.der())],
            "not_before": now + s.cert_from,
            "not_after": now + s.cert_to,
            "config": sign(&self.root, CONFIG_CONTEXT, &s.config),
            "seeds": s.seeds.iter()
                .map(|(epoch, from, seed)| seal_seed(&self.root, &hpke_key, MEMBER, *epoch, *from, seed))
                .collect::<Vec<_>>(),
        });
        ("200 OK", reply.to_string())
    }
}
