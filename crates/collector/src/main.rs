//! `collector`: run Flow assembly over capture files or a live dumpcap ring.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use collector::fleet::{Channel, Fleet, FleetOptions, StubEvidence};
use collector::observe::{log_summary, Stats};
use collector::output::JsonlSink;
use collector::run::run;
use collector::ship::{self, Ingest, Shipper};
use collector::sign::{parse_hex, KeyProvider, SoftwareKey};
use collector::spool::{Spool, Uploaded, Uploader};
use collector::stats::{serve_metrics, Registry};
use collector::store::{StoreConfig, StoreSink};
use collector::{AssemblerConfig, DecoderConfig, FileSource, Observed, PacketSource, RingConfig, RingSource};

// Each option's help is one line; docs/spec.md ("Command line") has the
// details. README.md shows this help, and tests/readme.rs keeps it in step.
#[derive(Parser)]
#[command(about = "TokenSpectra Collector", next_help_heading = "Global options")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Don't keep HTTP bodies (hashes and tables stay the same)
    #[arg(long, global = true)]
    no_bodies: bool,
    /// More log detail: -v DEBUG, -vv TRACE
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,
    /// Less log detail: -q WARN, -qq ERROR
    #[arg(short, long, action = ArgAction::Count, global = true, conflicts_with = "verbose")]
    quiet: u8,
    /// Log level; overrides -v/-q (RUST_LOG overrides it)
    #[arg(long, global = true, value_enum)]
    log_level: Option<Level>,
    /// Log line format on stdout
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Serve Prometheus metrics here, e.g. 127.0.0.1:9464
    #[arg(long, global = true)]
    metrics_addr: Option<String>,
    /// Object store: a directory or s3://bucket[/prefix] [default: <out>/store]
    #[arg(long, global = true)]
    store: Option<String>,
    /// S3 endpoint; required for s3:// unless AWS_ENDPOINT is set
    #[arg(long, global = true)]
    s3_endpoint: Option<String>,
    /// Local spool for s3:// uploads [default: <out>/spool]
    #[arg(long, global = true)]
    spool: Option<PathBuf>,
    /// Spool cap in MiB; a full spool holds the run back
    #[arg(long, global = true, default_value_t = 4096)]
    spool_max_mib: u64,
    /// Seconds to finish uploads at the end of a run
    #[arg(long, global = true, default_value_t = 30)]
    upload_wait_s: u64,
    /// Fleet URL to enrol with and pull config and seeds from (https://)
    #[arg(long, global = true, requires_all = ["fleet_ca", "fleet_root"])]
    fleet: Option<String>,
    /// PEM file of the CA the Fleet's and ingest's TLS chain to
    #[arg(long, global = true)]
    fleet_ca: Option<PathBuf>,
    /// The Fleet's Ed25519 public key, 64 hex digits
    #[arg(long, global = true)]
    fleet_root: Option<String>,
    /// File holding the site join token; needed to enrol
    #[arg(long, global = true)]
    join_token_file: Option<PathBuf>,
    /// Fleet keys and state [default: <out>/fleet]
    #[arg(long, global = true)]
    fleet_dir: Option<PathBuf>,
    /// Dev only: allow plain http:// to the ingest and the Fleet
    #[arg(long, global = true)]
    dev_plain_http: bool,
    /// Dev only: plain http:// ingest URL; with --fleet, config names it
    #[arg(long, global = true, conflicts_with = "fleet")]
    ingest: Option<String>,
    /// Seconds to finish shipping manifests at the end of a run
    #[arg(long, global = true, default_value_t = 30)]
    ship_wait_s: u64,
    /// Manifest signing key, made if missing [default: <out>/signing.key]
    #[arg(long, global = true)]
    signing_key: Option<PathBuf>,
    /// The {site} part of object keys
    #[arg(long, global = true, default_value = "local")]
    site: String,
    /// The {collector} part of object keys
    #[arg(long, global = true, default_value = "local")]
    collector_id: String,
    /// Capture Rate: share of Request Workunits kept in full (0 to 1); --fleet's config wins
    #[arg(long, global = true, default_value_t = 1.0)]
    capture_rate: f64,
    /// Dev only: Capture Rate key, 64 hex digits; --fleet uses seeds
    #[arg(long, global = true, conflicts_with = "fleet")]
    capture_key: Option<String>,
    /// Captured bytes left in a truncated packet
    #[arg(long, global = true, default_value_t = 128)]
    truncate_to: u32,
    /// Alarm-packet bytes kept in full per Flow per Slice
    #[arg(long, global = true, default_value_t = 16 << 20)]
    alarm_cap: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Cmd {
    /// Assemble Flows from .pcap/.pcapng files, in the order given
    Files {
        /// Window (Slice) length in seconds
        #[arg(short, long, default_value_t = 10)]
        window_s: u32,
        /// Output directory
        #[arg(short, long, default_value = "ts-captures")]
        out: PathBuf,
        /// Capture files
        files: Vec<PathBuf>,
    },
    /// Rebuild by-exchange/ in an output directory
    Views {
        /// Output directory
        #[arg(default_value = "ts-captures")]
        out: PathBuf,
    },
    /// POST the manifests not shipped yet to --ingest
    Ship {
        /// Output directory
        #[arg(default_value = "ts-captures")]
        out: PathBuf,
    },
    /// Upload what the spool still holds to an s3:// --store
    Upload {
        /// Output directory
        #[arg(default_value = "ts-captures")]
        out: PathBuf,
    },
    /// Capture live through a dumpcap ring buffer
    Ring {
        /// Window (Slice) length in seconds; also dumpcap's ring interval
        #[arg(short, long, default_value_t = 10)]
        window_s: u32,
        /// Capture interface; it becomes the Link id
        #[arg(short, long)]
        interface: String,
        /// Ring file directory [default: <tmp>/tokenspectra-ring-<interface>]
        #[arg(short = 'd', long)]
        ring_dir: Option<PathBuf>,
        /// Stop after this many seconds
        #[arg(short = 't', long)]
        duration_s: Option<u32>,
        /// Capture filter (dumpcap -f)
        #[arg(short, long)]
        filter: Option<String>,
        /// Kernel capture buffer in MiB (dumpcap -B)
        #[arg(short = 'B', long)]
        buffer_mib: Option<u32>,
        /// The dumpcap binary
        #[arg(long, default_value = "dumpcap")]
        dumpcap: PathBuf,
        /// Output directory
        #[arg(short, long, default_value = "ts-captures")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(&cli);
    match real_main(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Logs go to stdout. They are diagnostics, never part of the outputs.
fn init_logging(cli: &Cli) {
    let level = cli.log_level.unwrap_or(match (cli.verbose, cli.quiet) {
        (0, 0) => Level::Info,
        (1, _) => Level::Debug,
        (_, 0) => Level::Trace,
        (_, 1) => Level::Warn,
        _ => Level::Error,
    });
    let level = match level {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    };
    let filter = match std::env::var("RUST_LOG") {
        Ok(v) if !v.trim().is_empty() => EnvFilter::new(v),
        _ => EnvFilter::new(level),
    };
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .with_target(false);
    match cli.log_format {
        LogFormat::Text => fmt.with_ansi(std::io::stdout().is_terminal()).init(),
        LogFormat::Json => fmt.json().flatten_event(true).init(),
    }
}

fn log_uploaded(u: &Uploaded) {
    if u.left == 0 {
        info!(objects = u.objects, bytes = u.bytes, "spool uploaded");
    } else {
        warn!(
            objects = u.objects,
            bytes = u.bytes,
            left = u.left,
            left_bytes = u.left_bytes,
            "spool not empty: the next run or `collector upload` sends the rest"
        );
    }
}

/// A 32-byte key from 64 hex digits.
fn parse_key(hex: &str) -> Result<[u8; 32], String> {
    let bad = || "--capture-key must be 64 hex digits".to_string();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(bad());
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(key)
}

/// The ingest of a run without a Fleet: for development, so plain only.
fn dev_ingest(cli: &Cli) -> Result<Option<Ingest>, Box<dyn std::error::Error>> {
    let Some(url) = cli.ingest.as_deref() else {
        return Ok(None);
    };
    if !cli.dev_plain_http {
        return Err(format!(
            "--ingest {url}: the ingest is mTLS, with the certificate --fleet brings; plain http:// needs --dev-plain-http"
        )
        .into());
    }
    Ok(Some(Ingest::plain(url)?))
}

fn signing_key_path(flag: Option<&Path>, out: &Path) -> PathBuf {
    flag.map_or_else(|| out.join("signing.key"), Path::to_path_buf)
}

/// Picks up this Collector's enrolment in the Fleet, or enrols it.
fn open_fleet(cli: &Cli, url: &str, out: &Path) -> Result<Arc<Fleet>, Box<dyn std::error::Error>> {
    let root = cli.fleet_root.as_deref().and_then(parse_hex::<32>);
    let root = root.ok_or("--fleet-root must be 64 hex digits")?;
    let ca = cli.fleet_ca.clone().ok_or("--fleet needs --fleet-ca")?;
    std::fs::create_dir_all(out)?;
    let key_path = signing_key_path(cli.signing_key.as_deref(), out);
    let key = SoftwareKey::open_or_create(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    let join_token = cli
        .join_token_file
        .as_ref()
        .map(|p| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display())))
        .transpose()?
        .map(|t| t.trim().to_string());
    Ok(Fleet::open(FleetOptions {
        url: url.to_string(),
        ca,
        root,
        dir: cli.fleet_dir.clone().unwrap_or_else(|| out.join("fleet")),
        join_token,
        signing_key: key.public_key(),
        evidence: Box::new(StubEvidence),
        dev_plain_http: cli.dev_plain_http,
    })?)
}

fn real_main(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let decoder_cfg = DecoderConfig {
        keep_bodies: !cli.no_bodies,
        ..DecoderConfig::default()
    };
    let mut dumpcap_pid = None;
    let ingest = dev_ingest(&cli)?;
    // Enrolled before anything is captured: a Collector the Fleet won't
    // have doesn't start. One enrolled before starts with the channel cut.
    let fleet = match (&cli.cmd, cli.fleet.as_deref()) {
        (Cmd::Files { out, .. } | Cmd::Ring { out, .. } | Cmd::Ship { out }, Some(url)) => {
            Some(open_fleet(&cli, url, out)?)
        }
        _ => None,
    };
    // An s3:// store without a named endpoint refuses to start, before
    // capture begins or anything is written.
    let s3_endpoint = match cli.store.as_deref() {
        Some(s) if collector::store::is_remote(s) => Some(collector::store::s3_endpoint(
            cli.s3_endpoint.as_deref(),
            std::env::var("AWS_ENDPOINT").ok().as_deref(),
        )?),
        _ => None,
    };
    let s3_endpoint = s3_endpoint.as_deref();
    let (mut source, window_s, out): (Box<dyn PacketSource>, u32, PathBuf) = match cli.cmd {
        Cmd::Files { window_s, out, files } => (Box::new(FileSource::new(files)), window_s, out),
        Cmd::Views { out } => {
            let s = collector::views::write(&out)?;
            info!(links = s.links, merged = s.merged, out = %out.display(), "views written");
            return Ok(());
        }
        Cmd::Ship { out } => {
            // The channel first: a certificate that ran out during a long
            // cut renews before the first line, and a long drain goes on
            // renewing.
            let channel = fleet.clone().map(Channel::spawn).transpose()?;
            let ingest: Box<dyn Fn() -> Ingest> = match (fleet, ingest) {
                (Some(f), _) => Box::new(move || f.ingest()),
                (None, Some(i)) => Box::new(move || i.clone()),
                (None, None) => return Err("`collector ship` needs --fleet or --ingest".into()),
            };
            let shipped = ship::ship_from(&out, &*ingest, Duration::from_secs(10));
            if let Some(channel) = channel {
                channel.finish();
            }
            let s = shipped?;
            // No deadline here, so the count is always known.
            info!(
                sent = s.sent,
                pending = s.pending.unwrap_or_default(),
                "manifests shipped"
            );
            return Ok(());
        }
        Cmd::Upload { out } => {
            let store = cli.store.as_deref().filter(|s| collector::store::is_remote(s));
            let store = store.ok_or("`collector upload` needs an s3:// --store")?;
            let remote = collector::store::open(store, s3_endpoint)?;
            let spool = Spool::open(
                &cli.spool.clone().unwrap_or_else(|| out.join("spool")),
                u64::MAX,
                None,
            )?;
            let (objects, bytes) = spool.pending();
            info!(objects, bytes, "uploading the spool");
            let uploader = Uploader::spawn(spool, remote)?;
            log_uploaded(&uploader.finish(Duration::from_secs(cli.upload_wait_s))?);
            return Ok(());
        }
        Cmd::Ring {
            window_s,
            interface,
            ring_dir,
            duration_s,
            filter,
            buffer_mib,
            dumpcap,
            out,
        } => {
            let ring_dir = ring_dir
                .unwrap_or_else(|| std::env::temp_dir().join(format!("tokenspectra-ring-{interface}")));
            std::fs::create_dir_all(&ring_dir)?;
            let mut cfg = RingConfig::new(interface, window_s, ring_dir);
            cfg.autostop_s = duration_s;
            cfg.dumpcap = dumpcap;
            if let Some(f) = filter {
                cfg.extra_args.extend(["-f".into(), f]);
            }
            if let Some(b) = buffer_mib {
                cfg.extra_args.extend(["-B".into(), b.to_string()]);
            }
            let ring = RingSource::spawn(&cfg)?;
            dumpcap_pid = ring.pid();
            (Box::new(ring), window_s, out)
        }
    };
    if window_s == 0 {
        return Err("window must be positive".into());
    }
    let window_ns = u64::from(window_s) * 1_000_000_000;
    let mut store_cfg = StoreConfig::new(window_ns);
    store_cfg.site = fleet.as_ref().map_or_else(|| cli.site.clone(), |f| f.site());
    store_cfg.collector = fleet
        .as_ref()
        .map_or_else(|| cli.collector_id.clone(), |f| f.member());
    store_cfg.capture.rate = cli.capture_rate;
    store_cfg.capture.truncate_to = cli.truncate_to;
    store_cfg.capture.alarm_cap_bytes = cli.alarm_cap;
    store_cfg.capture.key = cli.capture_key.as_deref().map(parse_key).transpose()?;
    store_cfg.capture.seeds = fleet.as_ref().map(|f| f.seeds());
    store_cfg.fleet = fleet.clone();
    if !(0.0..=1.0).contains(&cli.capture_rate) {
        return Err("--capture-rate must be between 0 and 1".into());
    }
    if cli.capture_rate < 1.0 && store_cfg.capture.key.is_none() && fleet.is_none() {
        return Err("--capture-rate below 1 needs --capture-key: the draw must be unpredictable".into());
    }
    std::fs::create_dir_all(&out)?;
    let store_url = cli
        .store
        .clone()
        .unwrap_or_else(|| out.join("store").display().to_string());
    let registry = Registry::new();
    // A remote store is written through the spool, inside the boundary.
    let spooled = if collector::store::is_remote(&store_url) {
        let remote = collector::store::open(&store_url, s3_endpoint)?;
        let dir = cli.spool.clone().unwrap_or_else(|| out.join("spool"));
        let spool = Spool::open(&dir, cli.spool_max_mib << 20, Some(registry.clone()))?;
        let (objects, bytes) = spool.pending();
        if objects > 0 {
            info!(
                objects,
                bytes, "the spool holds objects from a past run; uploading them first"
            );
        }
        let uploader = Uploader::spawn(spool.clone(), remote)?;
        Some((spool, uploader))
    } else {
        None
    };
    if let Some(addr) = &cli.metrics_addr {
        let bound = serve_metrics(addr.as_str(), registry.clone())
            .map_err(|e| format!("--metrics-addr {addr}: {e}"))?;
        info!(url = %format_args!("http://{bound}/metrics"), "serving metrics");
    }
    #[cfg(unix)]
    let _triggers = match collector::observe::triggers::spawn(
        registry.clone(),
        cli.log_format == LogFormat::Json,
        dumpcap_pid,
        spooled.as_ref().map(|(spool, _)| {
            let spool = spool.clone();
            Box::new(move || spool.stop()) as Box<dyn Fn() + Send>
        }),
    ) {
        Ok(t) => {
            tracing::debug!(
                keys = t.keys,
                "snapshot on SIGUSR1, and on `s` or Enter with keys"
            );
            Some(t)
        }
        Err(e) => {
            warn!(error = %e, "no snapshot triggers");
            None
        }
    };
    let key_path = signing_key_path(cli.signing_key.as_deref(), &out);
    let key = SoftwareKey::open_or_create(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    info!(
        key = %collector::sign::hex(&key.public_key()),
        path = %key_path.display(),
        "manifests signed with a software key"
    );
    let mut sink = JsonlSink::create(&out, Box::new(key))?;
    let shipper = match &fleet {
        Some(f) => {
            let f = f.clone();
            let ingest = Box::new(move || f.ingest());
            Some(Shipper::spawn_with(out.clone(), ingest, Duration::from_secs(1))?)
        }
        None => ingest
            .map(|i| Shipper::spawn(out.clone(), i, Duration::from_secs(1)))
            .transpose()?,
    };
    let channel = fleet.clone().map(Channel::spawn).transpose()?;
    let mut store = match &spooled {
        Some((spool, _)) => StoreSink::spooled(&mut sink, spool.clone(), store_cfg, Some(registry.clone())),
        None => StoreSink::new(
            &mut sink,
            collector::store::open(&store_url, s3_endpoint)?,
            store_cfg,
            Some(registry.clone()),
        ),
    };
    run(
        source.as_mut(),
        window_ns,
        AssemblerConfig::default(),
        decoder_cfg,
        &mut Observed::new(&mut store, Stats::new(registry.clone())),
    )?;
    let stored = store.finish();
    // The uploader gets its time even when the run failed: what is
    // spooled is evidence all the same.
    if let Some((_, uploader)) = spooled {
        let uploaded = uploader.finish(Duration::from_secs(cli.upload_wait_s));
        if let Ok(u) = &uploaded {
            log_uploaded(u);
        }
        stored.as_ref().map_err(|e| e.to_string())?;
        uploaded?;
    }
    let stored = stored?;
    sink.finish()?;
    info!(
        store = %store_url,
        chunks = stored.chunks,
        packs = stored.packs,
        index_files = stored.index_files,
        "object store written"
    );
    // Views for people, derived from the tables and bodies just written.
    if !cli.no_bodies {
        collector::views::write(&out)?;
    }
    if let Some(shipper) = shipper {
        ship::log_outcome(&shipper.finish(Duration::from_secs(cli.ship_wait_s)), &out);
    }
    if let Some(channel) = channel {
        channel.finish();
    }
    log_summary(&registry.snapshot(), &out);
    Ok(())
}
