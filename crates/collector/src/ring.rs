//! `RingSource`: live capture through a dumpcap ring buffer (spec §3).
//!
//! Runs `dumpcap -i <if> -b interval:<W> -b printname:stdout -w <dir>/<name>`
//! and reads each file name dumpcap prints once that file is closed, then
//! hands the file to [`FileSource`]. A file is never read while dumpcap is
//! still writing it.
//!
//! **Never `-b files:N`**: dumpcap would delete the oldest files and packets
//! would be lost whenever the Collector falls behind. The Collector deletes
//! local files itself, after upload. [`RingConfig::extra_args`] rejects it.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use crate::source::{CapturedPacket, FileSource, PacketSource, SourceError};

#[derive(Clone, Debug)]
pub struct RingConfig {
    /// The dumpcap binary.
    pub dumpcap: PathBuf,
    /// Capture interface; it becomes the Link id.
    pub interface: String,
    /// Window length `W` in seconds; dumpcap cuts files at multiples of it.
    pub interval_s: u32,
    /// Where dumpcap writes the ring files.
    pub dir: PathBuf,
    /// File name template; dumpcap adds a counter and a timestamp.
    pub file_name: String,
    /// Stop after this many seconds (`-a duration:N`), if set.
    pub autostop_s: Option<u32>,
    /// Further dumpcap arguments, e.g. a capture filter (`-f`).
    pub extra_args: Vec<String>,
}

impl RingConfig {
    pub fn new(interface: impl Into<String>, interval_s: u32, dir: impl Into<PathBuf>) -> Self {
        RingConfig {
            dumpcap: PathBuf::from("dumpcap"),
            interface: interface.into(),
            interval_s,
            dir: dir.into(),
            file_name: "link.pcapng".into(),
            autostop_s: None,
            extra_args: Vec::new(),
        }
    }

    /// The capture filter (`-f`) in [`Self::extra_args`], if any.
    pub fn filter(&self) -> Option<&str> {
        let i = self.extra_args.iter().position(|a| a == "-f")?;
        self.extra_args.get(i + 1).map(String::as_str)
    }

    /// The dumpcap arguments.
    pub fn args(&self) -> Result<Vec<OsString>, SourceError> {
        if self.interval_s == 0 {
            return Err(SourceError::Dumpcap("interval must be positive".into()));
        }
        if self.extra_args.iter().any(|a| a.contains("files:")) {
            return Err(SourceError::Dumpcap(
                "`-b files:N` deletes ring files before they are read; it is never used".into(),
            ));
        }
        let mut args: Vec<OsString> = vec![
            "-q".into(),
            "-i".into(),
            self.interface.clone().into(),
            "-b".into(),
            format!("interval:{}", self.interval_s).into(),
            "-b".into(),
            "printname:stdout".into(),
            "-w".into(),
            self.dir.join(&self.file_name).into(),
        ];
        if let Some(s) = self.autostop_s {
            args.push("-a".into());
            args.push(format!("duration:{s}").into());
        }
        args.extend(self.extra_args.iter().map(OsString::from));
        Ok(args)
    }
}

/// Yields packets from each ring file as dumpcap closes it.
pub struct RingSource<R: BufRead = BufReader<ChildStdout>> {
    names: R,
    child: Option<Child>,
    current: Option<FileSource>,
    files: Vec<PathBuf>,
    done: bool,
    log: Option<PathBuf>,
    /// Drops from the ring files' statistics blocks, then from dumpcap's
    /// final report once it exits.
    drops: Option<u64>,
}

impl RingSource {
    /// Starts dumpcap. Its stderr goes to `<dir>/dumpcap.log`.
    ///
    /// A missing dumpcap gives [`SourceError::DumpcapNotFound`], one the user
    /// may not run gives [`SourceError::DumpcapNotPermitted`]; dumpcap
    /// failing later (e.g. an unknown interface) gives
    /// [`SourceError::DumpcapFailed`] with the end of its log.
    pub fn spawn(cfg: &RingConfig) -> Result<Self, SourceError> {
        let args = cfg.args()?;
        let filter = cfg.filter().unwrap_or("none");
        tracing::info!(interface = %cfg.interface, filter, "dumpcap starting");
        let log_path = cfg.dir.join("dumpcap.log");
        let log = std::fs::File::create(&log_path)
            .map_err(|e| SourceError::Dumpcap(format!("creating log in {}: {e}", cfg.dir.display())))?;
        let mut child = Command::new(&cfg.dumpcap)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(log)
            .spawn()
            .map_err(|e| {
                let program = cfg.dumpcap.clone();
                match e.kind() {
                    ErrorKind::NotFound => SourceError::DumpcapNotFound { program },
                    ErrorKind::PermissionDenied => SourceError::DumpcapNotPermitted { program },
                    _ => SourceError::Dumpcap(format!("starting {}: {e}", cfg.dumpcap.display())),
                }
            })?;
        let stdout = child.stdout.take().expect("piped");
        Ok(RingSource {
            names: BufReader::new(stdout),
            child: Some(child),
            current: None,
            files: Vec::new(),
            done: false,
            log: Some(log_path),
            drops: None,
        })
    }

    /// Process id of dumpcap, e.g. to stop it with SIGINT.
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }
}

impl<R: BufRead> RingSource<R> {
    /// A source fed with closed file names, one per line, from `names`.
    /// This is the handoff `spawn` uses, without a dumpcap process.
    pub fn from_names(names: R) -> Self {
        RingSource {
            names,
            child: None,
            current: None,
            files: Vec::new(),
            done: false,
            log: None,
            drops: None,
        }
    }

    /// Every file read so far, in order.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    fn next_file(&mut self) -> Option<Result<PathBuf, SourceError>> {
        let mut line = String::new();
        loop {
            line.clear();
            match self.names.read_line(&mut line) {
                Ok(0) => return self.wait().map(Err),
                Ok(_) => {
                    let name = line.trim_end_matches(['\n', '\r']);
                    if !name.is_empty() {
                        return Some(Ok(Path::new(name).to_owned()));
                    }
                }
                Err(e) => return Some(Err(SourceError::Dumpcap(format!("reading file names: {e}")))),
            }
        }
    }

    /// Reaps dumpcap; an error if it failed.
    fn wait(&mut self) -> Option<SourceError> {
        let mut child = self.child.take()?;
        let status = child.wait();
        if let Some(n) = self.log.as_deref().and_then(log_drops) {
            self.drops = Some(self.drops.unwrap_or(0).max(n));
        }
        match status {
            Ok(status) if status.success() => {
                tracing::info!(files = self.files.len(), "dumpcap exited");
                None
            }
            Ok(status) => Some(SourceError::DumpcapFailed {
                status,
                log: self.log.as_deref().map(log_tail).unwrap_or_default(),
            }),
            Err(e) => Some(SourceError::Dumpcap(format!("waiting: {e}"))),
        }
    }
}

/// Drops in dumpcap's final report, summed over interfaces:
/// `Packets received/dropped on interface 'lo': 1234/5 (pcap:5/...)`.
fn log_drops(path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut total = None;
    for line in text.lines() {
        let Some((_, counts)) = line.split_once("dropped on interface") else {
            continue;
        };
        let counts = counts.rsplit_once("': ").map_or(counts, |(_, c)| c);
        let counts = counts.split_whitespace().next().unwrap_or_default();
        if let Some(n) = counts.split_once('/').and_then(|(_, d)| d.parse::<u64>().ok()) {
            *total.get_or_insert(0) += n;
        }
    }
    total
}

/// The last few lines dumpcap wrote to its log, without the per-file
/// `File: ...` notices, joined with `; `.
fn log_tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("File: "))
        .collect();
    lines[lines.len().saturating_sub(5)..].join("; ")
}

impl<R: BufRead> PacketSource for RingSource<R> {
    fn next(&mut self) -> Option<Result<CapturedPacket, SourceError>> {
        loop {
            if self.done {
                return None;
            }
            if let Some(file) = &mut self.current {
                match file.next() {
                    Some(item) => return Some(item),
                    None => {
                        if let Some(n) = file.capture_drops() {
                            self.drops = Some(self.drops.unwrap_or(0).max(n));
                        }
                        self.current = None;
                    }
                }
            }
            match self.next_file() {
                Some(Ok(path)) => {
                    tracing::debug!(file = %path.display(), "ring file closed");
                    self.files.push(path.clone());
                    self.current = Some(FileSource::new([path]));
                }
                Some(Err(e)) => {
                    self.done = true;
                    return Some(Err(e));
                }
                None => {
                    self.done = true;
                    return None;
                }
            }
        }
    }

    fn capture_drops(&self) -> Option<u64> {
        let current = self.current.as_ref().and_then(FileSource::capture_drops);
        match (self.drops, current) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }
}

impl<R: BufRead> Drop for RingSource<R> {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_filter_is_passed_to_dumpcap() {
        let mut cfg = RingConfig::new("lo", 10, "/tmp/ring");
        assert_eq!(cfg.filter(), None);
        cfg.extra_args = vec!["-f".into(), "tcp port 11434".into()];
        assert_eq!(cfg.filter(), Some("tcp port 11434"));
        let args = cfg.args().unwrap();
        assert_eq!(args[args.len() - 2..], ["-f", "tcp port 11434"]);
    }

    #[cfg(unix)]
    #[test]
    fn missing_or_forbidden_dumpcap_is_reported() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = RingConfig::new("lo", 1, tmp.path());
        cfg.dumpcap = tmp.path().join("no-such-dumpcap");
        let err = RingSource::spawn(&cfg).err().unwrap();
        assert!(matches!(err, SourceError::DumpcapNotFound { .. }), "{err}");
        assert!(err.to_string().contains("--dumpcap"), "{err}");

        let script = tmp.path().join("not-executable");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).unwrap();
        cfg.dumpcap = script;
        let err = RingSource::spawn(&cfg).err().unwrap();
        assert!(matches!(err, SourceError::DumpcapNotPermitted { .. }), "{err}");
        assert!(err.to_string().contains("wireshark"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn dumpcap_failure_reports_its_log() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("failing-dumpcap");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'Capturing on nosuchif' >&2\necho 'There is no device named \"nosuchif\".' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cfg = RingConfig::new("nosuchif", 1, tmp.path());
        cfg.dumpcap = script;
        let mut ring = RingSource::spawn(&cfg).unwrap();
        let err = ring.next().unwrap().err().unwrap();
        assert!(matches!(err, SourceError::DumpcapFailed { .. }), "{err}");
        assert!(err.to_string().contains("There is no device named"), "{err}");
        assert!(ring.next().is_none());
    }

    #[test]
    fn drops_from_dumpcap_report() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("dumpcap.log");
        std::fs::write(
            &log,
            "Capturing on 'lo'\nFile: /x/link_00001.pcapng\nPackets captured: 30\n\
             Packets received/dropped on interface 'lo': 30/2 (pcap:2/dumpcap:0/flushed:0/ps_ifdrop:0) (93.8%)\n\
             Packets received/dropped on interface 'eth0': 10/1 (pcap:1/dumpcap:0/flushed:0/ps_ifdrop:0) (90.9%)\n",
        )
        .unwrap();
        assert_eq!(log_drops(&log), Some(3));
        std::fs::write(&log, "Capturing on 'lo'\n").unwrap();
        assert_eq!(log_drops(&log), None);
    }

    #[test]
    fn args_never_use_files() {
        let mut cfg = RingConfig::new("lo", 10, "/tmp/x");
        let args: Vec<String> = cfg
            .args()
            .unwrap()
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "-q",
                "-i",
                "lo",
                "-b",
                "interval:10",
                "-b",
                "printname:stdout",
                "-w",
                "/tmp/x/link.pcapng"
            ]
        );
        cfg.extra_args = vec!["-b".into(), "files:3".into()];
        assert!(cfg.args().is_err());
    }
}
