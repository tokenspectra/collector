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
        match child.wait() {
            Ok(status) if status.success() => None,
            Ok(status) => Some(SourceError::DumpcapFailed {
                status,
                log: self.log.as_deref().map(log_tail).unwrap_or_default(),
            }),
            Err(e) => Some(SourceError::Dumpcap(format!("waiting: {e}"))),
        }
    }
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
                    None => self.current = None,
                }
            }
            match self.next_file() {
                Some(Ok(path)) => {
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
