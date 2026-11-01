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
use std::io::{BufRead, BufReader};
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
}

impl RingSource {
    /// Starts dumpcap. Its stderr goes to `<dir>/dumpcap.log`.
    pub fn spawn(cfg: &RingConfig) -> Result<Self, SourceError> {
        let log = std::fs::File::create(cfg.dir.join("dumpcap.log"))
            .map_err(|e| SourceError::Dumpcap(format!("creating log in {}: {e}", cfg.dir.display())))?;
        let mut child = Command::new(&cfg.dumpcap)
            .args(cfg.args()?)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(log)
            .spawn()
            .map_err(|e| SourceError::Dumpcap(format!("starting {}: {e}", cfg.dumpcap.display())))?;
        let stdout = child.stdout.take().expect("piped");
        Ok(RingSource {
            names: BufReader::new(stdout),
            child: Some(child),
            current: None,
            files: Vec::new(),
            done: false,
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
            Ok(status) => Some(SourceError::Dumpcap(format!("exited with {status}"))),
            Err(e) => Some(SourceError::Dumpcap(format!("waiting: {e}"))),
        }
    }
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
