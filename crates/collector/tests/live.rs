//! Live `RingSource` against real dumpcap (TS-24 acceptance: live equals
//! offline). Needs capture rights, so it only runs with
//! `TS_LIVE_DUMPCAP=1`:
//!
//! ```sh
//! sg wireshark -c "TS_LIVE_DUMPCAP=1 cargo test -p collector --test live -- --nocapture"
//! ```

#[path = "support/collect.rs"]
mod collect;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use collector::{FileSource, RingConfig, RingSource};

#[test]
fn live_ring_equals_file_source_over_its_files() {
    if std::env::var_os("TS_LIVE_DUMPCAP").is_none() {
        eprintln!("skipped: set TS_LIVE_DUMPCAP=1 (and run under `sg wireshark -c ...`)");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 64];
        while let Ok(n) = conn.read(&mut buf) {
            if n == 0 || conn.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let ring_dir = tempfile::tempdir().unwrap();
    let mut cfg = RingConfig::new("lo", 1, ring_dir.path());
    cfg.autostop_s = Some(4);
    cfg.extra_args = vec!["-f".into(), format!("tcp port {port}")];
    let mut ring = RingSource::spawn(&cfg).unwrap();

    let client = thread::spawn(move || {
        thread::sleep(Duration::from_millis(1000));
        let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 64];
        for i in 0..8 {
            let msg = format!("ping {i}\n");
            conn.write_all(msg.as_bytes()).unwrap();
            conn.read_exact(&mut buf[..msg.len()]).unwrap();
            thread::sleep(Duration::from_millis(300));
        }
    });

    let live = collect::tables(&mut ring);
    client.join().unwrap();
    server.join().unwrap();

    let files = ring.files().to_vec();
    assert!(files.len() >= 2, "dumpcap closed {} files", files.len());
    let offline = collect::tables(&mut FileSource::new(files));
    assert_eq!(live, offline);
    let packets = &live.iter().find(|(n, _)| n == "packets.jsonl").unwrap().1;
    assert!(packets.split(|b| *b == b'\n').count() > 20, "captured too little");
}
