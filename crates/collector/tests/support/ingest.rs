//! A stand-in for the control plane's ingest (spec §11): keeps each
//! window's manifest by its `Idempotency-Key`, answers 200 to a first copy
//! or a repeat of the same bytes, and 409 to other bytes for a window it
//! already holds.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct State {
    /// Manifests by dedup key.
    pub windows: BTreeMap<String, Vec<u8>>,
    pub accepted: u64,
    pub duplicates: u64,
    pub conflicts: u64,
}

pub struct MockIngest {
    pub url: String,
    pub state: Arc<Mutex<State>>,
}

impl MockIngest {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}/ingest/windows", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let st = state.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let _ = serve(conn, &st);
            }
        });
        MockIngest { url, state }
    }

    pub fn snapshot(&self) -> (BTreeMap<String, Vec<u8>>, u64, u64, u64) {
        let s = self.state.lock().unwrap();
        (s.windows.clone(), s.accepted, s.duplicates, s.conflicts)
    }
}

fn serve(conn: TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
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
    let (status, text) = if !request_line.starts_with("POST /ingest/windows ") || key.is_empty() {
        ("400 Bad Request", "bad request")
    } else {
        let mut s = state.lock().unwrap();
        match s.windows.get(&key) {
            None => {
                s.windows.insert(key, body);
                s.accepted += 1;
                ("200 OK", "accepted")
            }
            Some(b) if *b == body => {
                s.duplicates += 1;
                ("200 OK", "duplicate")
            }
            Some(_) => {
                s.conflicts += 1;
                ("409 Conflict", "window already held with other bytes")
            }
        }
    };
    let mut conn = conn;
    write!(
        conn,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )
}
