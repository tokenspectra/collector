//! Writes the golden `.pcapng` fixtures to `tests/fixtures/`.
//!
//! `cargo run -p collector --example gen_fixtures`

#[path = "../tests/support/fixtures.rs"]
mod fixtures;

use std::path::Path;

fn main() -> std::io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir)?;
    for fx in fixtures::all() {
        for (name, frames) in &fx.files {
            std::fs::write(dir.join(name), fixtures::pcapng(frames))?;
            println!("wrote {name}");
        }
    }
    Ok(())
}
