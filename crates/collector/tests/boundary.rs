//! The parse/I-O boundary (`docs/design/hardware-collector.md` §7): the
//! parser will run pinned in two places, so a parse module reaches only
//! other parse modules. Everything else in the crate is off limits: a new
//! module counts as I/O until it is listed in [`PARSE`].

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// The modules that will become the `parse` crate.
const PARSE: &[&str] = &[
    "assembler",
    "coding",
    "decode",
    "dns",
    "flow",
    "hpack",
    "hpack_huffman",
    "http",
    "http1",
    "http2",
    "mh",
    "net",
    "packet",
    "tcp",
    "wire",
];

/// Modules that must never join [`PARSE`].
const IO: &[&str] = &[
    "capture", "manifest", "observe", "ring", "run", "ship", "source", "stats", "store", "views", "window",
];

fn tokens(source: &str) -> Vec<TokenTree> {
    TokenStream::from_str(source)
        .expect("source lexes")
        .into_iter()
        .collect()
}

fn is_ident(t: Option<&TokenTree>, name: &str) -> bool {
    matches!(t, Some(TokenTree::Ident(i)) if i == name)
}

/// Whether `::` starts at `at`.
fn is_path_sep(ts: &[TokenTree], at: usize) -> bool {
    let colon = |t: Option<&TokenTree>| matches!(t, Some(TokenTree::Punct(p)) if p.as_char() == ':');
    colon(ts.get(at)) && colon(ts.get(at + 1))
}

/// Walks a path that is at module depth `level` (0 is the crate root) and
/// records what it names in the crate root, `*` for a glob or `self` for
/// the root itself under another name.
fn follow(ts: &[TokenTree], level: usize, found: &mut Vec<String>) {
    let next = match ts.first() {
        Some(t) if is_ident(Some(t), "crate") => 0,
        Some(t) if is_ident(Some(t), "self") => level,
        Some(t) if is_ident(Some(t), "super") => level.saturating_sub(1),
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
            let inner: Vec<_> = g.stream().into_iter().collect();
            let comma = |t: &TokenTree| matches!(t, TokenTree::Punct(p) if p.as_char() == ',');
            inner.split(comma).for_each(|path| follow(path, level, found));
            return;
        }
        Some(t) if level == 0 => return found.push(t.to_string()),
        _ => return,
    };
    if is_path_sep(ts, 1) {
        follow(&ts[3..], next, found);
    } else if next == 0 && (is_ident(ts.get(1), "as") || is_ident(ts.get(1), "self")) {
        found.push("self".to_string());
    }
}

/// Every path in `ts`, which sits `depth` modules below the crate root.
/// Works on tokens, so it sees grouped and multi-line imports and paths
/// inside macro calls, and skips comments and strings. Only a `mod` block
/// goes a level down: that is what `super` counts.
fn scan(ts: &[TokenTree], depth: usize, found: &mut Vec<String>) {
    for (i, t) in ts.iter().enumerate() {
        if let TokenTree::Group(g) = t {
            let in_mod = i >= 2 && is_ident(ts.get(i - 2), "mod");
            let inner: Vec<_> = g.stream().into_iter().collect();
            scan(&inner, depth + usize::from(in_mod), found);
        }
        let continues_a_path = i >= 2 && is_path_sep(ts, i - 2);
        if !continues_a_path && ["crate", "super", "self"].iter().any(|r| is_ident(Some(t), r)) {
            follow(&ts[i..], depth, found);
        }
    }
}

/// The modules `lib.rs` declares.
fn modules(lib: &str) -> BTreeSet<String> {
    let ts = tokens(lib);
    let declared = ts.windows(2).filter(|w| is_ident(w.first(), "mod"));
    declared.map(|w| w[1].to_string()).collect()
}

/// What crosses the boundary in `source`, a file `depth` modules down: all
/// it names in the crate root that is not a parse module. A `super` that
/// stays below the root stays inside the parse module.
fn crossings(source: &str, depth: usize) -> Vec<String> {
    let mut found = Vec::new();
    scan(&tokens(source), depth, &mut found);
    found.retain(|name| !PARSE.contains(&name.as_str()));
    found.dedup();
    found.iter().map(|name| format!("crate::{name}")).collect()
}

/// How far below the crate root a file under `src` sits.
fn depth_of(file: &Path) -> usize {
    let path = file.strip_prefix(src()).expect("under src");
    path.components().count() - usize::from(path.ends_with("mod.rs"))
}

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
}

fn parse_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for name in PARSE {
        let file = src().join(format!("{name}.rs"));
        if file.exists() {
            files.push(file);
        } else {
            rust_files(&src().join(name), &mut files);
        }
    }
    files
}

fn lib_modules() -> BTreeSet<String> {
    modules(&fs::read_to_string(src().join("lib.rs")).expect("read lib.rs"))
}

#[test]
fn a_parse_module_imports_no_io_module() {
    let mut bad = Vec::new();
    for file in parse_files() {
        let source = fs::read_to_string(&file).expect("read module");
        for crossing in crossings(&source, depth_of(&file)) {
            bad.push(format!("{}: {crossing}", file.display()));
        }
    }
    assert!(
        bad.is_empty(),
        "parse modules reach past the boundary:\n{}",
        bad.join("\n")
    );
}

#[test]
fn every_listed_module_exists_on_one_side() {
    let modules = lib_modules();
    for name in PARSE.iter().chain(IO) {
        assert!(modules.contains(*name), "{name} is not in lib.rs");
    }
    for name in IO {
        assert!(!PARSE.contains(name), "{name} does I/O");
    }
    assert!(parse_files().len() >= PARSE.len());
}

#[test]
fn the_scan_sees_every_way_of_naming_a_module() {
    let bad = |source: &str| crossings(source, 1);
    assert_eq!(bad("use crate::store::StoreSink;"), ["crate::store"]);
    assert_eq!(bad("use crate::{flow::Dir, stats};"), ["crate::stats"]);
    assert_eq!(
        bad("use crate::{\n    mh,\n    window::{self},\n};"),
        ["crate::window"]
    );
    assert_eq!(
        bad("fn f() -> crate::stats::Outcome { todo!() }"),
        ["crate::stats"]
    );
    assert_eq!(
        bad("fn f() { warn!(d = %crate::stats::dir_str(x)); }"),
        ["crate::stats"]
    );
    assert_eq!(
        bad("#[cfg(test)] mod t { use crate::source::LinkId; }"),
        ["crate::source"]
    );
    assert_eq!(bad("use crate::*;"), ["crate::*"]);
    assert_eq!(bad("use crate::RingSource;"), ["crate::RingSource"]);
}

/// `use super::*` at a module's root brings in every module of the crate,
/// and a later `store::…` names no root at all.
#[test]
fn a_path_up_to_the_crate_root_counts_as_one_from_it() {
    let bad = |source: &str| crossings(source, 1);
    assert_eq!(bad("use super::*;\nfn f(_: store::ChunkRecord) {}"), ["crate::*"]);
    assert_eq!(crossings("use super::super::*;", 2), ["crate::*"]);
    assert_eq!(bad("mod t { use super::super::*; }"), ["crate::*"]);
    assert_eq!(bad("fn f() { use super::*; }"), ["crate::*"]);
    assert_eq!(bad("use self::super::*;"), ["crate::*"]);
    assert_eq!(bad("use super::ship;"), ["crate::ship"]);
    assert_eq!(bad("use super::{flow, ring};"), ["crate::ring"]);
    assert_eq!(bad("mod t { use super::super::{flow, ring}; }"), ["crate::ring"]);
    assert_eq!(bad("mod t { use super::{super::store}; }"), ["crate::store"]);
    assert_eq!(bad("use super as root;"), ["crate::self"]);
    assert_eq!(bad("use crate as root;"), ["crate::self"]);
    assert_eq!(bad("use crate::{self as root};"), ["crate::self"]);
    assert_eq!(bad("extern crate self as root;"), ["crate::self"]);
}

#[test]
fn the_scan_leaves_alone_what_is_not_an_import() {
    let bad = |source: &str| crossings(source, 1);
    assert!(bad("use crate::flow::Dir;\nuse crate::wire::{self, Claim};").is_empty());
    assert!(bad("//! See [`crate::store`].\n/// [`crate::stats`]\nfn f() {}").is_empty());
    assert!(bad("// use crate::store;\nconst S: &str = \"crate::store\";").is_empty());
    assert!(bad("pub(crate) fn f() {}\npub(super) fn g() {}").is_empty());
    assert!(bad("mod tests { use super::*; use super::helper; }").is_empty());
    assert!(bad("mod a { mod tests { use super::super::*; } }").is_empty());
    assert!(crossings("use super::*;\nuse super::framing;", 2).is_empty());
    assert_eq!(depth_of(&src().join("decode.rs")), 1);
    assert_eq!(depth_of(&src().join("wire/mod.rs")), 1);
    assert_eq!(depth_of(&src().join("wire/openai.rs")), 2);
}
