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

/// A module path in a source file, up to its first segment after the root.
#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// `crate::name`, or `*` for a glob.
    Crate(String),
    /// `super::name`, past any further `super`s.
    Super(String),
}

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

/// The first segment of each path in a `{a, b::c, d::{e}}` use group.
fn group_heads(ts: &[TokenTree]) -> Vec<String> {
    ts.split(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
        .filter_map(|path| path.first().map(TokenTree::to_string))
        .collect()
}

/// Every crate-relative path in `ts`. Works on tokens, so it sees grouped
/// and multi-line imports and paths inside macro calls, and skips comments
/// and strings.
fn scan(ts: &[TokenTree], found: &mut Vec<Reach>) {
    for (i, t) in ts.iter().enumerate() {
        if let TokenTree::Group(g) = t {
            scan(&g.stream().into_iter().collect::<Vec<_>>(), found);
        }
        let is_crate = is_ident(Some(t), "crate");
        let continues_a_path = i >= 2 && is_path_sep(ts, i - 2);
        if !(is_crate || is_ident(Some(t), "super")) || !is_path_sep(ts, i + 1) || continues_a_path {
            continue;
        }
        let mut at = i + 3;
        while is_ident(ts.get(at), "super") && is_path_sep(ts, at + 1) {
            at += 3;
        }
        let heads = match ts.get(at) {
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
                group_heads(&g.stream().into_iter().collect::<Vec<_>>())
            }
            Some(t) => vec![t.to_string()],
            None => vec![],
        };
        for head in heads {
            found.push(if is_crate {
                Reach::Crate(head)
            } else {
                Reach::Super(head)
            });
        }
    }
}

fn reaches(source: &str) -> Vec<Reach> {
    let mut found = Vec::new();
    scan(&tokens(source), &mut found);
    found
}

/// The modules `lib.rs` declares.
fn modules(lib: &str) -> BTreeSet<String> {
    let ts = tokens(lib);
    let declared = ts.windows(2).filter(|w| is_ident(w.first(), "mod"));
    declared.map(|w| w[1].to_string()).collect()
}

/// What in `source` crosses the boundary. `super::` also names items of
/// the file's own module, so only the crate's other modules count there.
fn crossings(source: &str, modules: &BTreeSet<String>) -> Vec<String> {
    let parse = |name: &str| PARSE.contains(&name);
    let mut bad = Vec::new();
    for r in reaches(source) {
        match r {
            Reach::Crate(name) if !parse(&name) => bad.push(format!("crate::{name}")),
            Reach::Super(name) if !parse(&name) && modules.contains(&name) => {
                bad.push(format!("super::{name}"))
            }
            _ => {}
        }
    }
    bad
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
    let modules = lib_modules();
    let mut bad = Vec::new();
    for file in parse_files() {
        let source = fs::read_to_string(&file).expect("read module");
        for crossing in crossings(&source, &modules) {
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
    let modules = lib_modules();
    let bad = |source: &str| crossings(source, &modules);
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
    assert_eq!(bad("use super::ship;"), ["super::ship"]);
    assert_eq!(bad("use super::super::{flow, ring};"), ["super::ring"]);
    assert_eq!(bad("use crate::*;"), ["crate::*"]);
    assert_eq!(bad("use crate::RingSource;"), ["crate::RingSource"]);
}

#[test]
fn the_scan_leaves_alone_what_is_not_an_import() {
    let modules = lib_modules();
    let bad = |source: &str| crossings(source, &modules);
    assert!(bad("use crate::flow::Dir;\nuse crate::wire::{self, Claim};").is_empty());
    assert!(bad("//! See [`crate::store`].\n/// [`crate::stats`]\nfn f() {}").is_empty());
    assert!(bad("// use crate::store;\nconst S: &str = \"crate::store\";").is_empty());
    assert!(bad("pub(crate) fn f() {}\nmod tests { use super::*; use super::helper; }").is_empty());
}
