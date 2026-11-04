//! The README's "Command line" section is the real `--help` output: one
//! block for `collector --help` and one per subcommand. A changed option,
//! or a subcommand without its block, fails here. `UPDATE_README=1`
//! rewrites the blocks from the binary.

use std::path::Path;
use std::process::Command;

const FENCE: &str = "```";

fn help(args: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_collector"))
        .args(args.split_whitespace())
        .output()
        .unwrap();
    assert!(out.status.success(), "collector {args}");
    String::from_utf8(out.stdout).unwrap().trim_end().to_string()
}

/// The subcommands `collector --help` lists, but `help`.
fn subcommands(main_help: &str) -> Vec<String> {
    main_help
        .lines()
        .skip_while(|l| *l != "Commands:")
        .skip(1)
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .filter(|c| *c != "help")
        .map(String::from)
        .collect()
}

/// The byte range of the text block after `<!-- help: {args} -->`.
fn block(readme: &str, args: &str) -> Option<std::ops::Range<usize>> {
    let marker = format!("<!-- help: {args} -->\n{FENCE}text\n");
    let start = readme.find(&marker)? + marker.len();
    if readme[start..].starts_with(FENCE) {
        return Some(start..start);
    }
    let len = readme[start..].find(&format!("\n{FENCE}"))?;
    Some(start..start + len)
}

#[test]
fn the_readme_shows_the_real_help() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    let mut readme = std::fs::read_to_string(&path).unwrap();
    let main_help = help("--help");
    let mut wanted = vec!["--help".to_string()];
    wanted.extend(subcommands(&main_help).iter().map(|c| format!("{c} --help")));
    assert!(wanted.len() > 1, "no subcommands found in:\n{main_help}");

    let update = std::env::var_os("UPDATE_README").is_some();
    // Differing blocks (rewritten by UPDATE_README), and missing or
    // unknown ones (never rewritten: the prose around them needs a hand).
    let (mut stale, mut missing) = (Vec::new(), Vec::new());
    for args in &wanted {
        let real = help(args);
        match block(&readme, args) {
            Some(r) if readme[r.clone()] == real => {}
            // An empty block has no newline before its closing fence yet.
            Some(r) if update && r.is_empty() => readme.insert_str(r.start, &format!("{real}\n")),
            Some(r) if update => readme.replace_range(r, &real),
            Some(_) => stale.push(format!("`collector {args}` differs")),
            None => missing.push(format!("no block for `collector {args}`")),
        }
    }
    // Blocks for subcommands that no longer exist.
    for line in readme.lines() {
        if let Some(args) = line
            .strip_prefix("<!-- help: ")
            .and_then(|l| l.strip_suffix(" -->"))
        {
            if !wanted.iter().any(|w| w == args) {
                missing.push(format!("block for `collector {args}`, which no longer exists"));
            }
        }
    }
    if update {
        std::fs::write(&path, &readme).unwrap();
    }
    assert!(
        missing.is_empty(),
        "README.md is out of step with the CLI:\n{}",
        missing.join("\n")
    );
    assert!(
        stale.is_empty() || update,
        "README.md is out of step with the CLI (UPDATE_README=1 rewrites the blocks):\n{}",
        stale.join("\n")
    );
}
