//! envctl — manage keys in env files (Rust port of envctl.c, std-only).
//!
//! Behaviour matches the C tool: in-place key edits, atomic write, optional
//! `./.env`, redact rules for agents on a TTY.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;

const PROG: &str = "envctl";

const SHORT_USAGE: &str = "\
usage: envctl [<cmd>] [file] <KEY> [VALUE]
  commands: set get disable enable delete|rm list|ls
  file:     optional when ./.env exists
  bare:     envctl [file] <KEY>          == get
            envctl [file] <KEY> <VALUE>  == set
  flags:    --values --all (list)  --dry-run  --redact --raw
";

const AI_PREAMBLE: &str = "\
You are an AI coding agent. Use envctl to change a key in any env / .env-style file.
NEVER hand-edit an env file to add, change, comment, or remove a key -
envctl does it in place, atomically, preserving order, comments, and mode.
If ./.env exists you may omit the file argument. Secret-looking values are
redacted on a TTY by default; use --raw only when you truly need full secrets.

";

const LONG_USAGE: &str = "\
envctl — manage keys in env files

Commands:
  envctl set     [file] <KEY> [VALUE]   set/replace KEY (uncomments if commented)
  envctl get     [file] <KEY>           print active value; exit 1 if unset
  envctl disable [file] <KEY>           comment KEY out, keep its value
  envctl enable  [file] <KEY>           uncomment KEY
  envctl delete  [file] <KEY>           remove KEY entirely (active + commented) [rm]
  envctl list    [file] [--values] [--all]  active keys; --values shows values;
                                        --all also lists disabled keys           [ls]

File: optional when ./.env exists as a regular file. If the first positional is
an existing regular file, it is used; otherwise .env is assumed when present.

Bare form (no command word):
  envctl [file] <KEY>            == get
  envctl [file] <KEY> <VALUE>    == set

Flags:
  --dry-run   mutating command: print the result, write nothing
  --values    list: show values (secret-looking ones follow redact rules)
  --all       list: include disabled keys tagged (disabled)
  --redact    mask secret-looking values on get / list --values / dry-run
  --raw       never mask (overrides auto-redact and --redact)

Redaction: secret-looking key names (KEY, TOKEN, SECRET, PASSWORD, PASSWD,
CREDENTIAL, API; segment PASS/PWD e.g. DB_PASS) are masked as **** + last 4
chars when redact is on.
Default on when a coding agent is detected and stdout is a TTY; off when
stdout is piped/redirected (scripts, command substitution) unless --redact.

Guarantees: only the target key's line changes; re-running with the same args
is a no-op; writes are atomic (temp + rename) and preserve file mode; VALUE is
literal (no shell/regex reinterpretation).
";

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("{}: {}", PROG, msg.as_ref());
    process::exit(2);
}

fn env_set(k: &str) -> bool {
    env::var_os(k).is_some_and(|v| !v.is_empty())
}

fn detect_agent() -> bool {
    const KEYS: &[&str] = &[
        "AI_AGENT",
        "CLAUDECODE",
        "CLAUDE_CODE",
        "REPL_ID",
        "GEMINI_CLI",
        "CODEX_SANDBOX",
        "CODEX_THREAD_ID",
        "OPENCODE",
        "AUGMENT_AGENT",
        "GOOSE_PROVIDER",
        "JUNIE_DATA",
        "JUNIE_SHIM_PATH",
        "CURSOR_AGENT",
    ];
    if KEYS.iter().any(|k| env_set(k)) {
        return true;
    }
    if env::var("PATH").is_ok_and(|p| p.contains(".pi/agent") || p.contains(".pi\\agent")) {
        return true;
    }
    if env::var("EDITOR").is_ok_and(|e| e.contains("devin")) {
        return true;
    }
    if env::var("TERM_PROGRAM").is_ok_and(|t| t.contains("kiro")) && !io::stdout().is_terminal() {
        return true;
    }
    false
}

fn print_help(longform: bool) -> ! {
    if longform {
        if detect_agent() {
            print!("{AI_PREAMBLE}");
        }
        print!("{LONG_USAGE}");
    } else {
        print!("{SHORT_USAGE}");
    }
    process::exit(0);
}

fn read_file(path: &Path) -> Vec<String> {
    let data =
        fs::read(path).unwrap_or_else(|_| die(format!("cannot open file: {}", path.display())));
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            let mut end = i;
            if end > start && data[end - 1] == b'\r' {
                end -= 1;
            }
            lines.push(String::from_utf8_lossy(&data[start..end]).into_owned());
            start = i + 1;
        }
    }
    if start < data.len() {
        let mut end = data.len();
        if end > start && data[end - 1] == b'\r' {
            end -= 1;
        }
        lines.push(String::from_utf8_lossy(&data[start..end]).into_owned());
    }
    lines
}

fn skip_ws(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

fn skip_export(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix("export")
        && rest.starts_with([' ', '\t'])
    {
        return skip_ws(rest);
    }
    s
}

fn key_at(s: &str, key: &str) -> bool {
    s.strip_prefix(key).is_some_and(|r| r.starts_with('='))
}

fn is_active_def(line: &str, key: &str) -> bool {
    if skip_ws(line).starts_with('#') {
        return false;
    }
    key_at(skip_export(line), key)
}

fn is_comment_def(line: &str, key: &str) -> bool {
    let p = skip_ws(line);
    let Some(rest) = p.strip_prefix('#') else {
        return false;
    };
    key_at(skip_export(skip_ws(rest)), key)
}

fn find_defs(lines: &[String], key: &str) -> (Option<usize>, Option<usize>) {
    let mut active = None;
    let mut commented = None;
    for (i, line) in lines.iter().enumerate() {
        if active.is_none() && is_active_def(line, key) {
            active = Some(i);
        }
        if commented.is_none() && is_comment_def(line, key) {
            commented = Some(i);
        }
        if active.is_some() && commented.is_some() {
            break;
        }
    }
    (active, commented)
}

fn mk_kv(key: &str, val: &str) -> String {
    format!("{key}={val}")
}

fn mk_comment(line: &str) -> String {
    format!("# {line}")
}

fn uncomment(line: &str) -> String {
    let p = skip_ws(line);
    skip_ws(&p[1..]).to_string()
}

fn act_set(lines: &[String], key: &str, val: &str) -> Vec<String> {
    let (first_active, first_comment) = find_defs(lines, key);
    let mut out = Vec::with_capacity(lines.len() + 1);
    for (i, line) in lines.iter().enumerate() {
        let next = if let Some(fa) = first_active {
            if i == fa {
                mk_kv(key, val)
            } else if is_active_def(line, key) {
                mk_comment(line)
            } else {
                line.clone()
            }
        } else if first_comment == Some(i) {
            mk_kv(key, val)
        } else {
            line.clone()
        };
        out.push(next);
    }
    if first_active.is_none() && first_comment.is_none() {
        out.push(mk_kv(key, val));
    }
    out
}

fn act_disable(lines: &[String], key: &str) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            if is_active_def(line, key) {
                mk_comment(line)
            } else {
                line.clone()
            }
        })
        .collect()
}

fn act_enable(lines: &[String], key: &str) -> Vec<String> {
    let (first_active, first_comment) = find_defs(lines, key);
    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            if first_active.is_none() && first_comment == Some(i) {
                uncomment(line)
            } else {
                line.clone()
            }
        })
        .collect()
}

fn act_delete(lines: &[String], key: &str) -> Vec<String> {
    lines
        .iter()
        .filter(|line| !is_active_def(line, key) && !is_comment_def(line, key))
        .cloned()
        .collect()
}

fn has_segment(k: &str, seg: &str) -> bool {
    let n = seg.len();
    let b = k.as_bytes();
    let sb = seg.as_bytes();
    if n == 0 || b.len() < n {
        return false;
    }
    for i in 0..=b.len() - n {
        if &b[i..i + n] != sb {
            continue;
        }
        let left = i == 0 || b[i - 1] == b'_';
        let right = i + n == b.len() || b[i + n] == b'_';
        if left && right {
            return true;
        }
    }
    false
}

fn secretish(k: &str) -> bool {
    for tok in [
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "API",
    ] {
        if k.contains(tok) {
            return true;
        }
    }
    has_segment(k, "PASS") || has_segment(k, "PWD")
}

fn valid_keychars(k: &str) -> bool {
    let mut chars = k.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn want_redact(flag_redact: bool, flag_raw: bool) -> bool {
    if flag_raw {
        return false;
    }
    if flag_redact {
        return true;
    }
    detect_agent() && io::stdout().is_terminal()
}

fn mask_value(val: &str) -> String {
    if val.len() > 4 {
        format!("****{}", &val[val.len() - 4..])
    } else {
        "****".to_string()
    }
}

fn print_value(key: &str, val: &str, redact: bool) {
    if redact && secretish(key) {
        println!("{}", mask_value(val));
    } else {
        println!("{val}");
    }
}

fn act_get(lines: &[String], key: &str, redact: bool) -> i32 {
    for line in lines {
        if is_active_def(line, key) {
            let s = skip_export(line);
            let val = &s[key.len() + 1..];
            print_value(key, val, redact);
            return 0;
        }
    }
    1
}

fn act_list(lines: &[String], values: bool, all: bool, redact: bool) {
    for orig in lines {
        let p = skip_ws(orig);
        let (commented, s) = if let Some(rest) = p.strip_prefix('#') {
            if !all {
                continue;
            }
            (true, skip_ws(rest))
        } else {
            (false, orig.as_str())
        };
        let s = skip_export(s);
        let Some(eq) = s.find('=') else { continue };
        let kname = &s[..eq];
        if !valid_keychars(kname) {
            continue;
        }
        let tag = if commented { " (disabled)" } else { "" };
        if !values {
            println!("{kname}{tag}");
            continue;
        }
        let val = &s[eq + 1..];
        if redact && secretish(kname) {
            println!("{kname}={}{tag}", mask_value(val));
        } else {
            println!("{kname}={val}{tag}");
        }
    }
}

fn emit_line(out: &mut dyn Write, line: &str, redact: bool) -> io::Result<()> {
    if !redact {
        writeln!(out, "{line}")?;
        return Ok(());
    }
    let mut p = skip_ws(line);
    if let Some(rest) = p.strip_prefix('#') {
        p = skip_ws(rest);
    }
    p = skip_export(p);
    let Some(eq_rel) = p.find('=') else {
        writeln!(out, "{line}")?;
        return Ok(());
    };
    let kname = &p[..eq_rel];
    if !valid_keychars(kname) || !secretish(kname) {
        writeln!(out, "{line}")?;
        return Ok(());
    }
    // Keep prefix through '=' relative to original line.
    let eq_abs = line.find('=').unwrap();
    write!(out, "{}", &line[..=eq_abs])?;
    let val = &line[eq_abs + 1..];
    writeln!(out, "{}", mask_value(val))?;
    Ok(())
}

fn emit(out: &mut dyn Write, lines: &[String], redact: bool) {
    for line in lines {
        emit_line(out, line, redact).unwrap_or_else(|_| die("write failed"));
    }
}

fn commit_file(path: &Path, lines: &[String]) {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mode = fs::metadata(path).ok().map(|m| m.permissions());

    let mut tmp_path = dir.to_path_buf();
    tmp_path.push(format!(
        ".envctl.{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .unwrap_or_else(|_| die("temp open failed"));
        emit(&mut f, lines, false);
        f.flush().unwrap_or_else(|_| {
            let _ = fs::remove_file(&tmp_path);
            die("write failed");
        });
    }

    if let Some(perms) = mode {
        let _ = fs::set_permissions(&tmp_path, perms);
    }

    // Atomic replace: rename over target (Unix); on Windows rename won't overwrite.
    #[cfg(windows)]
    {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp_path, path).unwrap_or_else(|_| {
        let _ = fs::remove_file(&tmp_path);
        die("rename failed");
    });
}

fn is_command(a: &str) -> bool {
    matches!(
        a,
        "set" | "get" | "disable" | "enable" | "delete" | "list" | "ls" | "rm"
    )
}

fn is_reg_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

struct Resolved {
    file: PathBuf,
    key: Option<String>,
    val: Option<String>,
}

fn resolve_file_args(rest: &[&str]) -> Resolved {
    if !rest.is_empty() && is_reg_file(Path::new(rest[0])) {
        if rest.len() > 3 {
            die("too many arguments");
        }
        return Resolved {
            file: PathBuf::from(rest[0]),
            key: rest.get(1).map(|s| (*s).to_string()),
            val: rest.get(2).map(|s| (*s).to_string()),
        };
    }
    if !rest.is_empty() && !valid_keychars(rest[0]) {
        die(format!("no such file: {}", rest[0]));
    }
    if is_reg_file(Path::new(".env")) {
        if rest.len() > 2 {
            die("too many arguments");
        }
        return Resolved {
            file: PathBuf::from(".env"),
            key: rest.first().map(|s| (*s).to_string()),
            val: rest.get(1).map(|s| (*s).to_string()),
        };
    }
    if !rest.is_empty() {
        die("no file given and no .env in cwd");
    }
    die("no file given and no .env in cwd");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut dry = false;
    let mut values = false;
    let mut all = false;
    let mut flag_redact = false;
    let mut flag_raw = false;
    let mut pos: Vec<&str> = Vec::new();

    for a in &args {
        match a.as_str() {
            "--dry-run" => dry = true,
            "--values" => values = true,
            "--all" => all = true,
            "--redact" => flag_redact = true,
            "--raw" => flag_raw = true,
            "-h" => print_help(false),
            "--help" => print_help(true),
            _ => {
                if pos.len() >= 16 {
                    die("too many arguments");
                }
                pos.push(a);
            }
        }
    }

    if pos.is_empty() {
        print_help(true);
    }

    let mut cmd: Option<&str> = None;
    let mut rest: Vec<&str> = Vec::new();
    for a in &pos {
        if cmd.is_none() && is_command(a) {
            cmd = Some(a);
        } else {
            rest.push(a);
        }
    }

    let (cmd, file, key, val) = if let Some(mut c) = cmd {
        if c == "ls" {
            c = "list";
        }
        if c == "rm" {
            c = "delete";
        }
        if c == "list" {
            let file = match rest.as_slice() {
                [] => {
                    if !is_reg_file(Path::new(".env")) {
                        die("list needs a file (no .env in cwd)");
                    }
                    PathBuf::from(".env")
                }
                [p] if is_reg_file(Path::new(p)) => PathBuf::from(*p),
                [p] => die(format!("no such file: {p}")),
                _ => die("too many arguments"),
            };
            (c, file, None, None)
        } else {
            let r = resolve_file_args(&rest);
            (c, r.file, r.key, r.val)
        }
    } else {
        if rest.is_empty() {
            die("usage: envctl [<cmd>] [file] <KEY> [VALUE]");
        }
        let r = resolve_file_args(&rest);
        if r.key.is_none() {
            die("usage: envctl [file] <KEY> [VALUE]  or  envctl <cmd> [file] ...");
        }
        let c = if r.val.is_some() { "set" } else { "get" };
        (c, r.file, r.key, r.val)
    };

    if !is_reg_file(&file) {
        die(format!("no such file: {}", file.display()));
    }

    let redact = want_redact(flag_redact, flag_raw);
    let lines = read_file(&file);

    if cmd == "list" {
        act_list(&lines, values, all, redact);
        return;
    }

    let key = key.unwrap_or_else(|| die(format!("{cmd} needs KEY")));
    if !valid_keychars(&key) {
        die(format!("invalid key: '{key}'"));
    }
    if cmd != "set" && val.is_some() {
        die("too many arguments");
    }

    if cmd == "get" {
        process::exit(act_get(&lines, &key, redact));
    }

    let out = match cmd {
        "set" => act_set(&lines, &key, val.as_deref().unwrap_or("")),
        "disable" => act_disable(&lines, &key),
        "enable" => act_enable(&lines, &key),
        "delete" => act_delete(&lines, &key),
        _ => die("internal error"),
    };

    if dry {
        emit(&mut io::stdout(), &out, redact);
    } else {
        commit_file(&file, &out);
    }
}
