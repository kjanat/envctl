# envctl

envctl — manage keys in env files

Edits a single key in place without disturbing order, comments, spacing, or any
other line. Writes are atomic (temp file + rename) and preserve the target’s
mode, so a crash mid-write never leaves a half-written env file.

## Install

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/kjanat/envctl/releases)
(`linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`,
`windows-amd64`, `windows-arm64`).

```sh
# Example: Linux x86_64 → ~/.local/bin
curl -fsSL -o ~/.local/bin/envctl \
  https://github.com/kjanat/envctl/releases/latest/download/envctl-linux-amd64
chmod +x ~/.local/bin/envctl
```

Verify against `SHA256SUMS` on the same release when you care.

### From source

```sh
git clone https://github.com/kjanat/envctl.git
cd envctl
make
make install   # symlink → ~/.local/bin/envctl
```

One-liner:

```sh
git clone https://github.com/kjanat/envctl.git && cd envctl && make && make install
```

Needs a C11 compiler (`cc` by default). Override with `CC=` / `CFLAGS=` /
`PREFIX=` as usual. `make test` runs a short smoke suite.

Sources live under [`src/`](src/) (`util`, `agent`, `help`, `lines`, `redact`,
`fileio`, `main`). A pure Bash reference is [`envctl.sh`](envctl.sh).

### Releasing

Push a version tag; CI builds the five artifacts, writes `SHA256SUMS`, and
publishes a GitHub Release:

```sh
git tag v0.1.0
git push origin v0.1.0
```

## Usage

```text
envctl set     [file] <KEY> [VALUE]   set/replace KEY (uncomments if commented)
envctl get     [file] <KEY>           print active value; exit 1 if unset
envctl disable [file] <KEY>           comment KEY out, keep its value
envctl enable  [file] <KEY>           uncomment KEY
envctl delete  [file] <KEY>           remove KEY entirely (active + commented)
envctl list    [file] [--values] [--all]
```

Aliases: `ls` = `list`, `rm` = `delete`.

### Default file

If the first positional is an existing regular file, it is used. Otherwise, when
`./.env` exists, it is assumed and you can omit the file argument:

```sh
envctl list
envctl get DATABASE_URL
envctl set DEBUG true
```

### Bare form

If there is no command word:

```text
envctl [file] <KEY>            # get
envctl [file] <KEY> <VALUE>    # set
```

A command name always wins over a same-named file, so
`envctl .env get API_KEY` is a get.

### Flags

| Flag        | Applies to                    | Effect                                                 |
| ----------- | ----------------------------- | ------------------------------------------------------ |
| `--dry-run` | set, disable, enable, delete  | Print the resulting file to stdout; write nothing      |
| `--values`  | list                          | Show values (secret-looking ones follow redact rules)  |
| `--all`     | list                          | Include disabled (commented) keys, tagged `(disabled)` |
| `--redact`  | get, list `--values`, dry-run | Force masking of secret-looking values                 |
| `--raw`     | get, list `--values`, dry-run | Never mask (overrides auto-redact and `--redact`)      |

Help: `-h` for short usage, `--help` (or no args) for long help.

### Redaction

Presentation hygiene only (not a security boundary against `cat .env`). When
redaction is on, values become `<redacted>`, `<redacted:private-key>`, or
`<redacted:credentials>` — never partial suffixes.

**When redaction is on**

| Situation                                     | Redact?                |
| --------------------------------------------- | ---------------------- |
| Human on a TTY                                | No (unless `--redact`) |
| Coding agent detected **and** stdout is a TTY | Yes (unless `--raw`)   |
| Piped / redirected / scripts                  | No (unless `--redact`) |

`get` stays raw on pipes so scripts and command substitution keep working.
Agent detection follows [unjs/std-env](https://github.com/unjs/std-env) signals
(plus `AI_AGENT`).

**What counts as secret**

- **Key names** (case-insensitive `_` segments): `PASSWORD` / `PASS` / `PWD`,
  `SECRET`, `TOKEN`, `CREDENTIAL(S)`, `DSN`, credentialed `*_KEY` (e.g.
  `API_KEY`, `PRIVATE_KEY`), `DATABASE_URL` / `DB_URL`, …
- **Not by name alone:** path-like suffixes `*_FILE`, `*_PATH`, `*_ENDPOINT`,
  `*_NAME`, `*_VERSION`, `*_DIR`, `*_HOME` (value may still be masked)
- **Values:** PEM private keys, credentialed URLs (`scheme://user:pass@host`),
  known token prefixes (`ghp_`, `sk_live_`, …), JWT compact form, plus
  random-looking values under weaker key names
- **Multiline:** PEM bodies after a masked assignment are suppressed in dry-run
  output

Disk writes are never redacted.

### Examples

```sh
envctl set .env DATABASE_URL 'postgres://localhost/app'
envctl get DATABASE_URL              # uses ./.env when present
envctl disable DEBUG
envctl enable DEBUG
envctl list --values --all
envctl --dry-run delete OLD_KEY
envctl --redact get API_TOKEN        # force mask
envctl --raw list --values           # force full secrets
```

## Matching rules

| Kind      | Shape                                            |
| --------- | ------------------------------------------------ |
| Active    | optional `export`, then `KEY=...`                |
| Commented | leading `#` (optional whitespace), then the same |

On `set`:

1. Update the first active definition in place
2. Comment out any extra active duplicates
3. If none active, revive the first commented definition
4. Otherwise append

Re-running with the same arguments is a no-op on content. `VALUE` is literal —
no shell or regex reinterpretation.

Keys must match `[A-Za-z_][A-Za-z0-9_]*`.

## Guarantees

- Only the target key’s line changes
- Order, comments, and unrelated lines are preserved
- Atomic write (temp + rename); file mode preserved
- Secret-looking values are masked under the redact rules above; never on disk

## License

[MIT](LICENSE)
