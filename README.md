# envctl

envctl — manage keys in env files

Edits a single key in place without disturbing order, comments, spacing, or any
other line. Writes are atomic (temp file + rename) and preserve the target’s
mode, so a crash mid-write never leaves a half-written env file.

## Install

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
`PREFIX=` as usual.

Or build directly:

```sh
cc -O2 -Wall -Wextra -std=c11 -o envctl envctl.c
```

A pure Bash reference implementation lives in [`envctl.sh`](envctl.sh); the
installed tool is the C binary from [`envctl.c`](envctl.c).

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

Secret-looking key names are masked as `****` + last 4 characters when
redaction is on:

- **Substring:** `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `CREDENTIAL`, `API`
- **Full `_`-separated segment only:** `PASS`, `PWD` (e.g. `DB_PASS`, `MYSQL_PWD`;
  not `PASSPORT` / `COMPASS`)

Disk writes are never redacted — only stdout from `get`, `list --values`, and
`--dry-run`.

| Situation                                     | Redact?                |
| --------------------------------------------- | ---------------------- |
| Human on a TTY                                | No (unless `--redact`) |
| Coding agent detected **and** stdout is a TTY | Yes (unless `--raw`)   |
| Piped / redirected / scripts                  | No (unless `--redact`) |

Agent detection follows the same environment signals as [unjs/std-env](https://github.com/unjs/std-env)
(plus `AI_AGENT` as an explicit override).

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
