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
`PREFIX=` as usual. `make test` runs the assertion suite.

Sources live under [`src/`](src/) (`util`, `agent`, `help`, `lines`, `entropy`,
`redact`, `mask`, `filter`, `diff`, `fileio`, `main`).

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
envctl redact  [file | --no-env]      filter stdin to stdout, masking secrets
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

| Flag        | Applies to                    | Effect                                                  |
| ----------- | ----------------------------- | ------------------------------------------------------- |
| `--dry-run` | set, disable, enable, delete  | Print a unified diff to stdout; write nothing           |
| `--values`  | list                          | Show values (secret-looking ones follow redact rules)   |
| `--all`     | list                          | Include disabled (commented) keys, tagged `(disabled)`  |
| `--no-env`  | redact                        | Skip the env file's literal values, use heuristics only |
| `--redact`  | get, list `--values`, dry-run | Force masking of secret-looking values                  |
| `--raw`     | get, list `--values`, dry-run | Never mask (overrides auto-redact and `--redact`)       |

`redact` rejects `--raw` and exits non-zero.

Help: `-h` for short usage, `--help` (or no args) for long help.

### Dry run

`--dry-run` prints a unified diff of the change and writes nothing. Only the
changed lines appear; unchanged lines are omitted. When the command would change
nothing, stdout is empty and `envctl: no changes` goes to stderr.

```console
$ envctl --dry-run set .env FOO two
--- .env
+++ .env
@@ -1,1 +1,1 @@
-FOO=one
+FOO=two
```

Under `--redact` the `+++` header reads `+++ .env (redacted)` and both sides of
the diff are masked.

### Filter mode

`envctl redact` reads text on stdin and writes it to stdout with secrets masked.

```sh
some-agent-command 2>&1 | envctl redact
envctl redact prod.env < build.log
cat build.log | envctl redact --no-env
```

The positional names the env file supplying literal values, defaulting to
`./.env` when it exists. Every maskable value in that file is matched literally,
together with its base64, URL-encoded, and JSON-escaped forms. The value-shape
heuristics then run over the rest of the text, and entropy applies only on lines
that carry a key name. `--no-env` skips the env file. Filter mode always
redacts, so agent detection and the TTY check do not apply.

A PEM private key prints as one `<redacted:private-key>` line and its body
lines are dropped. When the `-----END-----` marker never arrives, up to 512
following lines are dropped with it.

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
  `API_KEY`, `PRIVATE_KEY`), `DATABASE_URL` / `DB_URL`, `WEBHOOK_URL`, …
- **Not by name alone:** path-like suffixes `*_FILE`, `*_PATH`, `*_ENDPOINT`,
  `*_NAME`, `*_VERSION`, `*_LENGTH`, `*_DIR`, `*_HOME` (webhook keys excepted),
  and digest-like names `*_SHA`, `*_SHA256`, `*_HASH`, `*_DIGEST`, `*_CHECKSUM`,
  `*_ETAG`, `*_COMMIT`. A path-like suffix drops the key to the entropy bar; a
  digest-like name masks only on value shape
- **Values:** PEM private keys, PuTTY private key files, private JWKs (JSON with
  `kty` plus `d` or `k`), credentialed URLs (`scheme://user:pass@host`), URLs
  carrying `token=`, `api_key=`, `access_token=`, `X-Amz-Signature=`, …,
  `Authorization: Bearer` / `Basic` values, connection-string fragments
  (`;Password=`, `;Pwd=`, `sslkey=`), known token prefixes (`ghp_`, `sk_live_`,
  `AKIA`, `A3T…`, …), JWT compact form
- **Entropy:** under a key name containing `KEY`, `API`, `AUTH`, `ACCESS`,
  `CRED`, `PASS`, `JWT`, `BEARER`, or `OAUTH`, a value clears the bar at 32+ hex
  characters with H > 3.0, or 24+ base64 characters or 16+ opaque characters
  with H > 3.5. UUIDs, paths, and URLs are exempt, and so is a `*_ID` key
  (`SESSION_ID`, `OAUTH_CLIENT_ID`), which still masks under a strong secret
  name such as `PASSWORD_ID` or `VAULT_SECRET_ID`
- **Quoting:** surrounding `"`, `'`, or `` ` `` is stripped before detection.
  Output keeps the original bytes
- **Multiline:** a quoted or PEM value spanning several lines is one logical
  assignment. Masking it prints one line, and its continuation lines are never
  printed. Unmasked, `get` prints the whole value and `list --values` prints the
  first line

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
npm run build 2>&1 | envctl redact   # mask secrets in tool output
```

## Matching rules

| Kind      | Shape                                            |
| --------- | ------------------------------------------------ |
| Active    | optional `export`, then `KEY=...`                |
| Commented | leading `#` (optional whitespace), then the same |

A value that opens a quote (`"`, `'`, `` ` ``) or a `-----BEGIN` block runs until
its terminator, up to 512 lines. Those lines belong to the key, so `set`,
`disable`, `enable`, and `delete` move all of them. Mutating a key whose value
never terminates exits non-zero and writes nothing.

On `set`:

1. Update the first active definition in place
2. Comment out any extra active duplicates
3. If none active, revive the first commented definition
4. Otherwise append

Re-running with the same arguments is a no-op on content. `VALUE` is literal —
no shell or regex reinterpretation.

Keys must match `[A-Za-z_][A-Za-z0-9_]*`.

## Guarantees

- Only the target key’s logical assignment changes; a multiline value moves with
  its continuation lines
- Order, comments, and unrelated lines are preserved
- Atomic write (temp + rename); file mode preserved
- Secret-looking values are masked under the redact rules above; never on disk

## License

[MIT](LICENSE)
