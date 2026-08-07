# envctl — manage keys in env files

Edits a single key in place without disturbing order, comments, spacing, or any
other line. Writes are atomic (temp file + rename) and preserve the target’s
mode, so a crash mid-write never leaves a half-written env file.

## Install

### Prebuilt binaries

```sh
curl -fsSL https://raw.githubusercontent.com/kjanat/envctl/master/install.sh | bash
```

[`install.sh`] picks the release asset for your OS and architecture, verifies it
against `SHA256SUMS`, and installs it to `~/.local/bin`. Override with
`ENVCTL_INSTALL_DIR` and `ENVCTL_VERSION`:

```sh
ENVCTL_INSTALL_DIR=/usr/local/bin ENVCTL_VERSION=v0.1.0 bash install.sh
```

To pick an asset yourself, download from [GitHub Releases] (`linux-amd64`,
`linux-arm64`, `darwin-amd64`, `darwin-arm64`, `windows-amd64`,
`windows-arm64`):

```sh
# Example: Linux x86_64 → ~/.local/bin
curl -fsSL -o ~/.local/bin/envctl \
  https://github.com/kjanat/envctl/releases/latest/download/envctl-linux-amd64
chmod +x ~/.local/bin/envctl
```

With the `gh` CLI:

```sh
gh release download -R kjanat/envctl \
  --pattern envctl-linux-amd64 --output ~/.local/bin/envctl
chmod +x ~/.local/bin/envctl
```

Verify against `SHA256SUMS` on the same release when you care.

### From source

```sh
git clone https://github.com/kjanat/envctl.git
cd envctl
make
make install   # symlink → ~/.local/bin/envctl, man page → ~/.local/share/man/man1
```

One-liner:

```sh
git clone https://github.com/kjanat/envctl.git && cd envctl && make && make install
```

Needs a C11 compiler (`cc` by default). Override with `CC=` / `CFLAGS=` /
`PREFIX=` as usual. `make test` runs the assertion suite.

`src/cli.c` is the single registry of commands and flags: parser validation,
`--help`, and the man page are all built from it. `make man` regenerates
`man/envctl.1` through `gen/man.c`, and `make test` fails when the checked-in
page no longer matches. `HOSTCC=` builds the generator when cross-compiling.

Development, testing, and release workflow: [CONTRIBUTING.md].\
Threat model and vulnerability reporting: [SECURITY.md].

## Usage

```text
envctl set     [file] <KEY> [VALUE]   set/replace KEY (uncomments if commented)
envctl get     [file] <KEY>           print active value; exit 1 if unset
envctl disable [file] <KEY>           comment KEY out, keep its value
envctl enable  [file] <KEY>           uncomment KEY
envctl delete  [file] <KEY>           remove KEY entirely (active + commented)
envctl list    [file | --env] [--values] [--all]
envctl redact  [file | --env | --no-env]   filter stdin to stdout, masking secrets
envctl env                            print the process environment, always redacted
envctl completions <shell>            print a completion script for a shell
```

Aliases: `ls` = `list`, `rm` = `delete`.

### Default file

If the first positional is an existing path, it is used. Otherwise, when
`./.env` exists (as a regular file), it is assumed and you can omit the file
argument:

```sh
envctl list
envctl get DATABASE_URL
envctl set DEBUG true
```

Read commands (`get`, `list`, and `redact`'s env file) accept any openable path
— FIFOs from process substitution, `/dev/fd/N`, character devices — so
`envctl redact <(sops -d secrets.env)` works. The mutating commands (`set`,
`disable`, `enable`, `delete`) rewrite the target atomically and therefore
require a regular file; anything else fails with `not a regular file`.

### Bare form

If there is no command word:

```text
envctl [file] <KEY>            # get
envctl [file] <KEY> <VALUE>    # set
```

A command name always wins over a same-named file, so `envctl .env get API_KEY`
is a get. This includes `env` and `completions`: `envctl env` is the environment
dump command and `envctl completions` prints a completion script, so a key or
file literally named `env` or `completions` needs the explicit form
`envctl get env`.

### Flags

| Flag         | Applies to                             | Effect                                                                                          |
| ------------ | -------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `--dry-run`  | set, disable, enable, delete           | Print a unified diff to stdout; write nothing                                                   |
| `--values`   | list                                   | Show values (secret-looking ones follow redact rules)                                           |
| `--all`      | list, not with `--env`                 | Include disabled (commented) keys, tagged `(disabled)`                                          |
| `--sort`     | list, env                              | Print entries sorted by key instead of file or environ order                                    |
| `--env`      | get, list, redact                      | Read the process environment instead of an env file                                             |
| `--no-env`   | redact                                 | Skip the env file's literal values, use heuristics only                                         |
| `--redact`   | all but `completions`                  | Force masking; `redact` and `env` already mask unconditionally                                  |
| `--raw`      | all but `redact`, `env`, `completions` | Never mask (overrides auto-redact and `--redact`)                                               |
| `--paranoid` | all but `completions`                  | Apply the entropy bar whatever the key is called; path-like and digest-like values stay visible |

Using a flag outside its row is a usage error that names where it is valid, so
`envctl env --raw` reports
`--raw is only valid for set, get, disable, enable, delete, and list`. `redact`
takes a file, `--env`, or `--no-env`, never two of them. `--paranoid` implies
`--redact` and rejects `--raw`.

Help: `-h` for short usage, `--help` (or no args) for long help. With a command
word both print that command alone: its synopsis, description, and the flags it
accepts. `envctl get --help` and `envctl --help get` are the same thing, since
the command word is found wherever it sits. `man envctl` has the full reference,
and `-V`/`--version` prints the version baked into the build.

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
npm run build 2>&1 | envctl redact --env
```

The positional names the env file supplying literal values, defaulting to
`./.env` when it exists. Every maskable value in that file is matched literally,
together with its base64, URL-encoded, and JSON-escaped forms. The value-shape
heuristics then run over the rest of the text, and entropy applies only on lines
that carry a key name, or on every line under `--paranoid`. An assignment is
recognised with or without spaces around its separator, so `.aws/credentials`
and other INI files that write `key = value` are covered, and the key stays
attached to its value either way: under `--paranoid` a spaced `GIT_COMMIT = …`
keeps the same digest exemption its unspaced form gets. `--no-env` skips the env
file; `--env` uses the process environment's values as the literal mask set
instead of a file's. Filter mode always redacts, so agent detection and the TTY
check do not apply.

A PEM private key prints as one `<redacted:private-key>` line and its body lines
are dropped. If the `-----END-----` marker never arrives, the first 511
continuation lines are suppressed. After that, base64-looking body lines remain
suppressed, but the first non-body line resumes normal processing.

### Process environment

`--env` makes `get`, `list`, and `redact` read the process environment instead
of an env file — no `env` binary or process substitution needed:

```sh
envctl get --env DATABASE_URL     # like get: raw on pipes, exit 1 if unset
envctl list --env                 # key names, environ order
envctl list --env --sort          # key names, sorted
envctl list --env --values        # values follow the same redact rules as list
some-command | envctl redact --env
```

`envctl env` prints the whole environment as `KEY=VALUE` lines with redaction
always on (it rejects `--raw`, like filter mode), making it the safe one-word
replacement for `env | envctl redact --no-env`:

```console
$ envctl env
# envctl v0.4.2 (redacted)
PATH=/usr/bin:/bin
API_TOKEN=<redacted>
```

The first line names the version that produced the dump and marks the output as
redacted. Only `envctl env` prints it.

Entries are printed in environ order, or sorted by key with `--sort`. `list`
takes the same flag, for both a file and `--env`. Names that aren't
`[A-Za-z_][A-Za-z0-9_]*` (for example bash's exported functions) are skipped,
matching `list`. A masked multi-line value collapses to one token line; an
unmasked one shows its control bytes in caret notation (`^J` for a newline, `^[`
for ESC), keeping one entry per line where `env(1)` would let a `LESS_TERMCAP_*`
value restyle your terminal or an embedded newline forge extra entries.

### Redaction

Presentation hygiene only, not a security boundary; see [SECURITY.md] for what
that means. When redaction is on, values become `<redacted>`,
`<redacted:private-key>`, or `<redacted:credentials>`, never partial suffixes.

**When redaction is on**

| Situation                                     | Redact?                |
| --------------------------------------------- | ---------------------- |
| Human on a TTY                                | No (unless `--redact`) |
| Coding agent detected **and** stdout is a TTY | Yes (unless `--raw`)   |
| Piped / redirected / scripts                  | No (unless `--redact`) |

`get` stays raw on pipes so scripts and command substitution keep working. Agent
detection follows [unjs/std-env] signals (plus `AI_AGENT`).

Displayed values show control bytes in caret notation (ESC as `^[`, newline as
`^J`) on a TTY and whenever redaction is on; pipes keep raw bytes unless
redaction is enabled. `--raw` turns it off along with masking.

**What counts as secret**

- **Key names** (case-insensitive; `_` and camelCase both split into segments,
  so `secretAccessKey` reads the same as `SECRET_ACCESS_KEY`): `PASSWORD` /
  `PASS` / `PWD`, `SECRET`, `TOKEN`, `CREDENTIAL(S)`, `DSN`, `MNEMONIC`,
  `SEED`+`PHRASE`, credentialed `*_KEY` (e.g. `API_KEY`, `PRIVATE_KEY`),
  `DATABASE_URL` / `DB_URL`, `WEBHOOK_URL`, …
- **Compound key names:** a spelled-out secret word also counts when it closes a
  run with no separator in it, because an English compound carries its head word
  last, so `BW_CLIENTSECRET`, `GITHUBTOKEN`, and `ADMINPASSWORD` match. That
  covers `PASSWORD`, `PASSPHRASE`, `SECRET`, `TOKEN`, `CREDENTIAL(S)`,
  `KEYSTORE`, `MNEMONIC`, `WEBHOOK`, `DATABASEURL` / `DBURL`,
  `CONNECTIONSTRING`, `SEEDPHRASE`, and a qualifier joined to `KEY` (`APIKEY`,
  `ACCESSKEY`, `CLIENTKEY`). The abbreviations `PASS`, `PWD`, `PSK`, `P12`, and
  a bare `KEY` still need a segment of their own, which keeps `BYPASS_HOSTS`,
  `COMPASS_HEADING`, and `KEYBOARD_LAYOUT` visible
- **Not by name alone:** path-like final segments `*_FILE`, `*_PATH`,
  `*_ENDPOINT`, `*_NAME`, `*_VERSION`, `*_LENGTH`, `*_DIR`, `*_HOME` (webhook
  keys excepted), and digest-like names `*_SHA`, `*_SHA256`, `*_HASH`,
  `*_DIGEST`, `*_CHECKSUM`, `*_ETAG`, `*_COMMIT`. A path-like suffix drops the
  key to the entropy bar; a digest-like name masks only on value shape
- **Values:** PEM private keys, PuTTY private key files, private JWKs (JSON with
  `kty` plus `d` or `k`), credentialed URLs (`scheme://user:pass@host`,
  `scheme://token@host`, scheme-relative `//user:pass@host`, and Go DSNs such as
  `user:pass@tcp(host:port)/db`), Slack and Discord webhook URLs whose trailing
  path segment is the credential, URLs carrying `token=`, `api_key=`,
  `access_token=`, `X-Amz-Signature=`, … — including bare query strings with no
  scheme, as Azure SAS tokens are passed around, `Authorization: Bearer` /
  `Basic` values, connection-string fragments (`;Password=`, `;Pwd=`,
  `sslkey=`), known token prefixes (`ghp_`, `sk_live_`, `AKIA`, `A3T…`,
  `LS0tLS1` for a base64-wrapped PEM, …), JWT compact form
- **Not by prefix alone:** a token prefix counts only when the body its issuer
  puts after it follows — a long enough run of the right alphabet. So
  `npm_Pw6sYv9RtM3zXq7KbC2eNh8GdJ5fLa4u` masks while the variables npm hands
  every script it runs (`npm_command`, `npm_config_*`, `npm_package_*`) stay
  visible
- **Not by dotted shape alone:** JWT compact form needs its first two segments
  to open with `ey`, the base64url of a JSON object, since three dotted segments
  is also what an identifier chain looks like — a CI expression such as
  `steps.publish.outputs` stays visible
- **Trivial values:** `true`/`false`, `yes`/`no`, `on`/`off`, `read`/`write`
  (`id-token: write` is a permissions scope, not a token), `none`, `null`,
  `changeme`, log levels, `localhost`, and short numerics keep a value visible
  even under a strong secret name
- **Entropy:** under a key name containing `KEY`, `API`, `AUTH`, `ACCESS`,
  `CRED`, `PASS`, `JWT`, `BEARER`, `OAUTH`, `SESSION` (e.g. `BW_SESSION`), or
  `COOKIE`, a value clears the bar at 32+ hex characters with H > 3.0, or 24+
  base64 characters or 16+ opaque characters with H > 3.5. UUIDs, paths, and
  URLs are exempt, and so is a `*_ID` key (`SESSION_ID`, `OAUTH_CLIENT_ID`),
  which still masks under a strong secret name such as `PASSWORD_ID` or
  `VAULT_SECRET_ID`. Two or more slashes read as a relative path, unless the
  value is strict base64 — either `=`-padded, or unpadded with separator slashes
  sparser than one in sixteen characters
- **`--paranoid`:** applies the entropy bar to every value, whatever its key is
  called, closing values like `RANDOM_THING=<44 random chars>`. Trivial values,
  plain paths, and digest-like key names stay visible
- **Not detected:** `.pgpass` lines (`host:port:db:user:password`). Five
  colon-separated fields are too generic a shape to key on without masking
  ordinary text, so mask those by key name or with `--paranoid`
- **Quoting:** surrounding `"`, `'`, or `` ` `` is stripped before detection.
  Output keeps the original bytes
- **Multiline:** a quoted or PEM value spanning several lines is one logical
  assignment. Masking it prints one line, and its continuation lines are never
  printed. Unmasked, `get` prints the whole value and `list --values` prints the
  first line

Disk writes are never redacted.

### Shell completions

`envctl completions <shell>` writes a completion script to stdout for `bash`,
`zsh`, `fish`, or `pwsh`. The script is generated from the same command and flag
tables the parser uses, so it offers exactly the flags each command accepts and
never drifts from the binary.

`make install` writes the bash, zsh, and fish scripts under `$(PREFIX)`. To
install by hand, or to load without installing:

```sh
# bash
envctl completions bash > ~/.local/share/bash-completion/completions/envctl
source <(envctl completions bash)              # current shell only

# zsh — the directory must be in $fpath, before compinit runs
envctl completions zsh > ~/.local/share/zsh/site-functions/_envctl

# fish
envctl completions fish > ~/.config/fish/completions/envctl.fish
envctl completions fish | source               # current shell only
```

PowerShell is not installed by `make install`. Append it to your profile:

```powershell
envctl completions pwsh | Out-String | Invoke-Expression          # current session
envctl completions pwsh >> $PROFILE                               # persistent
```

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
envctl env                           # print the environment, secrets masked
envctl get --env HOME                # read an environment variable
envctl get --help                    # help for one command
envctl completions zsh               # completion script for zsh
```

## Matching rules

| Kind      | Shape                                            |
| --------- | ------------------------------------------------ |
| Active    | optional whitespace and `export`, then `KEY=...` |
| Commented | leading `#` (optional whitespace), then the same |

A value that opens a quote (`"`, `'`, `` ` ``) or a `-----BEGIN` block runs
until its terminator, up to 512 lines. Those lines belong to the key, so `set`,
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

[MIT][LICENSE]

[CONTRIBUTING.md]: CONTRIBUTING.md
[LICENSE]: LICENSE
[SECURITY.md]: SECURITY.md
[`install.sh`]: install.sh
[GitHub Releases]: https://github.com/kjanat/envctl/releases
[unjs/std-env]: https://github.com/unjs/std-env
