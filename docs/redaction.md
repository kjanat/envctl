# Redaction

Presentation hygiene, not a security boundary. It keeps secrets out of terminal
scrollback, screen shares, and agent transcripts. It is not a control you should
rely on to contain a secret; see [SECURITY.md](../SECURITY.md) for the threat
model.

Masked values become `<redacted>`, `<redacted:private-key>`, or
`<redacted:credentials>`. Never a partial value, never a suffix.

## When it is on

`--redact[=WHEN]` chooses the rule. A bare `--redact` means `always`.

| `--redact=` | Masks when                                    |
| ----------- | --------------------------------------------- |
| `never`     | never                                         |
| `auto`      | an agent is detected and stdout is a terminal |
| `agent`     | an agent is detected, terminal or not         |
| `tty`       | stdout is a terminal, agent or not            |
| `always`    | always                                        |

`auto` is the default, which leaves a human on a terminal unmasked and an agent
on a terminal masked. Agents usually capture stdout rather than owning a
terminal, and in that case `auto` does not mask, so that
`API_KEY=$(envctl get API_KEY)` keeps working. `--redact=agent` is the setting
that masks for an agent through a pipe as well.

Agent detection follows [unjs/std-env](https://github.com/unjs/std-env) signals,
plus `AI_AGENT`.

`envctl redact` always masks and refuses `--redact=never`.

`envctl env` masks unconditionally by default rather than following `auto`. An
explicit `--redact=WHEN` replaces that default and is honoured as written, so
`--redact=agent` leaves the dump unmasked when no agent is present, and
`--redact=tty` leaves it unmasked in a pipe. `--redact=never` drops the masking
but still escapes control bytes on a terminal; `--raw` drops both.

Disk writes are never redacted.

## Control bytes

Displayed values show C0 and DEL in caret notation, `^[` for ESC and `^J` for
newline, on a TTY and whenever redaction is on. Without it a `LESS_TERMCAP_*`
value restyles everything printed after it, and a value containing a newline can
forge extra `KEY=VALUE` lines in a dump.

Pipes keep raw bytes unless redaction is enabled. `--show-control-chars` turns
escaping off on its own, leaving masking alone, following `ls`, which keeps
`--color` and its control-character flags separate. `--raw` does both at once.

## What counts as a secret

### By key name

Case-insensitive. Both `_` and camelCase split a key into segments, so
`secretAccessKey` reads the same as `SECRET_ACCESS_KEY`.

`PASSWORD`, `PASS`, `PWD`, `SECRET`, `TOKEN`, `CREDENTIAL(S)`, `DSN`,
`MNEMONIC`, `SEED`+`PHRASE`, a credentialed `*_KEY` such as `API_KEY` or
`PRIVATE_KEY`, `DATABASE_URL`, `DB_URL`, `WEBHOOK_URL`.

### Compound names

A spelled-out secret word also counts when it ends the key's last segment,
because an English compound carries its head word last. `BW_CLIENTSECRET`,
`GITHUBTOKEN`, and `ADMINPASSWORD` match, and so do plurals such as
`DB_PASSWORDS`, `VAULT_SECRETS`, and `API_KEYS`. The same holds for `KEYSTORE`,
`WEBHOOK`, `DATABASEURL`, `CONNECTIONSTRING`, `SEEDPHRASE`, and a qualifier
joined to `KEY` such as `APIKEY` or `APIACCESSKEY`.

Only the last segment counts, so `accesstokenExpiry` stays visible. The
abbreviations `PASS`, `PWD`, `PSK`, `P12`, and a bare `KEY` still need a whole
segment, which keeps `BYPASS_HOSTS`, `COMPASS_HEADING`, and `KEYBOARD_LAYOUT`
visible.

### Not by name alone

Path-like final segments (`*_FILE`, `*_PATH`, `*_ENDPOINT`, `*_NAME`,
`*_VERSION`, `*_LENGTH`, `*_DIR`, `*_HOME`, webhook keys excepted) drop the key
to the entropy bar rather than masking outright.

Digest-like names (`*_SHA`, `*_SHA256`, `*_HASH`, `*_DIGEST`, `*_CHECKSUM`,
`*_ETAG`, `*_COMMIT`) mask only when the value itself looks secret.

### By value shape

PEM private keys, PuTTY private key files, and private JWKs (JSON carrying `kty`
plus `d` or `k`).

Credentialed URLs: `scheme://user:pass@host`, `scheme://token@host`,
scheme-relative `//user:pass@host`, and Go DSNs such as
`user:pass@tcp(host:port)/db`.

Slack and Discord webhook URLs whose trailing path segment is the credential.
URLs carrying `token=`, `api_key=`, `access_token=`, or `X-Amz-Signature=`,
including bare query strings with no scheme, which is how Azure SAS tokens
travel.

`Authorization: Bearer` and `Basic` values, connection-string fragments
(`;Password=`, `;Pwd=`, `sslkey=`), known token prefixes (`ghp_`, `sk_live_`,
`AKIA`, `A3T…`, `LS0tLS1` for a base64-wrapped PEM), and JWT compact form.

### Deliberately left visible

A token prefix counts only when the body its issuer puts after it follows, so
`npm_Pw6sYv9RtM3zXq7KbC2eNh8GdJ5fLa4u` masks while the variables npm hands every
script it runs (`npm_command`, `npm_config_*`, `npm_package_*`) stay readable.

JWT compact form needs its first two dotted segments to open with `ey`, the
base64url of a JSON object. Three dotted segments is also what an identifier
chain looks like, so a CI expression such as `steps.publish.outputs` survives.

Trivial values keep a value visible even under a strong secret name:
`true`/`false`, `yes`/`no`, `on`/`off`, `read`/`write` (`id-token: write` is a
permissions scope), `none`, `null`, `changeme`, log levels, `localhost`, and
short numerics.

`.pgpass` lines (`host:port:db:user:password`) are not detected. Five
colon-separated fields is too generic a shape to key on without masking ordinary
prose, so mask those by key name or with `--paranoid`.

### Entropy

Under a key name containing `KEY`, `API`, `AUTH`, `ACCESS`, `CRED`, `PASS`,
`JWT`, `BEARER`, `OAUTH`, `SESSION`, or `COOKIE`, a value clears the bar at 32+
hex characters with H > 3.0, or 24+ base64 characters or 16+ opaque characters
with H > 3.5.

UUIDs, paths, and URLs are exempt, and so is an `*_ID` key such as `SESSION_ID`
or `OAUTH_CLIENT_ID`, which still masks under a strong secret name like
`VAULT_SECRET_ID`. Two or more slashes read as a relative path unless the value
is strict base64.

`--paranoid` applies the entropy bar to every value whatever its key is called,
which closes cases like `RANDOM_THING=<44 random chars>`. Trivial values, plain
paths, and digest-like key names still stay visible.

## Quoting and multiline values

Surrounding `"`, `'`, or `` ` `` is stripped before detection, and the output
keeps the original bytes.

A quoted or PEM value spanning several lines is one logical assignment. Masked,
it prints as a single token line and its continuation lines are never printed.
Unmasked, `get` prints the whole value and `list --values` prints the first
line.

## Filter mode

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
carrying a key name, or on every line under `--paranoid`.

An assignment parses with or without spaces around its separator, so
`.aws/credentials` and other INI files that write `key = value` are covered, and
the key stays attached to its value either way.

`--no-env` skips the env file entirely. `--env` uses the process environment's
values as the literal mask set. Filter mode always redacts, so agent detection
and the TTY check do not apply.

A PEM private key prints as one `<redacted:private-key>` line and its body is
dropped. With no `-----END-----` marker the first 511 continuation lines are
suppressed; after that, base64-looking lines stay suppressed and the first
non-body line resumes normal processing.
