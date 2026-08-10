# Command reference

Every command, what it does, and the rules it follows. `man envctl` and
`envctl <cmd> --help` carry the same reference, generated from the same table
the parser validates against.

## Reading

```sh
envctl get [file] <KEY>       # print the active value, exit 1 if unset
envctl list [file]            # print active key names
envctl list [file] --values   # print KEY=VALUE
envctl list [file] --all      # include commented keys, tagged (disabled)
envctl list [file] --sort     # key order instead of file order
```

`get` prints the value followed by a newline. A multiline value prints in full.
`list --values` prints the first line of an unmasked multiline value.

## Editing

```sh
envctl set     [file] <KEY> [VALUE]   # create or replace
envctl disable [file] <KEY>           # comment out, keep the value
envctl enable  [file] <KEY>           # uncomment
envctl delete  [file] <KEY>           # remove active and commented alike
```

Aliases: `rm` for `delete`, `ls` for `list`.

`VALUE` is literal. Nothing reinterprets it as shell syntax or a regex. An
omitted `VALUE` writes an empty value.

### What `set` does

1. Update the first active definition in place.
2. Comment out any further active duplicates.
3. If no active definition exists, revive the first commented one.
4. Failing all of that, append the assignment.

Running the same `set` twice changes nothing the second time.

### Preview a change

`--dry-run` prints a unified diff and writes nothing:

```console
$ envctl --dry-run set .env FOO two
--- .env
+++ .env
@@ -1,1 +1,1 @@
-FOO=one
+FOO=two
```

Only changed lines appear. When the command would change nothing, stdout stays
empty and `envctl: no changes` goes to stderr. Under `--redact` both sides are
masked and the header reads `+++ .env (redacted)`.

## The process environment

```sh
envctl get --env DATABASE_URL   # like get, but from the environment
envctl list --env               # key names in environ order
envctl list --env --values      # values, under the redact rules
envctl env                      # the whole environment, always redacted
```

`envctl env` is the safe one-word replacement for `env`:

```console
$ envctl env
PATH=/usr/bin:/bin
API_TOKEN=<redacted>
```

Names outside `[A-Za-z_][A-Za-z0-9_]*` are skipped, which drops bash's exported
functions. `envctl env` masks unconditionally by default. An explicit
`--redact=WHEN` replaces that default, so `--redact=agent` leaves the dump
unmasked when no agent is detected. `--redact=never` drops the masking but still
escapes control bytes on a terminal; `--raw` drops both.

## Filtering text

```sh
some-command 2>&1 | envctl redact
```

`redact` reads stdin and writes stdout with secrets masked. See
[redaction.md](redaction.md) for what it looks for and how the env file feeds
it.

## Which file

If the first positional is an existing path, it is used. Otherwise `./.env` is
assumed when it exists as a regular file:

```sh
envctl list
envctl get DATABASE_URL
envctl set DEBUG true
```

Read commands accept any openable path, including FIFOs from process
substitution and `/dev/fd/N`, so `envctl redact <(sops -d secrets.env)` works.
Mutating commands rewrite the target atomically and therefore need a regular
file; anything else fails with `not a regular file`.

## Without a command word

```sh
envctl [file] <KEY>           # get
envctl [file] <KEY> <VALUE>   # set
```

A command name always beats a same-named file or key. So `envctl .env get X` is
a get, and a key literally named `env`, `completions`, or `module` needs the
explicit form `envctl get env`.

## Flags

| Flag                   | Applies to                          | Effect                                                        |
| ---------------------- | ----------------------------------- | ------------------------------------------------------------- |
| `--dry-run`            | set, disable, enable, delete        | Print a unified diff, write nothing                           |
| `--values`             | list                                | Show values                                                   |
| `--all`                | list, not with `--env`              | Include commented keys, tagged `(disabled)`                   |
| `--sort`               | list, env                           | Key order instead of file or environ order                    |
| `--env`                | get, list, redact                   | Use the process environment instead of a file                 |
| `--no-env`             | redact                              | Skip the env file's literal values, heuristics only           |
| `--redact[=WHEN]`      | all but completions, module         | Choose when masking applies, see [redaction.md](redaction.md) |
| `--raw`                | all but redact, completions, module | Shorthand for `--redact=never --show-control-chars`           |
| `--show-control-chars` | all but redact, completions, module | Print control bytes as they are                               |
| `--paranoid`           | all but completions, module         | Apply the entropy bar whatever the key is called              |

A flag outside its row is a usage error naming where it belongs:

```console
$ envctl get --values FOO
envctl: --values is only valid for list
```

`redact` takes a file, `--env`, or `--no-env`, never two of them. `--paranoid`
implies `--redact` and rejects `--raw`.

## Help and version

```sh
envctl -h                # short usage
envctl --help            # long help
envctl get --help        # one command, with only the flags it accepts
man envctl               # full reference
envctl --version         # the version this binary was built from
```

`envctl get --help` and `envctl --help get` do the same thing, since the command
word is found wherever it sits.

## File format

| Kind      | Shape                                            |
| --------- | ------------------------------------------------ |
| Active    | optional whitespace and `export`, then `KEY=...` |
| Commented | leading `#`, optional whitespace, then the same  |

Keys must match `[A-Za-z_][A-Za-z0-9_]*`.

A value that opens a quote (`"`, `'`, `` ` ``) or a `-----BEGIN` block runs
until its terminator, up to 512 lines. Those continuation lines belong to the
key, so `set`, `disable`, `enable`, and `delete` move all of them together.
Mutating a key whose value never terminates writes nothing and exits non-zero.

A file containing a NUL byte is rejected rather than silently truncated there.

## Exit codes

| Code | Meaning                                                                 |
| ---- | ----------------------------------------------------------------------- |
| 0    | Success                                                                 |
| 1    | `get` found no active definition of the key                             |
| 2    | Usage error, unreadable or unwritable file, or a failed write to stdout |

## Guarantees

- Only the target key's logical assignment changes, continuation lines included.
- Order, comments, spacing, and unrelated lines survive untouched.
- Writes are atomic (temp file plus rename) and preserve the file mode.
- Redaction never applies to what lands on disk.
