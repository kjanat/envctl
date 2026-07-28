# Contributing

## Build

```sh
make
```

Needs a C11 compiler (`cc` by default). Override with `CC=` / `CFLAGS=` /
`PREFIX=` as usual.\
The build must stay warning-free at `-Wall -Wextra -Wpedantic -Wshadow`.

## Source layout

| Module    | Purpose                                      |
| --------- | -------------------------------------------- |
| `main`    | CLI entry point and argument resolution      |
| `lines`   | Env parsing, logical spans, mutations        |
| `redact`  | Secret detection and the text scanner        |
| `mask`    | Literal value masking with encoding variants |
| `entropy` | Fixed-point Shannon entropy                  |
| `filter`  | `envctl redact` stream mode                  |
| `diff`    | Unified diff for `--dry-run`                 |
| `fileio`  | Atomic writes and span rendering             |
| `agent`   | Coding agent detection                       |
| `help`    | Usage text                                   |
| `util`    | Memory helpers, `die`, buffers               |

## Test

```sh
make test
```

The suite lives in [`tests/run.sh`]: named assertions, one `ok`/`FAIL` line
each, summary at the end. A failure prints the expectation and what actually
happened. `V=1 make test` also prints passing cases. To run against a specific
binary:

```sh
bash tests/run.sh ./envctl
```

Every redaction fix needs an assertion that fails without it. Leaks and their
regression tests belong together in one commit.

## Format and lint

```sh
dprint fmt                          # clang-format for C, shfmt for shell, plus md/json/yaml
shellcheck tests/run.sh install.sh  # https://github.com/koalaman/shellcheck
```

- dprint: https://dprint.dev/install/ (also requires clang-format on PATH)
- shellcheck: https://github.com/koalaman/shellcheck

CI runs `make test` on Linux, macOS, and Windows.

## Labels

| Label            | Use for                                        |
| ---------------- | ---------------------------------------------- |
| `leak`           | A secret escapes redaction                     |
| `false-positive` | Masks something it should not                  |
| `detector`       | Value-shape and key-name heuristics            |
| `filter`         | `envctl redact` stream mode                    |
| `parser`         | Env parsing, spans, quoting                    |
| `diff`           | Dry-run diff output                            |
| `atomicity`      | File writes, atomic replace, mode preservation |
| `agent-detect`   | Coding agent detection and TTY rules           |
| `portability`    | Windows, macOS, BSD behavior                   |
| `build`          | Makefile, CI, release artifacts                |
| `tests`          | Suite and harness                              |

A working redaction bypass is not an issue; see [SECURITY.md].

## Releasing

Push a version tag; CI builds the six artifacts, writes `SHA256SUMS`, attests
build provenance, and publishes a GitHub Release:

```sh
git tag -s v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

[`tests/run.sh`]: tests/run.sh
[SECURITY.md]: SECURITY.md#reporting
