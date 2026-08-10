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
| `envsrc`  | Process-environment source (`--env`, `env`)  |
| `diff`    | Unified diff for `--dry-run`                 |
| `fileio`  | Atomic writes and span rendering             |
| `agent`   | Coding agent detection                       |
| `help`    | Usage text                                   |
| `util`    | Memory helpers, `die`, buffers               |

## Test

```sh
make test
```

[`tests/run.sh`] is a harness and holds no test data. Every case is a file in
[`tests/cases/`], and every input and expectation is a file under
[`tests/fixtures/`]. A failure prints the case name and a diff. `V=1 make test`
also prints passing cases. To run against a specific binary:

```sh
bash tests/run.sh ./envctl
```

A case is a set of `%% <name>` sections. `args` holds one argv element per line,
so a value never passes through shell word splitting. `env` names a fixture that
is copied into a scratch directory, `stdin-file` names one to feed on stdin, and
`stdout`, `stderr`, `file` and `exit` are the expectations. Cases run under
`env -i` so agent detection sees a clean environment; `setenv` opts back in.
`fifo-file` names a fixture served through a FIFO in the scratch directory,
standing in for shell process substitution; `{FIFO}` in `args` expands to its
relative path. Such cases require `plain` mode and are skipped where `mkfifo` is
unusable (including MSYS).

A section runs to the next `%%` marker, and the blank line separating it from
that marker is layout rather than content, so one trailing blank is dropped.
Write two to end a section with a real blank line. When bytes are too subtle for
a section, such as output with no final newline, `stdout-file` points at a
fixture instead.

`mode` selects how the command runs:

| mode         | what it does                                                                        |
| ------------ | ----------------------------------------------------------------------------------- |
| `plain`      | default, stdout to a file                                                           |
| `pty`        | under `script`, so `stdout_isatty()` is true and automatic redaction applies        |
| `nosigpipe`  | under `env --ignore-signal=PIPE` with an early-closing reader, for the `EPIPE` path |
| `epipe-open` | stdin held open past two lines over FIFOs, for the per-write `EPIPE` check          |
| `posix-env`  | `plain`, but skipped on Windows, where the runtime reorders the environment block   |

`pty` needs `script` and `nosigpipe` needs GNU `env`; neither exists on Windows,
where those cases report as skipped in the summary rather than passing silently.
`posix-env` is for environ-order expectations (`envctl env`, `list --env`),
which only hold where the environment block passes through unmodified.

Every redaction fix needs a case that fails without it. Leaks and their
regression cases belong together in one commit.

### Completions

[`tests/completions.sh`] runs after the case suite and checks a different thing:
it drives each shell's completion function and asks the parser whether what came
back is valid. Reading the generated scripts cannot catch an emitter that puts
correct data where the shell applies it too widely, which is the defect it
exists for.

It drives bash, zsh, and fish, and fails when one of them is missing rather than
skipping it. `COMPLETIONS_SHELLS` narrows the set, which is how Windows CI runs
it with bash alone:

```sh
COMPLETIONS_SHELLS=bash bash tests/completions.sh ./envctl
```

The final line names the shells it drove, so a green run says what it covered.
It needs bash 4 for `mapfile` and associative arrays; macOS ships 3.2, so CI
installs a newer one there.

## Format and lint

```sh
dprint fmt                          # clang-format for C, shfmt for shell, plus md/json/yaml
shellcheck tests/*.sh install.sh    # https://github.com/koalaman/shellcheck
```

- dprint: https://dprint.dev/install/ (also requires clang-format on PATH),\
  both configured in [`.dprint.jsonc`]. Format using `dprint fmt [files...]`, or
  `make fmt`.
  - clang-format specifically takes it's config from [`.clang-format`], when
    invoked by dprint.
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
| `completions`    | Shell completion scripts and the pwsh module   |
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

[`.dprint.jsonc`]: .dprint.jsonc
[`.clang-format`]: .clang-format
[`tests/run.sh`]: tests/run.sh
[`tests/completions.sh`]: tests/completions.sh
[`tests/cases/`]: tests/cases/
[`tests/fixtures/`]: tests/fixtures/
[SECURITY.md]: SECURITY.md#reporting
