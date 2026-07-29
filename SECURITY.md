# Security

## Threat model

envctl's redaction is presentation hygiene. It keeps secrets out of terminal
output, diffs, and logs that pass through it. It is not a security boundary.

What it covers:

- `get`, `list --values`, and `--dry-run` mask secret-looking values on a TTY
  when a coding agent is detected, or always under `--redact`
- `envctl redact` masks secrets in any text piped through it, using the env
  file's literal values plus value-shape heuristics
- Disk writes are never redacted, so masking can never corrupt an env file

What it cannot cover:

- A process reading `.env` directly. `cat .env` never passes through envctl
- Captured pipes. `envctl get KEY` stays raw on a pipe by design, so command
  substitution keeps working. Whatever receives that value can leak it
- Output that never flows through the filter, including stderr of other tools

Containment against those requires the outer layer: an agent runner filtering
its own output, or filesystem policy keeping the env file unreadable. Piping an
agent's combined output through `envctl redact` is the intended deployment.

## Reporting a vulnerability

A value that escapes redaction when it should mask is a vulnerability. Report it
privately via [GitHub security advisories] and include the smallest input that
reproduces the leak. Do not open a public issue containing a working bypass.

Over-masking (an innocent value gets redacted) is a normal bug. Open a public
issue with the `false-positive` label.

What to expect after reporting:

- Acknowledgment and updates on the advisory thread as the report is worked on,
  with no committed timeline
- Accepted: the fix lands on `master` with a regression test and ships with the
  next release; the advisory is published once the fix is out, crediting you
  unless you prefer otherwise
- Declined: an explanation on the thread, usually because the report needs
  access the threat model above already concedes, such as reading `.env`
  directly

## Supported versions

Fixes land on `master` and ship with the next tag. No older release receives
backports.

| Version        | Supported |
| -------------- | --------- |
| Latest release | yes       |
| Older releases | no        |

## Verifying release artifacts

Every release publishes `SHA256SUMS` alongside the binaries. `install.sh`
verifies it automatically; for manual downloads:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

Releases after v0.1.0 also carry signed build provenance: a Sigstore attestation
binding each binary to the workflow run, repository, and commit that built it. A
tampered binary fails this check even when `SHA256SUMS` was regenerated to
match. Verify with an authenticated `gh`:

```sh
gh attestation verify envctl-linux-amd64 -R kjanat/envctl
```

`ENVCTL_ATTEST=1 install.sh` runs the same check during install and refuses to
install on failure.

[GitHub security advisories]: https://github.com/kjanat/envctl/security/advisories/new
