#include "help.h"

#include "agent.h"

#include <stdio.h>
#include <stdlib.h>

static const char *SHORT_USAGE =
    "usage: envctl <cmd> [file] [args...]\n"
    "       envctl [file] <KEY> [VALUE]\n"
    "  commands: set get disable enable delete|rm list|ls redact env\n"
    "  file:     optional when ./.env exists\n"
    "  bare:     envctl [file] <KEY>          == get\n"
    "            envctl [file] <KEY> <VALUE>  == set\n"
    "  flags:    --values --all (list)  --env (get/list/redact)  --no-env (redact)\n"
    "            --dry-run  --redact --raw\n"
    "  version:  -v | -V | --version\n";

static const char *AI_PREAMBLE =
    "You are an AI coding agent. Use envctl to change a key in any env / .env-style file.\n"
    "NEVER hand-edit an env file to add, change, comment, or remove a key -\n"
    "envctl does it in place, atomically, preserving order, comments, and mode.\n"
    "If ./.env exists you may omit the file argument. Secret-looking values are\n"
    "redacted on a TTY by default; use --raw only when you truly need full secrets.\n"
    "Pipe command output through 'envctl redact' to mask secrets in what you print.\n\n";

static const char *LONG_USAGE =
    "envctl — manage keys in env files\n"
    "\n"
    "Commands:\n"
    "  envctl set     [file] <KEY> [VALUE]   set/replace KEY (uncomments if commented)\n"
    "  envctl get     [file] <KEY>           print active value; exit 1 if unset\n"
    "  envctl disable [file] <KEY>           comment KEY out, keep its value\n"
    "  envctl enable  [file] <KEY>           uncomment KEY\n"
    "  envctl delete  [file] <KEY>           remove KEY entirely (active + commented) [rm]\n"
    "  envctl list    [file] [--values] [--all]  active keys; --values shows values;\n"
    "                                        --all also lists disabled keys           [ls]\n"
    "  envctl redact  [file | --env | --no-env]  filter stdin to stdout, masking secrets\n"
    "  envctl env                            print process environment, always redacted\n"
    "\n"
    "File: optional when ./.env exists as a regular file. If the first positional is\n"
    "an existing path, it is used; otherwise .env is assumed when present. Read\n"
    "commands (get, list, redact's env file) accept any openable path, including\n"
    "FIFOs from process substitution and /dev/fd/N; set/disable/enable/delete\n"
    "require a regular file.\n"
    "\n"
    "Bare form (no command word):\n"
    "  envctl [file] <KEY>            == get\n"
    "  envctl [file] <KEY> <VALUE>    == set\n"
    "\n"
    "Flags:\n"
    "  --dry-run   mutating command: print a unified diff, write nothing\n"
    "  --values    list: show values (secret-looking ones follow redact rules)\n"
    "  --all       list: include disabled keys tagged (disabled)\n"
    "  --env       get/list/redact: use the process environment instead of a file\n"
    "              (get --env KEY, list --env, redact --env; rejected elsewhere)\n"
    "  --no-env    redact: skip the env file's literal values, use heuristics only\n"
    "              (redact takes a file, --env, or --no-env, never two of them)\n"
    "  --redact    mask secret-looking values on get / list --values / dry-run\n"
    "  --raw       never mask (overrides auto-redact and --redact; redact rejects it)\n"
    "  -V, --version  print the version this binary was built from (also -v)\n"
    "\n"
    "Redaction (presentation only; pipes and scripts stay raw so get stays composable):\n"
    "  mask as <redacted> / <redacted:private-key> / <redacted:credentials> when on.\n"
    "  Signals: key-name segments (case-insensitive), PEM private keys, PuTTY keys,\n"
    "  private JWKs, credentialed URLs, sensitive URL query parameters, Bearer and\n"
    "  Basic values, connection-string password fragments, known token prefixes,\n"
    "  JWTs, and Shannon entropy under a suspicious key name. Path-like key suffixes\n"
    "  (*_FILE/*_PATH/*_NAME) and digest-like key names (*_SHA/*_HASH/*_COMMIT) mask\n"
    "  only when the value itself looks secret; *_ID keys skip the entropy bar but\n"
    "  still mask under a strong secret name. A multiline quoted or PEM value masks\n"
    "  to one line and its continuation lines are never printed.\n"
    "Default on when a coding agent is detected and stdout is a TTY; off when\n"
    "stdout is piped/redirected unless --redact. --raw always shows full secrets.\n"
    "\n"
    "Filter mode: envctl redact reads stdin and writes stdout with secrets masked.\n"
    "  It always redacts and rejects --raw. Every maskable value in the env file is\n"
    "  matched literally, together with its base64, URL-encoded and JSON-escaped\n"
    "  forms; value-shape heuristics then run over the rest of the text. Entropy\n"
    "  applies only where a key name is present. A PEM private key prints as one\n"
    "  <redacted:private-key> line and its body is dropped. With no END marker, 511\n"
    "  lines drop unconditionally, then only base64-shaped lines stay suppressed.\n"
    "  redact --env masks the process environment's literal values instead of a\n"
    "  file's; envctl env prints the environment itself with the same always-on\n"
    "  redaction.\n"
    "\n"
    "Guarantees: only the target key's logical assignment changes (a multiline value\n"
    "moves with its continuation lines); re-running with the same args is a no-op;\n"
    "writes are atomic (temp + rename) and preserve file mode; VALUE is literal (no\n"
    "shell/regex reinterpretation).\n";

#ifndef ENVCTL_VERSION
#define ENVCTL_VERSION "unknown"
#endif

NORETURN void print_version(void) {
	fputs(ENVCTL_VERSION "\n", stdout);
	stdout_flush_check();
	exit(0);
}

NORETURN void print_help(int longform) {
	if (!longform) {
		fputs(SHORT_USAGE, stdout);
	} else {
		if (detect_agent())
			fputs(AI_PREAMBLE, stdout);
		fputs(LONG_USAGE, stdout);
	}
	stdout_flush_check();
	exit(0);
}
