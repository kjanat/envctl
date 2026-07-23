#include "help.h"

#include "agent.h"

#include <stdio.h>
#include <stdlib.h>

static const char *SHORT_USAGE = "usage: envctl [<cmd>] [file] <KEY> [VALUE]\n"
                                 "  commands: set get disable enable delete|rm list|ls\n"
                                 "  file:     optional when ./.env exists\n"
                                 "  bare:     envctl [file] <KEY>          == get\n"
                                 "            envctl [file] <KEY> <VALUE>  == set\n"
                                 "  flags:    --values --all (list)  --dry-run  --redact --raw\n";

static const char *AI_PREAMBLE =
    "You are an AI coding agent. Use envctl to change a key in any env / .env-style file.\n"
    "NEVER hand-edit an env file to add, change, comment, or remove a key -\n"
    "envctl does it in place, atomically, preserving order, comments, and mode.\n"
    "If ./.env exists you may omit the file argument. Secret-looking values are\n"
    "redacted on a TTY by default; use --raw only when you truly need full secrets.\n\n";

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
    "\n"
    "File: optional when ./.env exists as a regular file. If the first positional is\n"
    "an existing regular file, it is used; otherwise .env is assumed when present.\n"
    "\n"
    "Bare form (no command word):\n"
    "  envctl [file] <KEY>            == get\n"
    "  envctl [file] <KEY> <VALUE>    == set\n"
    "\n"
    "Flags:\n"
    "  --dry-run   mutating command: print the result, write nothing\n"
    "  --values    list: show values (secret-looking ones follow redact rules)\n"
    "  --all       list: include disabled keys tagged (disabled)\n"
    "  --redact    mask secret-looking values on get / list --values / dry-run\n"
    "  --raw       never mask (overrides auto-redact and --redact)\n"
    "\n"
    "Redaction (presentation only — pipes/scripts stay raw so get stays composable):\n"
    "  mask as <redacted> / <redacted:private-key> / <redacted:credentials> when on.\n"
    "  Signals: key-name segments (case-insensitive), PEM private keys, credentialed\n"
    "  URLs, known token prefixes, JWTs; path-like key suffixes (*_FILE/*_PATH) only\n"
    "  mask when the value itself looks secret. Multiline PEM bodies are suppressed.\n"
    "Default on when a coding agent is detected and stdout is a TTY; off when\n"
    "stdout is piped/redirected unless --redact. --raw always shows full secrets.\n"
    "\n"
    "Guarantees: only the target key's line changes; re-running with the same args\n"
    "is a no-op; writes are atomic (temp + rename) and preserve file mode; VALUE is\n"
    "literal (no shell/regex reinterpretation).\n";

NORETURN void print_help(int longform) {
	if (!longform) {
		fputs(SHORT_USAGE, stdout);
	} else {
		if (detect_agent())
			fputs(AI_PREAMBLE, stdout);
		fputs(LONG_USAGE, stdout);
	}
	exit(0);
}
