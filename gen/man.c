#include "cli.h"

#include <stdio.h>
#include <string.h>

static void roff_escape_n(const char *s, size_t n) {
	for (size_t i = 0; i < n; i++) {
		if (s[i] == '\\')
			fputs("\\e", stdout);
		else if (s[i] == '-')
			fputs("\\-", stdout);
		else if (s[i] == '`')
			fputs("\\(ga", stdout);
		else if (s[i] == '\'')
			fputs("\\(aq", stdout);
		else
			fputc(s[i], stdout);
	}
}

static void roff_escape(const char *s) { roff_escape_n(s, strlen(s)); }

/* A line opening with '.' or '\'' is a roff control line, so text starting that way needs \&. */
static void roff_lines(const char *s, const char *between) {
	for (const char *p = s;;) {
		const char *nl = strchr(p, '\n');
		if (*p == '.' || *p == '\'')
			fputs("\\&", stdout);
		roff_escape_n(p, nl ? (size_t)(nl - p) : strlen(p));
		fputc('\n', stdout);
		if (!nl)
			return;
		fputs(between, stdout);
		p = nl + 1;
	}
}

static void roff_paragraphs(const char *s) { roff_lines(s, ".PP\n"); }

static void section(const char *name, const char *body) {
	printf(".SH %s\n", name);
	roff_paragraphs(body);
}

static void valid_for(unsigned mask) {
	int total = 0, seen = 0;

	for (int i = 0; i < CMD_COUNT; i++) {
		if (mask & CMD_BIT(cli_commands[i].id))
			total++;
	}
	fputs("Valid for: ", stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		if (!(mask & CMD_BIT(cli_commands[i].id)))
			continue;
		if (seen > 0)
			fputs(seen == total - 1 ? (total == 2 ? " and " : ", and ") : ", ", stdout);
		fputs(cli_commands[i].name, stdout);
		seen++;
	}
	fputs(".\n", stdout);
}

static const char *DESCRIPTION =
    "envctl edits a single key in an env file in place, without disturbing order, comments, "
    "spacing, or any other line. Writes are atomic (temp file plus rename) and preserve the "
    "target's mode, so a crash mid-write never leaves a half-written env file.\n"
    "If the first positional is an existing path it names the file. Otherwise ./.env is assumed "
    "when it exists as a regular file. The read commands (get, list, and redact's env file) "
    "accept any openable path, including FIFOs from process substitution, /dev/fd/N, and "
    "character devices, so envctl redact <(sops -d secrets.env) works. The mutating commands "
    "(set, disable, enable, delete) rewrite the target atomically and therefore require a regular "
    "file; anything else fails with 'not a regular file'.\n"
    "With no command word, envctl [file] <KEY> is a get and envctl [file] <KEY> <VALUE> is a set. "
    "A command name always wins over a same-named file, so envctl .env get API_KEY is a get. That "
    "includes env: a key literally named env needs envctl get env.\n"
    "Keys must match [A-Za-z_][A-Za-z0-9_]*. An active assignment is optional whitespace and "
    "export, then KEY=...; a commented one is a leading # before the same. A value that opens a "
    "quote (\", ', or `) or a -----BEGIN block runs until its terminator, up to 512 lines, and "
    "those lines belong to the key, so set, disable, enable, and delete move all of them. "
    "Mutating a key whose value never terminates exits non-zero and writes nothing.";

static const char *REDACTION =
    "Redaction is presentation hygiene, not a security boundary. When it is on, values print as "
    "<redacted>, <redacted:private-key>, or <redacted:credentials>, never as partial suffixes. "
    "Disk writes are never redacted.\n"
    "It is on by default when a coding agent is detected and stdout is a TTY, and off when stdout "
    "is piped or redirected unless --redact is given. Agent detection follows the unjs/std-env "
    "signals plus AI_AGENT. get stays raw on pipes so scripts and command substitution keep "
    "working. --raw always shows full secrets. redact and env always redact and reject --raw.\n"
    "Displayed values show control bytes in caret notation (ESC as ^[, newline as ^J) on a TTY "
    "and whenever redaction is on; pipes keep raw bytes unless redaction is enabled. --raw turns "
    "it off along with masking.\n"
    "The signals are: key-name segments (case-insensitive, with both _ and camelCase splitting, "
    "so secretAccessKey reads as SECRET_ACCESS_KEY), PEM private keys, PuTTY private key files, "
    "private JWKs, credentialed URLs (user:pass@, token@, scheme-relative, and Go tcp()/unix() "
    "DSNs), Slack and Discord webhook URLs, sensitive URL query parameters with or without a "
    "scheme, Bearer and Basic values, connection-string password fragments, known token prefixes, "
    "JWTs, and Shannon entropy under a suspicious key name.\n"
    "A spelled-out secret word also counts when it closes a run with no separator in it, because "
    "an English compound carries its head word last, so BW_CLIENTSECRET, GITHUBTOKEN, and "
    "ADMINPASSWORD match. The abbreviations PASS, PWD, PSK, P12, and a bare KEY still need a "
    "segment of their own, which keeps BYPASS_HOSTS, COMPASS_HEADING, and KEYBOARD_LAYOUT "
    "visible.\n"
    "Path-like key suffixes (*_FILE, *_PATH, *_ENDPOINT, *_NAME, *_VERSION, *_LENGTH, *_DIR, "
    "*_HOME, webhook keys excepted) drop the key to the entropy bar, and digest-like key names "
    "(*_SHA, *_SHA256, *_HASH, *_DIGEST, *_CHECKSUM, *_ETAG, *_COMMIT) mask only when the value "
    "itself looks secret. A *_ID key skips the entropy bar but still masks under a strong secret "
    "name such as PASSWORD_ID. A token prefix counts only when the body its issuer puts after it "
    "follows, so npm_Pw6sYv9RtM3zXq7KbC2eNh8GdJ5fLa4u masks while npm_config_* stays visible. JWT "
    "compact form needs its first two segments to open with ey, so a CI expression such as "
    "steps.publish.outputs stays visible.\n"
    "Trivial values keep a value visible even under a strong secret name: true/false, yes/no, "
    "on/off, read/write, none, null, changeme, log levels, localhost, and short numerics. Under a "
    "key name containing KEY, API, AUTH, ACCESS, CRED, PASS, JWT, BEARER, OAUTH, SESSION, or "
    "COOKIE, a value clears the entropy bar at 32+ hex characters with H > 3.0, or 24+ base64 "
    "characters or 16+ opaque characters with H > 3.5. UUIDs, paths, and URLs are exempt.\n"
    ".pgpass lines (host:port:db:user:password) are not detected: five colon-separated fields are "
    "too generic a shape to key on without masking ordinary text, so mask those by key name or "
    "with --paranoid.\n"
    "Surrounding \", ', or ` is stripped before detection and the output keeps the original "
    "bytes. A quoted or PEM value spanning several lines is one logical assignment: masking it "
    "prints one line and its continuation lines are never printed.";

static const char *FILTER_MODE =
    "envctl redact reads stdin and writes stdout with secrets masked. It always redacts and "
    "rejects --raw, so agent detection and the TTY check do not apply.\n"
    "Every maskable value in the env file is matched literally, together with its base64, "
    "URL-encoded, and JSON-escaped forms. The value-shape heuristics then run over the rest of "
    "the text, and entropy applies only on lines that carry a key name, or on every line under "
    "--paranoid. An assignment parses with or without spaces around its separator, so INI files "
    "such as .aws/credentials are covered, and the key stays attached to its value either way: "
    "under --paranoid a spaced GIT_COMMIT = ... keeps the same digest exemption its unspaced form "
    "gets.\n"
    "A PEM private key prints as one <redacted:private-key> line and its body lines are dropped. "
    "If the -----END----- marker never arrives, the first 511 continuation lines are suppressed; "
    "after that, base64-looking body lines remain suppressed but the first non-body line resumes "
    "normal processing.\n"
    "--no-env skips the env file. --env uses the process environment's values as the literal mask "
    "set instead of a file's.";

static const char *GUARANTEES =
    "Only the target key's logical assignment changes, and a multiline value moves with its "
    "continuation lines.\n"
    "Order, comments, and unrelated lines are preserved.\n"
    "Re-running with the same arguments is a no-op on content.\n"
    "Writes are atomic (temp plus rename) and preserve the file mode.\n"
    "VALUE is literal: no shell or regex reinterpretation.\n"
    "Secret-looking values are masked under the rules in REDACTION, and never on disk.\n"
    "On set, the first active definition is updated in place, further active duplicates are "
    "commented out, an inactive definition is revived when no active one exists, and otherwise "
    "the assignment is appended.";

static const char *EXAMPLES = "envctl set .env DATABASE_URL 'postgres://localhost/app'\n"
                              "envctl get DATABASE_URL\n"
                              "envctl disable DEBUG\n"
                              "envctl list --values --all\n"
                              "envctl --dry-run delete OLD_KEY\n"
                              "envctl --redact get API_TOKEN\n"
                              "envctl --raw list --values\n"
                              "npm run build 2>&1 | envctl redact\n"
                              "envctl redact <(sops -d secrets.env) < build.log\n"
                              "envctl env\n"
                              "envctl get --env HOME";

static const char *EXIT_STATUS =
    "0 on success.\n"
    "1 when get finds no active definition of KEY.\n"
    "2 on a usage error, an unreadable or unwritable file, or a failed write to stdout.";

int main(void) {
	fputs(".TH ENVCTL 1 \"\" \"envctl\" \"General Commands Manual\"\n", stdout);

	fputs(".SH NAME\n"
	      "envctl \\- manage keys in env files\n",
	      stdout);

	fputs(".SH SYNOPSIS\n", stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		fputs(".B envctl ", stdout);
		roff_escape(cli_commands[i].name);
		if (cli_commands[i].args[0]) {
			fputs("\n.RI ", stdout);
			fputs("\"", stdout);
			roff_escape(cli_commands[i].args);
			fputs("\"", stdout);
		}
		fputs("\n.br\n", stdout);
	}
	fputs(".B envctl\n.RI \"[file] <KEY> [VALUE]\"\n", stdout);

	section("DESCRIPTION", DESCRIPTION);

	fputs(".SH COMMANDS\n", stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		fputs(".TP\n.B ", stdout);
		roff_escape(cli_commands[i].name);
		if (cli_commands[i].args[0]) {
			fputc(' ', stdout);
			roff_escape(cli_commands[i].args);
		}
		fputc('\n', stdout);
		roff_paragraphs(cli_commands[i].description);
		if (cli_commands[i].alias) {
			fputs("Alias: ", stdout);
			roff_escape(cli_commands[i].alias);
			fputs(".\n", stdout);
		}
	}

	fputs(".SH OPTIONS\n", stdout);
	for (int i = 0; i < FLAG_COUNT; i++) {
		fputs(".TP\n.B ", stdout);
		roff_escape(cli_flags[i].name);
		fputc('\n', stdout);
		roff_paragraphs(cli_flags[i].description);
		valid_for(cli_flags[i].commands);
	}
	fputs(".TP\n.B \\-h\n"
	      "Print the short usage summary and exit.\n"
	      ".TP\n.B \\-\\-help\n"
	      "Print the long help and exit. With no arguments at all, envctl prints it too.\n"
	      ".TP\n.B \\-V\n"
	      "Print the version this binary was built from and exit. Also \\-v and \\-\\-version.\n",
	      stdout);

	section("REDACTION", REDACTION);
	section("FILTER MODE", FILTER_MODE);

	fputs(".SH GUARANTEES\n", stdout);
	fputs(".IP \\(bu 2\n", stdout);
	roff_lines(GUARANTEES, ".IP \\(bu 2\n");

	fputs(".SH EXAMPLES\n.nf\n", stdout);
	roff_lines(EXAMPLES, "");
	fputs(".fi\n", stdout);

	section("EXIT STATUS", EXIT_STATUS);

	fputs(".SH SEE ALSO\n"
	      ".BR env (1),\n"
	      ".BR printenv (1)\n"
	      ".PP\n"
	      "Project home: https://github.com/kjanat/envctl\n",
	      stdout);

	if (fflush(stdout) != 0 || ferror(stdout)) {
		fputs("man: write failed\n", stderr);
		return 1;
	}
	return 0;
}
