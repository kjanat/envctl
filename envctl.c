/*
 * envctl — manage keys in env files (C port of envctl.sh).
 *
 * Edits a single KEY in place without disturbing order, comments, spacing, or
 * any other line. Writes atomically (temp file + rename) and preserves the
 * target's mode, so a crash mid-write can never leave a half-written env file.
 *
 *   envctl set     [file] <KEY> [VALUE]   set/replace KEY (uncomments if needed)
 *   envctl get     [file] <KEY>           print active value, exit 1 if unset
 *   envctl disable [file] <KEY>           comment KEY out, keep its value
 *   envctl enable  [file] <KEY>           uncomment KEY
 *   envctl delete  [file] <KEY>           remove KEY entirely (active + commented)
 *   envctl list    [file] [--values] [--all]
 *
 * Aliases: ls = list, rm = delete.
 * File is optional when ./.env exists as a regular file; an explicit path always
 * wins when the first positional is an existing regular file.
 * Bare form (no command word): `<file> <KEY>` / `<KEY>` == get,
 * `<file> <KEY> <VALUE>` / `<KEY> <VALUE>` == set (with .env).
 * A command name wins over a same-named file.
 *
 * Flags: --dry-run prints the result, writes nothing.
 *        --redact / --raw force secret masking on or off for get, list --values,
 *        and dry-run. Default: redact when a coding agent is detected and stdout
 *        is a TTY (not when piped or used non-interactively), unless --raw.
 *
 * Help: `-h` prints the short usage; `--help` (or no args) prints the long help.
 * Inside a detected AI coding agent (per unjs/std-env), the long help is prefixed
 * with an agent-oriented preamble.
 *
 * Build:  cc -O2 -Wall -Wextra -std=c11 -o envctl envctl.c
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#define strdup _strdup
#ifndef S_ISREG
#define S_ISREG(m) (((m)&_S_IFMT) == _S_IFREG)
#endif
#else
#include <unistd.h>
#endif

#if defined(_MSC_VER)
#define NORETURN __declspec(noreturn)
#else
#define NORETURN _Noreturn
#endif

/* -------------------------------------------------------------------------- */
/* utilities                                                                  */
/* -------------------------------------------------------------------------- */

static const char *PROG = "envctl";

static int stdout_isatty(void) {
#ifdef _WIN32
	return _isatty(_fileno(stdout));
#else
	return isatty(STDOUT_FILENO);
#endif
}

NORETURN static void die(const char *fmt, ...) {
	va_list ap;

	fprintf(stderr, "%s: ", PROG);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(2);
}

static void *xmalloc(size_t n) {
	void *p = malloc(n);
	if (!p)
		die("out of memory");
	return p;
}

static void *xrealloc(void *q, size_t n) {
	void *p = realloc(q, n);
	if (!p)
		die("out of memory");
	return p;
}

static char *xstrdup(const char *s) {
	char *p = strdup(s);
	if (!p)
		die("out of memory");
	return p;
}

/* -------------------------------------------------------------------------- */
/* agent detection (mirrors unjs/std-env src/agents.ts)                       */
/* -------------------------------------------------------------------------- */

static int env_set(const char *k) {
	const char *v = getenv(k);
	return v && *v;
}

static int detect_agent(void) {
	const char *v;
	static const char *const keys[] = {
	    "AI_AGENT",   /* explicit override */
	    "CLAUDECODE", /* claude */
	    "CLAUDE_CODE",
	    "REPL_ID",       /* replit */
	    "GEMINI_CLI",    /* gemini */
	    "CODEX_SANDBOX", /* codex */
	    "CODEX_THREAD_ID",
	    "OPENCODE",       /* opencode */
	    "AUGMENT_AGENT",  /* auggie */
	    "GOOSE_PROVIDER", /* goose */
	    "JUNIE_DATA",     /* junie */
	    "JUNIE_SHIM_PATH",
	    "CURSOR_AGENT", /* cursor */
	    NULL,
	};

	for (int i = 0; keys[i]; i++) {
		if (env_set(keys[i]))
			return 1;
	}

	if ((v = getenv("PATH")) && (strstr(v, ".pi/agent") || strstr(v, ".pi\\agent")))
		return 1; /* pi */
	if ((v = getenv("EDITOR")) && strstr(v, "devin"))
		return 1; /* devin */
	if ((v = getenv("TERM_PROGRAM")) && strstr(v, "kiro") && !stdout_isatty())
		return 1; /* kiro: only when non-interactive */

	return 0;
}

/* -------------------------------------------------------------------------- */
/* help                                                                       */
/* -------------------------------------------------------------------------- */

static const char *SHORT_USAGE = "usage: envctl [<cmd>] [file] <KEY> [VALUE]\n"
                                 "  commands: set get disable enable delete|rm list|ls\n"
                                 "  file:     optional when ./.env exists\n"
                                 "  bare:     envctl [file] <KEY>          == get\n"
                                 "            envctl [file] <KEY> <VALUE>  == set\n"
                                 "  flags:    --values --all (list)  --dry-run  --redact --raw\n";

/* Prepended to the long help only when running inside a detected AI agent. */
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
    "Redaction: secret-looking key names (KEY, TOKEN, SECRET, PASSWORD, PASSWD,\n"
    "CREDENTIAL, API; segment PASS/PWD e.g. DB_PASS) are masked as **** + last 4\n"
    "chars when redact is on.\n"
    "Default on when a coding agent is detected and stdout is a TTY; off when\n"
    "stdout is piped/redirected (scripts, command substitution) unless --redact.\n"
    "\n"
    "Guarantees: only the target key's line changes; re-running with the same args\n"
    "is a no-op; writes are atomic (temp + rename) and preserve file mode; VALUE is\n"
    "literal (no shell/regex reinterpretation).\n";

/* longform: 0 = SHORT_USAGE (-h); 1 = LONG_USAGE (--help or no args).
 * The AI preamble is prepended to the long help only inside an AI agent. */
NORETURN static void print_help(int longform) {
	if (!longform) {
		fputs(SHORT_USAGE, stdout);
	} else {
		if (detect_agent())
			fputs(AI_PREAMBLE, stdout);
		fputs(LONG_USAGE, stdout);
	}
	exit(0);
}

/* -------------------------------------------------------------------------- */
/* line store                                                                 */
/* -------------------------------------------------------------------------- */

typedef struct {
	char **v;
	size_t n;
	size_t cap;
} Lines;

static void lpush(Lines *L, char *s) {
	if (L->n == L->cap) {
		L->cap = L->cap ? L->cap * 2 : 64;
		L->v = xrealloc(L->v, L->cap * sizeof(char *));
	}
	L->v[L->n++] = s;
}

static void push_char(char **buf, size_t *cap, size_t *len, char c) {
	if (*len + 1 > *cap) {
		*cap = *cap ? *cap * 2 : 128;
		*buf = xrealloc(*buf, *cap);
	}
	(*buf)[(*len)++] = c;
}

/*
 * Portable line reader (no getline): splits on '\n', strips a trailing '\r'
 * so CRLF files read cleanly on any platform. Binary mode + explicit LF on
 * write keeps line endings consistent everywhere.
 */
static Lines read_file(const char *file) {
	FILE *f = fopen(file, "rb");
	if (!f)
		die("cannot open file: %s", file);

	Lines L = {0};
	char *buf = NULL;
	size_t cap = 0, len = 0;
	int c;

	while ((c = fgetc(f)) != EOF) {
		if (c == '\n') {
			if (len && buf[len - 1] == '\r')
				len--;
			push_char(&buf, &cap, &len, '\0');
			lpush(&L, xstrdup(buf));
			len = 0;
		} else {
			push_char(&buf, &cap, &len, (char)c);
		}
	}

	/* Final line with no trailing newline. */
	if (len > 0) {
		if (buf[len - 1] == '\r')
			len--;
		push_char(&buf, &cap, &len, '\0');
		lpush(&L, xstrdup(buf));
	}

	free(buf);
	fclose(f);
	return L;
}

/* -------------------------------------------------------------------------- */
/* definition matching (mirrors the awk in envctl.sh)                         */
/* -------------------------------------------------------------------------- */

static const char *skip_ws(const char *s) {
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

static const char *skip_export(const char *s) {
	if (!strncmp(s, "export", 6) && (s[6] == ' ' || s[6] == '\t'))
		s = skip_ws(s + 6);
	return s;
}

static int key_at(const char *s, const char *key, size_t kl) {
	return strncmp(s, key, kl) == 0 && s[kl] == '=';
}

static int is_active_def(const char *line, const char *key, size_t kl) {
	/* A comment line is never an active definition. */
	if (*skip_ws(line) == '#')
		return 0;
	return key_at(skip_export(line), key, kl);
}

static int is_comment_def(const char *line, const char *key, size_t kl) {
	const char *p = skip_ws(line);
	if (*p != '#')
		return 0;
	p = skip_ws(p + 1);
	return key_at(skip_export(p), key, kl);
}

/* First matching active / commented definition indices, or -1 if none. */
static void find_defs(const Lines *L, const char *key, size_t kl, long *active, long *commented) {
	*active = -1;
	*commented = -1;
	for (size_t i = 0; i < L->n; i++) {
		if (*active < 0 && is_active_def(L->v[i], key, kl))
			*active = (long)i;
		if (*commented < 0 && is_comment_def(L->v[i], key, kl))
			*commented = (long)i;
		if (*active >= 0 && *commented >= 0)
			break;
	}
}

static char *mk_kv(const char *key, const char *val) {
	size_t n = strlen(key) + 1 + strlen(val) + 1;
	char *s = xmalloc(n);
	snprintf(s, n, "%s=%s", key, val);
	return s;
}

static char *mk_comment(const char *line) {
	size_t n = strlen(line) + 3;
	char *s = xmalloc(n);
	snprintf(s, n, "# %s", line);
	return s;
}

static char *uncomment(const char *line) {
	const char *p = skip_ws(line); /* at '#' */
	return xstrdup(skip_ws(p + 1));
}

/* -------------------------------------------------------------------------- */
/* transforms                                                                 */
/*                                                                            */
/* Each act_* builds a new Lines view. Unchanged entries share pointers with  */
/* the input; replaced/new entries are freshly allocated. The process exits   */
/* soon after write, so shared ownership is intentional and leak-free enough. */
/* -------------------------------------------------------------------------- */

static Lines act_set(Lines *L, const char *key, size_t kl, const char *val) {
	long first_active, first_comment;
	find_defs(L, key, kl, &first_active, &first_comment);

	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];

		if (first_active >= 0) {
			if ((long)i == first_active)
				line = mk_kv(key, val);
			else if (is_active_def(L->v[i], key, kl))
				line = mk_comment(L->v[i]); /* dedupe extra active defs */
		} else if (first_comment >= 0 && (long)i == first_comment) {
			line = mk_kv(key, val); /* revive first commented def */
		}

		lpush(&out, line);
	}

	if (first_active < 0 && first_comment < 0)
		lpush(&out, mk_kv(key, val)); /* append */

	return out;
}

static Lines act_disable(Lines *L, const char *key, size_t kl) {
	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];
		if (is_active_def(line, key, kl))
			line = mk_comment(line);
		lpush(&out, line);
	}
	return out;
}

static Lines act_enable(Lines *L, const char *key, size_t kl) {
	long first_active, first_comment;
	find_defs(L, key, kl, &first_active, &first_comment);

	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];
		if (first_active < 0 && first_comment >= 0 && (long)i == first_comment)
			line = uncomment(line);
		lpush(&out, line);
	}
	return out;
}

static Lines act_delete(Lines *L, const char *key, size_t kl) {
	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		if (!is_active_def(L->v[i], key, kl) && !is_comment_def(L->v[i], key, kl))
			lpush(&out, L->v[i]);
	}
	return out;
}

/* -------------------------------------------------------------------------- */
/* secrets / redaction                                                        */
/* -------------------------------------------------------------------------- */

/* True if `seg` appears as a full _-separated segment: (^|_)seg(_|$). */
static int has_segment(const char *k, const char *seg) {
	size_t n = strlen(seg);

	for (const char *p = k; *p; p++) {
		if (strncmp(p, seg, n) != 0)
			continue;
		int left = (p == k) || (p[-1] == '_');
		int right = (p[n] == '\0') || (p[n] == '_');
		if (left && right)
			return 1;
	}
	return 0;
}

static int secretish(const char *k) {
	/* Long / unambiguous tokens: substring match. */
	if (strstr(k, "KEY") || strstr(k, "TOKEN") || strstr(k, "SECRET") || strstr(k, "PASSWORD") ||
	    strstr(k, "PASSWD") || strstr(k, "CREDENTIAL") || strstr(k, "API"))
		return 1;
	/* Short abbreviations: whole segment only (not PASSPORT / COMPASS). */
	return has_segment(k, "PASS") || has_segment(k, "PWD");
}

static int valid_keychars(const char *k, size_t kl) {
	if (kl < 1)
		return 0;
	if (!(isalpha((unsigned char)k[0]) || k[0] == '_'))
		return 0;
	for (size_t i = 1; i < kl; i++) {
		if (!(isalnum((unsigned char)k[i]) || k[i] == '_'))
			return 0;
	}
	return 1;
}

/* --raw wins; --redact forces on; else agent + TTY (not pipes/scripts). */
static int want_redact(int flag_redact, int flag_raw) {
	if (flag_raw)
		return 0;
	if (flag_redact)
		return 1;
	return detect_agent() && stdout_isatty();
}

/* Print a value, masking as **** + last 4 when redact && secretish. */
static void print_value(const char *key, const char *val, int redact) {
	if (redact && secretish(key)) {
		size_t vlen = strlen(val);
		if (vlen > 4)
			printf("****%s\n", val + vlen - 4);
		else
			printf("****\n");
	} else {
		printf("%s\n", val);
	}
}

static int act_get(Lines *L, const char *key, size_t kl, int redact) {
	for (size_t i = 0; i < L->n; i++) {
		if (is_active_def(L->v[i], key, kl)) {
			const char *s = skip_export(L->v[i]);
			print_value(key, s + kl + 1, redact);
			return 0;
		}
	}
	return 1; /* not set */
}

/* -------------------------------------------------------------------------- */
/* list                                                                       */
/* -------------------------------------------------------------------------- */

static void act_list(Lines *L, int values, int all, int redact) {
	for (size_t i = 0; i < L->n; i++) {
		const char *orig = L->v[i];
		const char *s;
		int commented = 0;
		const char *p = skip_ws(orig);

		if (*p == '#') {
			if (!all)
				continue;
			commented = 1;
			s = skip_ws(p + 1);
		} else {
			s = orig;
		}

		s = skip_export(s);
		const char *eq = strchr(s, '=');
		if (!eq)
			continue;

		size_t kl = (size_t)(eq - s);
		if (!valid_keychars(s, kl))
			continue;

		const char *tag = commented ? " (disabled)" : "";
		if (!values) {
			printf("%.*s%s\n", (int)kl, s, tag);
			continue;
		}

		const char *val = eq + 1;
		char kbuf[256];
		size_t kn = kl < sizeof(kbuf) - 1 ? kl : sizeof(kbuf) - 1;
		memcpy(kbuf, s, kn);
		kbuf[kn] = '\0';

		if (redact && secretish(kbuf)) {
			size_t vlen = strlen(val);
			if (vlen > 4)
				printf("%.*s=****%s%s\n", (int)kl, s, val + vlen - 4, tag);
			else
				printf("%.*s=****%s\n", (int)kl, s, tag);
		} else {
			printf("%.*s=%s%s\n", (int)kl, s, val, tag);
		}
	}
}

/* -------------------------------------------------------------------------- */
/* atomic write                                                               */
/* -------------------------------------------------------------------------- */

/* Emit one line; when redact, mask secret-looking KEY=value (active or commented). */
static void emit_line(FILE *out, const char *line, int redact) {
	if (!redact) {
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	const char *p = skip_ws(line);
	if (*p == '#')
		p = skip_ws(p + 1);
	p = skip_export(p);

	const char *eq = strchr(p, '=');
	if (!eq) {
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	size_t kl = (size_t)(eq - p);
	if (!valid_keychars(p, kl)) {
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	char kbuf[256];
	size_t kn = kl < sizeof(kbuf) - 1 ? kl : sizeof(kbuf) - 1;
	memcpy(kbuf, p, kn);
	kbuf[kn] = '\0';
	if (!secretish(kbuf)) {
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	/* Keep everything through '=' (comment / export / spacing), mask the value. */
	fwrite(line, 1, (size_t)(eq - line) + 1, out);
	const char *val = eq + 1;
	size_t vlen = strlen(val);
	if (vlen > 4)
		fprintf(out, "****%s\n", val + vlen - 4);
	else
		fputs("****\n", out);
}

static void emit(FILE *out, Lines *L, int redact) {
	for (size_t i = 0; i < L->n; i++)
		emit_line(out, L->v[i], redact);
}

/*
 * Directory portion of a path (malloc'd; "." if none). Handles '/' and, on
 * Windows, '\\'. Replaces POSIX dirname() so there is no libgen.h dependency.
 */
static char *dir_of(const char *path) {
	const char *slash = NULL;

	for (const char *p = path; *p; p++) {
		if (*p == '/'
#ifdef _WIN32
		    || *p == '\\'
#endif
		)
			slash = p;
	}

	if (!slash)
		return xstrdup(".");

	size_t n = (size_t)(slash - path);
	if (n == 0)
		n = 1; /* "/foo" -> keep the root "/" */

	char *d = xmalloc(n + 1);
	memcpy(d, path, n);
	d[n] = '\0';
	return d;
}

/*
 * Write `out` to `file` atomically: build a temp file in the same directory,
 * then replace the target in one step. POSIX preserves the file mode; Windows
 * needs MoveFileEx because rename() there won't overwrite an existing file.
 */
static void commit_file(const char *file, Lines *out) {
	char *dir = dir_of(file);

#ifdef _WIN32
	char tmp[MAX_PATH];
	if (!GetTempFileNameA(dir, "env", 0, tmp))
		die("GetTempFileName failed");

	FILE *tf = fopen(tmp, "wb");
	if (!tf) {
		DeleteFileA(tmp);
		die("temp open failed");
	}

	emit(tf, out, 0); /* never redact on disk */
	if (fflush(tf) != 0 || fclose(tf) != 0) {
		DeleteFileA(tmp);
		die("write failed");
	}
	if (!MoveFileExA(tmp, file, MOVEFILE_REPLACE_EXISTING)) {
		DeleteFileA(tmp);
		die("replace failed");
	}
#else
	size_t tl = strlen(dir) + sizeof("/.envctl.XXXXXX");
	char *tmpl = xmalloc(tl);
	snprintf(tmpl, tl, "%s/.envctl.XXXXXX", dir);

	int fd = mkstemp(tmpl);
	if (fd < 0)
		die("mkstemp failed");

	FILE *tf = fdopen(fd, "wb");
	if (!tf) {
		unlink(tmpl);
		die("fdopen failed");
	}

	emit(tf, out, 0); /* never redact on disk */
	if (fflush(tf) != 0) {
		fclose(tf);
		unlink(tmpl);
		die("write failed");
	}

	struct stat st;
	if (stat(file, &st) == 0)
		(void)fchmod(fd, st.st_mode & 07777); /* preserve mode; best effort */

	if (fclose(tf) != 0) {
		unlink(tmpl);
		die("close failed");
	}
	if (rename(tmpl, file) != 0) {
		unlink(tmpl);
		die("rename failed");
	}
	free(tmpl);
#endif

	free(dir);
}

/* -------------------------------------------------------------------------- */
/* CLI                                                                        */
/* -------------------------------------------------------------------------- */

static int is_command(const char *a) {
	static const char *const cmds[] = {
	    "set", "get", "disable", "enable", "delete", "list", "ls", "rm", NULL,
	};
	for (int i = 0; cmds[i]; i++) {
		if (!strcmp(a, cmds[i]))
			return 1;
	}
	return 0;
}

static int is_reg_file(const char *path) {
	struct stat st;
	return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/*
 * Resolve [file] KEY [VALUE] from positionals after the command word.
 *
 * If the first positional is an existing regular file, it is the target file.
 * Otherwise, when ./.env exists, use it and treat positionals as KEY [VALUE].
 * A non-key-shaped first token that is not a file is rejected as a missing path
 * (so `envctl get missing.env KEY` does not silently become a .env get).
 */
static void resolve_file_args(const char **rest, int nr, const char **file, const char **key,
                              const char **val) {
	*file = NULL;
	*key = NULL;
	*val = NULL;

	if (nr >= 1 && is_reg_file(rest[0])) {
		*file = rest[0];
		if (nr >= 2)
			*key = rest[1];
		if (nr >= 3)
			*val = rest[2];
		if (nr > 3)
			die("too many arguments");
		return;
	}

	/* Path-shaped first arg that isn't a file — don't swallow it as a KEY. */
	if (nr >= 1 && !valid_keychars(rest[0], strlen(rest[0])))
		die("no such file: %s", rest[0]);

	if (is_reg_file(".env")) {
		*file = ".env";
		if (nr >= 1)
			*key = rest[0];
		if (nr >= 2)
			*val = rest[1];
		if (nr > 2)
			die("too many arguments");
		return;
	}

	if (nr >= 1)
		die("no file given and no .env in cwd");
	die("no file given and no .env in cwd");
}

int main(int argc, char **argv) {
	int dry = 0, values = 0, all = 0, flag_redact = 0, flag_raw = 0, np = 0;
	const char *pos[16];

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];

		/* Options are global and position-free. */
		if (!strcmp(a, "--dry-run"))
			dry = 1;
		else if (!strcmp(a, "--values"))
			values = 1;
		else if (!strcmp(a, "--all"))
			all = 1;
		else if (!strcmp(a, "--redact"))
			flag_redact = 1;
		else if (!strcmp(a, "--raw"))
			flag_raw = 1;
		else if (!strcmp(a, "-h"))
			print_help(0); /* short */
		else if (!strcmp(a, "--help"))
			print_help(1); /* long */
		else if (np < (int)(sizeof(pos) / sizeof(*pos)))
			pos[np++] = a;
		else
			die("too many arguments");
	}

	if (np == 0)
		print_help(1); /* long */

	/*
	 * The command word may appear anywhere (before OR after the file): the first
	 * one wins. Remaining positionals are [file] KEY [VALUE] (file optional when
	 * ./.env exists). No command word: KEY only = get, KEY VALUE = set (with .env
	 * or explicit file).
	 */
	const char *cmd = NULL;
	const char *file = NULL;
	const char *key = NULL;
	const char *val = NULL;
	const char *rest[16];
	int nr = 0;

	for (int i = 0; i < np; i++) {
		if (!cmd && is_command(pos[i]))
			cmd = pos[i];
		else
			rest[nr++] = pos[i];
	}

	if (!cmd) {
		/*
		 * Bare form needs enough args to resolve a key. With an explicit file:
		 * file KEY [VALUE]. With .env only: KEY [VALUE].
		 */
		if (nr < 1)
			die("usage: envctl [<cmd>] [file] <KEY> [VALUE]");
		resolve_file_args(rest, nr, &file, &key, &val);
		if (!key)
			die("usage: envctl [file] <KEY> [VALUE]  or  envctl <cmd> [file] ...");
		if (val)
			cmd = "set";
		else
			cmd = "get";
	} else {
		if (!strcmp(cmd, "ls"))
			cmd = "list";
		if (!strcmp(cmd, "rm"))
			cmd = "delete";

		if (!strcmp(cmd, "list")) {
			if (nr == 0) {
				if (!is_reg_file(".env"))
					die("list needs a file (no .env in cwd)");
				file = ".env";
			} else if (nr == 1 && is_reg_file(rest[0])) {
				file = rest[0];
			} else if (nr == 1) {
				die("no such file: %s", rest[0]);
			} else {
				die("too many arguments");
			}
		} else {
			resolve_file_args(rest, nr, &file, &key, &val);
		}
	}

	if (!is_reg_file(file))
		die("no such file: %s", file);

	int redact = want_redact(flag_redact, flag_raw);

	if (!strcmp(cmd, "list")) {
		Lines L = read_file(file);
		act_list(&L, values, all, redact);
		return 0;
	}

	if (!key)
		die("%s needs KEY", cmd);
	if (!valid_keychars(key, strlen(key)))
		die("invalid key: '%s'", key);

	/* get / disable / enable / delete take no VALUE positional. */
	if (strcmp(cmd, "set") != 0 && val)
		die("too many arguments");

	Lines L = read_file(file);
	size_t kl = strlen(key);

	if (!strcmp(cmd, "get"))
		return act_get(&L, key, kl, redact);

	Lines out;
	if (!strcmp(cmd, "set"))
		out = act_set(&L, key, kl, val ? val : "");
	else if (!strcmp(cmd, "disable"))
		out = act_disable(&L, key, kl);
	else if (!strcmp(cmd, "enable"))
		out = act_enable(&L, key, kl);
	else /* delete */
		out = act_delete(&L, key, kl);

	if (dry)
		emit(stdout, &out, redact);
	else
		commit_file(file, &out);

	return 0;
}
