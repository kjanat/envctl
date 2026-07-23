/*
 * envctl - env-file key manager (C port of envctl.sh).
 *
 * Edits a single KEY in place without disturbing order, comments, spacing, or any other line.
 * Writes atomically (temp file + rename) and preserves the target's mode, so a crash
 * mid-write can never leave a half-written env file.
 *
 *   envctl set     <file> <KEY> [VALUE]   set/replace KEY (uncomments if needed)
 *   envctl get     <file> <KEY>           print active value, exit 1 if unset
 *   envctl disable <file> <KEY>           comment KEY out, keep its value
 *   envctl enable  <file> <KEY>           uncomment KEY
 *   envctl delete  <file> <KEY>           remove KEY entirely (active + commented)
 *   envctl list    <file> [--values] [--all]
 *
 * Aliases: ls = list, rm = delete.
 * Bare form (first arg is the file): `<file> <KEY>` == get, `<file> <KEY> <VALUE>` == set.
 * A command name wins over a same-named file.
 * Flag --dry-run prints the resulting file to stdout, writes nothing.
 *
 * Help: `-h` prints the short usage; `--help` (or no args) prints the long help.
 * Inside a detected AI coding agent (per unjs/std-env), the long help is prefixed
 * with an agent-oriented preamble.
 *
 * Build:  cc -O2 -Wall -Wextra -std=c11 -o envctl envctl.c
 */
#define _GNU_SOURCE
#include <ctype.h>
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

/* stdout tty check, portable across POSIX and Windows */
static int stdout_isatty(void) {
#ifdef _WIN32
	return _isatty(_fileno(stdout));
#else
	return isatty(STDOUT_FILENO);
#endif
}

static const char *PROG = "envctl";

NORETURN static void die(const char *fmt, const char *arg) {
	fprintf(stderr, "%s: ", PROG);
	fprintf(stderr, fmt, arg);
	fputc('\n', stderr);
	exit(2);
}
static void *xmalloc(size_t n) {
	void *p = malloc(n);
	if (!p)
		die("%s", "out of memory");
	return p;
}
static void *xrealloc(void *q, size_t n) {
	void *p = realloc(q, n);
	if (!p)
		die("%s", "out of memory");
	return p;
}
static char *xstrdup(const char *s) {
	char *p = strdup(s);
	if (!p)
		die("%s", "out of memory");
	return p;
}

/* agent detection: mirrors unjs/std-env src/agents.ts */
static int env_set(const char *k) {
	const char *v = getenv(k);
	return v && *v;
}
static int detect_agent(void) {
	const char *v;
	if (env_set("AI_AGENT"))
		return 1; /* explicit override */
	static const char *keys[] = {"CLAUDECODE",
	                             "CLAUDE_CODE", /* claude   */
	                             "REPL_ID",     /* replit   */
	                             "GEMINI_CLI",  /* gemini   */
	                             "CODEX_SANDBOX",
	                             "CODEX_THREAD_ID", /* codex    */
	                             "OPENCODE",        /* opencode */
	                             "AUGMENT_AGENT",   /* auggie   */
	                             "GOOSE_PROVIDER",  /* goose    */
	                             "JUNIE_DATA",
	                             "JUNIE_SHIM_PATH", /* junie    */
	                             "CURSOR_AGENT",    /* cursor   */
	                             NULL};
	for (int i = 0; keys[i]; i++)
		if (env_set(keys[i]))
			return 1;
	if ((v = getenv("PATH")) && (strstr(v, ".pi/agent") || strstr(v, ".pi\\agent")))
		return 1; /* pi */
	if ((v = getenv("EDITOR")) && strstr(v, "devin"))
		return 1; /* devin */
	if ((v = getenv("TERM_PROGRAM")) && strstr(v, "kiro") && !stdout_isatty())
		return 1; /* kiro, only when non-interactive (noTTY) */
	return 0;
}

/* help */
static const char *SHORT_USAGE =
    "usage: envctl [<cmd>] <file> <KEY> [VALUE]\n"
    "  commands: set get disable enable delete|rm list|ls\n"
    "  bare:     envctl <file> <KEY>          == get\n"
    "            envctl <file> <KEY> <VALUE>  == set\n"
    "  flags:    --values --all (list)   --dry-run (set/disable/enable/delete)\n";

/* Prepended to the long help only when running inside a detected AI agent. */
static const char *AI_PREAMBLE =
    "You are an AI coding agent. Use envctl to change a key in any env / .env-style file.\n"
    "NEVER hand-edit an env file to add, change, comment, or remove a key -\n"
    "envctl does it in place, atomically, preserving order, comments, and mode.\n\n";

static const char *LONG_USAGE =
    "envctl - env-file key manager.\n"
    "\n"
    "Commands:\n"
    "  envctl set     <file> <KEY> [VALUE]   set/replace KEY (uncomments if commented)\n"
    "  envctl get     <file> <KEY>           print active value; exit 1 if unset\n"
    "  envctl disable <file> <KEY>           comment KEY out, keep its value\n"
    "  envctl enable  <file> <KEY>           uncomment KEY\n"
    "  envctl delete  <file> <KEY>           remove KEY entirely (active + commented) [rm]\n"
    "  envctl list    <file> [--values] [--all]  active keys; --values masks secrets;\n"
    "                                        --all also lists disabled keys           [ls]\n"
    "\n"
    "Bare form (first argument is the file, no command word):\n"
    "  envctl <file> <KEY>            == get\n"
    "  envctl <file> <KEY> <VALUE>    == set\n"
    "\n"
    "Flags: --dry-run on a mutating command prints the result, writes nothing.\n"
    "\n"
    "Guarantees: only the target key's line changes; re-running with the same args\n"
    "is a no-op; writes are atomic (temp + rename) and preserve file mode; VALUE is\n"
    "literal (no shell/regex reinterpretation); secret-looking keys are masked by\n"
    "`list --values`.\n";

/* longform: 0 = SHORT_USAGE (-h); 1 = LONG_USAGE (--help or no args). The AI
 * preamble is prepended to the long help only when run inside an AI agent. */
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

/* line store */
typedef struct {
	char **v;
	size_t n, cap;
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
/* Portable line reader (no getline): splits on '\n', strips a trailing '\r' (so CRLF files read
 * cleanly on any platform). Binary mode + explicit LF on write keeps line endings consistent
 * everywhere. */
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
	if (len > 0) { /* final line with no trailing newline */
		if (buf[len - 1] == '\r')
			len--;
		push_char(&buf, &cap, &len, '\0');
		lpush(&L, xstrdup(buf));
	}
	free(buf);
	fclose(f);
	return L;
}

/* definition matching (mirrors the awk in envctl.sh) */
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
	if (*skip_ws(line) == '#')
		return 0; /* a comment line is never an active def */
	return key_at(skip_export(line), key, kl);
}
static int is_comment_def(const char *line, const char *key, size_t kl) {
	const char *p = skip_ws(line);
	if (*p != '#')
		return 0;
	p = skip_ws(p + 1);
	return key_at(skip_export(p), key, kl);
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

/* transforms */
static Lines act_set(Lines *L, const char *key, size_t kl, const char *val) {
	long fa = -1, fc = -1;
	for (size_t i = 0; i < L->n; i++) {
		if (fa < 0 && is_active_def(L->v[i], key, kl))
			fa = (long)i;
		if (fc < 0 && is_comment_def(L->v[i], key, kl))
			fc = (long)i;
	}
	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];
		if (fa >= 0) {
			if ((long)i == fa)
				line = mk_kv(key, val);
			else if (is_active_def(L->v[i], key, kl))
				line = mk_comment(L->v[i]); /* dedupe extra active defs */
		} else if (fc >= 0 && (long)i == fc) {
			line = mk_kv(key, val); /* revive first commented def */
		}
		lpush(&out, line);
	}
	if (fa < 0 && fc < 0)
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
	long fa = -1, fc = -1;
	for (size_t i = 0; i < L->n; i++) {
		if (fa < 0 && is_active_def(L->v[i], key, kl))
			fa = (long)i;
		if (fc < 0 && is_comment_def(L->v[i], key, kl))
			fc = (long)i;
	}
	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];
		if (fa < 0 && fc >= 0 && (long)i == fc)
			line = uncomment(line);
		lpush(&out, line);
	}
	return out;
}
static Lines act_delete(Lines *L, const char *key, size_t kl) {
	Lines out = {0};
	for (size_t i = 0; i < L->n; i++)
		if (!is_active_def(L->v[i], key, kl) && !is_comment_def(L->v[i], key, kl))
			lpush(&out, L->v[i]);
	return out;
}
static int act_get(Lines *L, const char *key, size_t kl) {
	for (size_t i = 0; i < L->n; i++)
		if (is_active_def(L->v[i], key, kl)) {
			const char *s = skip_export(L->v[i]);
			printf("%s\n", s + kl + 1);
			return 0;
		}
	return 1; /* not set */
}

/* list */
static int secretish(const char *k) {
	return strstr(k, "KEY") || strstr(k, "TOKEN") || strstr(k, "SECRET") || strstr(k, "PASSWORD") ||
	       strstr(k, "PASSWD") || strstr(k, "CREDENTIAL") || strstr(k, "API");
}
static int valid_keychars(const char *k, size_t kl) {
	if (kl < 1)
		return 0;
	if (!(isalpha((unsigned char)k[0]) || k[0] == '_'))
		return 0;
	for (size_t i = 1; i < kl; i++)
		if (!(isalnum((unsigned char)k[i]) || k[i] == '_'))
			return 0;
	return 1;
}
static void act_list(Lines *L, int values, int all) {
	for (size_t i = 0; i < L->n; i++) {
		const char *orig = L->v[i], *s;
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
		size_t vlen = strlen(val);
		if (secretish(kbuf) && vlen > 4)
			printf("%.*s=****%s%s\n", (int)kl, s, val + vlen - 4, tag);
		else
			printf("%.*s=%s%s\n", (int)kl, s, val, tag);
	}
}

/* atomic write */
static void emit(FILE *out, Lines *L) {
	for (size_t i = 0; i < L->n; i++) {
		fputs(L->v[i], out);
		fputc('\n', out);
	}
}
/* Directory portion of a path (malloc'd; "." if none). Handles '/' and, on
 * Windows, '\\'. Replaces POSIX dirname() so there is no libgen.h dependency. */
static char *dir_of(const char *path) {
	const char *slash = NULL;
	for (const char *p = path; *p; p++)
		if (*p == '/'
#ifdef _WIN32
		    || *p == '\\'
#endif
		)
			slash = p;
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

/* Write `out` to `file` atomically: build a temp file in the same directory, then replace the
 * target in one step. POSIX preserves the file mode; Windows needs MoveFileEx because rename()
 * there won't overwrite an existing file. */
static void commit_file(const char *file, Lines *out) {
	char *dir = dir_of(file);
#ifdef _WIN32
	char tmp[MAX_PATH];
	if (!GetTempFileNameA(dir, "env", 0, tmp))
		die("%s", "GetTempFileName failed");
	FILE *tf = fopen(tmp, "wb");
	if (!tf) {
		DeleteFileA(tmp);
		die("%s", "temp open failed");
	}
	emit(tf, out);
	if (fflush(tf) != 0 || fclose(tf) != 0) {
		DeleteFileA(tmp);
		die("%s", "write failed");
	}
	if (!MoveFileExA(tmp, file, MOVEFILE_REPLACE_EXISTING)) {
		DeleteFileA(tmp);
		die("%s", "replace failed");
	}
#else
	size_t tl = strlen(dir) + sizeof("/.envctl.XXXXXX");
	char *tmpl = xmalloc(tl);
	snprintf(tmpl, tl, "%s/.envctl.XXXXXX", dir);
	int fd = mkstemp(tmpl);
	if (fd < 0)
		die("%s", "mkstemp failed");
	FILE *tf = fdopen(fd, "wb");
	if (!tf) {
		unlink(tmpl);
		die("%s", "fdopen failed");
	}
	emit(tf, out);
	if (fflush(tf) != 0) {
		fclose(tf);
		unlink(tmpl);
		die("%s", "write failed");
	}
	struct stat st;
	if (stat(file, &st) == 0)
		(void)fchmod(fd, st.st_mode & 07777); /* preserve mode; best effort */
	if (fclose(tf) != 0) {
		unlink(tmpl);
		die("%s", "close failed");
	}
	if (rename(tmpl, file) != 0) {
		unlink(tmpl);
		die("%s", "rename failed");
	}
	free(tmpl);
#endif
	free(dir);
}

/* main */
static int is_command(const char *a) {
	static const char *cmds[] = {"set",  "get", "disable", "enable", "delete",
	                             "list", "ls",  "rm",      NULL};
	for (int i = 0; cmds[i]; i++)
		if (!strcmp(a, cmds[i]))
			return 1;
	return 0;
}

int main(int argc, char **argv) {
	int dry = 0, values = 0, all = 0, np = 0;
	const char *pos[16];
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		/* Options are global and position-free. --values/--all apply to list. */
		if (!strcmp(a, "--dry-run"))
			dry = 1;
		else if (!strcmp(a, "--values"))
			values = 1;
		else if (!strcmp(a, "--all"))
			all = 1;
		else if (!strcmp(a, "-h"))
			print_help(0); /* short */
		else if (!strcmp(a, "--help"))
			print_help(1); /* long */
		else if (np < (int)(sizeof(pos) / sizeof(*pos)))
			pos[np++] = a;
		else
			die("%s", "too many arguments");
	}
	if (np == 0)
		print_help(1); /* long */

	/* The command word may appear anywhere (before OR after the file): the first one wins.
	 * The remaining positionals keep their order as file, key, value.
	 * No command word: 2 args = get, 3 = set. So `envctl <file> get <KEY>` does a get,
	 * instead of "get=<KEY>". */
	const char *cmd = NULL, *file, *key = NULL, *val = NULL, *rest[16];
	int nr = 0;
	for (int i = 0; i < np; i++) {
		if (!cmd && is_command(pos[i]))
			cmd = pos[i];
		else
			rest[nr++] = pos[i];
	}
	if (nr < 1) {
		if (cmd)
			die("%s needs a file", cmd);
		die("%s", "usage: envctl [<cmd>] <file> <KEY> [VALUE]");
	}
	if (nr > 3)
		die("%s", "too many arguments");
	file = rest[0];
	if (nr >= 2)
		key = rest[1];
	if (nr >= 3)
		val = rest[2];
	if (!cmd) {
		if (nr == 2)
			cmd = "get";
		else if (nr == 3)
			cmd = "set";
		else
			die("%s", "usage: envctl <file> <KEY> [VALUE]  or  envctl <cmd> <file> ...");
	}
	if (!strcmp(cmd, "ls"))
		cmd = "list";
	if (!strcmp(cmd, "rm"))
		cmd = "delete";

	struct stat st;
	if (stat(file, &st) != 0 || !S_ISREG(st.st_mode))
		die("no such file: %s", file);

	if (!strcmp(cmd, "list")) {
		Lines L = read_file(file);
		act_list(&L, values, all);
		return 0;
	}

	if (!key)
		die("%s needs KEY", cmd);
	if (!valid_keychars(key, strlen(key)))
		die("invalid key: '%s'", key);

	Lines L = read_file(file);
	size_t kl = strlen(key);

	if (!strcmp(cmd, "get"))
		return act_get(&L, key, kl);

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
		emit(stdout, &out);
	else
		commit_file(file, &out);
	return 0;
}
