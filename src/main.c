/*
 * envctl — manage keys in env files.
 *
 * Build: make  (see Makefile; sources under src/)
 */
#define _GNU_SOURCE
#include "cli.h"
#include "complete.h"
#include "diff.h"
#include "envsrc.h"
#include "fileio.h"
#include "filter.h"
#include "help.h"
#include "lines.h"
#include "module.h"
#include "redact.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#endif

typedef enum { HELP_NONE, HELP_SHORT, HELP_LONG } HelpMode;

static const Command *command_by_id(CmdId id) {
	for (int i = 0; i < CMD_COUNT; i++) {
		if (cli_commands[i].id == id)
			return &cli_commands[i];
	}
	die("no such command id: %d", (int)id);
}

static char *join_names(const char *const *names, int n, const char *conj) {
	char *buf = NULL;
	size_t cap = 0, len = 0;

	buf_put(&buf, &cap, &len, "", 0);
	for (int i = 0; i < n; i++) {
		if (i > 0) {
			const char *sep = i == n - 1 && n == 2 ? " " : ", ";
			buf_put(&buf, &cap, &len, sep, strlen(sep));
			if (i == n - 1) {
				buf_put(&buf, &cap, &len, conj, strlen(conj));
				buf_put(&buf, &cap, &len, " ", 1);
			}
		}
		buf_put(&buf, &cap, &len, names[i], strlen(names[i]));
	}
	return buf;
}

NORETURN static void die_flag_scope(const Flag *f) {
	const char *names[CMD_COUNT];
	int n = 0;

	for (int i = 0; i < CMD_COUNT; i++) {
		if (f->commands & CMD_BIT(cli_commands[i].id))
			names[n++] = cli_commands[i].name;
	}
	if (n == 0)
		die("%s is not valid for any command", f->name);
	die("%s is only valid for %s", f->name, join_names(names, n, "and"));
}

NORETURN static void die_shell_choice(void) {
	const char *names[SHELL_COUNT];

	for (int i = 0; i < SHELL_COUNT; i++)
		names[i] = cli_shells[i].name;
	die("completions takes %s", join_names(names, SHELL_COUNT, "or"));
}

#define VALUE_MAX 8

static int split_values(const char *spec, const char **out) {
	int n = 0;
	for (const char *p = spec; *p && n < VALUE_MAX;) {
		while (*p == ' ')
			p++;
		if (!*p)
			break;
		const char *e = p;
		while (*e && *e != ' ')
			e++;
		out[n++] = p;
		p = e;
	}
	return n;
}

static int value_len(const char *v) {
	const char *e = v;
	while (*e && *e != ' ')
		e++;
	return (int)(e - v);
}

NORETURN static void die_flag_value(const Flag *f) {
	const char *raw[VALUE_MAX];
	char *owned[VALUE_MAX];
	const char *names[VALUE_MAX];
	int n = split_values(f->values, raw);

	for (int i = 0; i < n; i++) {
		int len = value_len(raw[i]);
		owned[i] = xmalloc((size_t)len + 1);
		memcpy(owned[i], raw[i], (size_t)len);
		owned[i][len] = '\0';
		names[i] = owned[i];
	}
	die("%s takes %s", f->name, join_names(names, n, "or"));
}

static const char *flag_value_match(const Flag *f, const char *given) {
	const char *raw[VALUE_MAX];
	int n = split_values(f->values, raw);

	for (int i = 0; i < n; i++) {
		int len = value_len(raw[i]);
		if ((int)strlen(given) == len && !strncmp(given, raw[i], (size_t)len))
			return raw[i];
	}
	return NULL;
}

static void check_flag_scope_mask(unsigned allowed, const int *opts) {
	for (int i = 0; i < FLAG_COUNT; i++) {
		if (opts[cli_flags[i].id] && !(cli_flags[i].commands & allowed))
			die_flag_scope(&cli_flags[i]);
	}
}

static void check_flag_scope(const Command *cmd, const int *opts) {
	check_flag_scope_mask(CMD_BIT(cmd->id), opts);
}

static int is_reg_file(const char *path) {
	struct stat st;
	return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/*
 * Read paths accept any openable file (FIFOs from process substitution,
 * /dev/fd/N, character devices); only writes need a regular file, because
 * commit_file replaces the target with rename().
 */
static int path_exists(const char *path) {
	struct stat st;
	return path && stat(path, &st) == 0;
}

/*
 * Resolve [file] KEY [VALUE] from positionals after the command word.
 * Explicit existing file wins; else ./.env when present.
 */
static void resolve_file_args(const char **rest, int nr, const char **file, const char **key,
                              const char **val) {
	*file = NULL;
	*key = NULL;
	*val = NULL;

	if (nr >= 1 && path_exists(rest[0])) {
		*file = rest[0];
		if (nr >= 2)
			*key = rest[1];
		if (nr >= 3)
			*val = rest[2];
		if (nr > 3)
			die("too many arguments");
		return;
	}

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
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);
#endif
	int opts[FLAG_COUNT] = {0};
	const char *optval[FLAG_COUNT] = {0};
	int options = 1, np = 0;
	HelpMode help = HELP_NONE;
	const char *pos[16];

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		const char *eq = options && a[0] == '-' ? strchr(a, '=') : NULL;
		char namebuf[64];
		const Flag *f = NULL;

		if (eq && (size_t)(eq - a) < sizeof(namebuf)) {
			memcpy(namebuf, a, (size_t)(eq - a));
			namebuf[eq - a] = '\0';
			f = cli_flag_by_name(namebuf);
			if (f && !f->values)
				die("%s takes no value", f->name);
			if (f && !flag_value_match(f, eq + 1))
				die_flag_value(f);
		}
		if (!f && !eq)
			f = options ? cli_flag_by_name(a) : NULL;

		if (options && !strcmp(a, "--"))
			options = 0;
		else if (f) {
			opts[f->id] = 1;
			optval[f->id] = eq ? eq + 1 : NULL;
		} else if (options && !strcmp(a, "-h"))
			help = HELP_SHORT;
		else if (options && !strcmp(a, "--help"))
			help = HELP_LONG;
		else if (options && (!strcmp(a, "-V") || !strcmp(a, "-v") || !strcmp(a, "--version")))
			print_version();
		else if (np < (int)(sizeof(pos) / sizeof(*pos)))
			pos[np++] = a;
		else
			die("too many arguments");
	}

	const Command *cmd = NULL;
	const char *file = NULL;
	const char *key = NULL;
	const char *val = NULL;
	const char *rest[16];
	int nr = 0;

	for (int i = 0; i < np; i++) {
		const Command *c = cli_command_by_name(pos[i]);
		if (!cmd && c)
			cmd = c;
		else
			rest[nr++] = pos[i];
	}

	if (help != HELP_NONE) {
		if (cmd)
			print_command_help(cmd);
		print_help(help == HELP_LONG);
	}

	if (np == 0)
		print_help(1);

	RedactWhen when = WHEN_AUTO;
	int show_control = opts[FLAG_SHOW_CONTROL] || opts[FLAG_RAW];

	if (opts[FLAG_RAW])
		when = WHEN_NEVER;
	if (opts[FLAG_REDACT]) {
		const char *v = optval[FLAG_REDACT];
		if (!v || !strcmp(v, "always"))
			when = WHEN_ALWAYS;
		else if (!strcmp(v, "never"))
			when = WHEN_NEVER;
		else if (!strcmp(v, "agent"))
			when = WHEN_AGENT;
		else if (!strcmp(v, "tty"))
			when = WHEN_TTY;
		else
			when = WHEN_AUTO;
		if (opts[FLAG_RAW] && when != WHEN_NEVER)
			die("--raw cannot be --redact=%s", v ? v : "always");
	}

	if (opts[FLAG_PARANOID]) {
		if (when == WHEN_NEVER)
			die("--paranoid cannot be %s", opts[FLAG_RAW] ? "--raw" : "--redact=never");
		if (!opts[FLAG_REDACT])
			when = WHEN_ALWAYS;
		redact_set_paranoid(1);
	}

	int bare = cmd == NULL;
	if (bare) {
		if (nr < 1)
			die("usage: envctl [<cmd>] [file] <KEY> [VALUE]");
		check_flag_scope_mask(CMD_BIT(CMD_GET) | CMD_BIT(CMD_SET), opts);
		if (opts[FLAG_ENV]) {
			cmd = command_by_id(nr > 1 ? CMD_SET : CMD_GET);
			if (nr == 1)
				key = rest[0];
		} else {
			resolve_file_args(rest, nr, &file, &key, &val);
			if (!key)
				die("usage: envctl [file] <KEY> [VALUE]  or  envctl <cmd> [file] ...");
			cmd = command_by_id(val ? CMD_SET : CMD_GET);
		}
	}

	check_flag_scope(cmd, opts);

	if (opts[FLAG_ALL] && opts[FLAG_ENV])
		die("--all is not valid with --env");

	if (cmd->id == CMD_COMPLETIONS) {
		if (nr > 1)
			die("too many arguments");
		if (nr < 1)
			die_shell_choice();
		const Shell *sh = cli_shell_by_name(rest[0]);
		if (!sh)
			die_shell_choice();
		act_completions(sh->id);
		stdout_flush_check();
		return 0;
	}

	if (cmd->id == CMD_MODULE) {
		if (nr > 1)
			die("too many arguments");
		if (nr < 1 || strcmp(rest[0], "pwsh") != 0)
			die("module takes pwsh");
		act_module_pwsh();
		stdout_flush_check();
		return 0;
	}

	if (cmd->id == CMD_REDACT) {
		if (opts[FLAG_ENV]) {
			if (opts[FLAG_NO_ENV])
				die("redact takes --env or --no-env, never both");
			if (nr > 0)
				die("too many arguments");
			return act_redact(NULL, 1);
		}
		if (opts[FLAG_NO_ENV]) {
			if (nr > 0)
				die("too many arguments");
		} else if (nr > 1) {
			die("too many arguments");
		} else if (nr == 1 && path_exists(rest[0])) {
			file = rest[0];
		} else if (nr == 1) {
			die("no such file: %s", rest[0]);
		} else if (is_reg_file(".env")) {
			file = ".env";
		}
		return act_redact(file, 0);
	}

	if (cmd->id == CMD_ENV) {
		if (nr > 0)
			die("too many arguments");
		int env_redact = want_redact(when == WHEN_AUTO ? WHEN_ALWAYS : when);
		display_set_escape(!show_control && (env_redact || stdout_isatty()));
		act_env_dump(opts[FLAG_SORT], env_redact);
		stdout_flush_check();
		return 0;
	}

	if (!bare) {
		if (cmd->id == CMD_LIST) {
			if (opts[FLAG_ENV]) {
				if (nr > 0)
					die("too many arguments");
			} else if (nr == 0) {
				if (!is_reg_file(".env"))
					die("list needs a file (no .env in cwd)");
				file = ".env";
			} else if (nr == 1 && path_exists(rest[0])) {
				file = rest[0];
			} else if (nr == 1) {
				die("no such file: %s", rest[0]);
			} else {
				die("too many arguments");
			}
		} else if (opts[FLAG_ENV]) {
			if (nr > 1)
				die("too many arguments");
			if (nr == 1)
				key = rest[0];
		} else {
			resolve_file_args(rest, nr, &file, &key, &val);
		}
	}

	if (!opts[FLAG_ENV]) {
		if (!path_exists(file))
			die("no such file: %s", file);
		int mutating = cmd->id != CMD_GET && cmd->id != CMD_LIST;
		if (mutating && !is_reg_file(file))
			die("not a regular file: %s", file);
	}

	int redact = want_redact(when);
	display_set_escape(!show_control && (redact || stdout_isatty()));

	if (cmd->id == CMD_LIST) {
		if (opts[FLAG_ENV]) {
			act_env_list(opts[FLAG_VALUES], redact, opts[FLAG_SORT]);
			stdout_flush_check();
			return 0;
		}
		Lines L = read_file(file);
		act_list(&L, opts[FLAG_VALUES], opts[FLAG_ALL], redact, opts[FLAG_SORT]);
		lines_free(&L);
		stdout_flush_check();
		return 0;
	}

	if (!key)
		die("%s needs KEY", cmd->name);
	if (!valid_keychars(key, strlen(key)))
		die("invalid key: '%s'", key);

	if (cmd->id != CMD_SET && val)
		die("too many arguments");

	if (opts[FLAG_ENV]) {
		int rc = act_env_get(key, redact);
		stdout_flush_check();
		return rc;
	}

	Lines L = read_file(file);
	size_t kl = strlen(key);

	if (cmd->id == CMD_GET) {
		int rc = act_get(&L, key, kl, redact);
		lines_free(&L);
		stdout_flush_check();
		return rc;
	}

	Lines out;
	if (cmd->id == CMD_SET)
		out = act_set(&L, key, kl, val ? val : "");
	else if (cmd->id == CMD_DISABLE)
		out = act_disable(&L, key, kl);
	else if (cmd->id == CMD_ENABLE)
		out = act_enable(&L, key, kl);
	else
		out = act_delete(&L, key, kl);

	if (opts[FLAG_DRY_RUN]) {
		if (!emit_diff(stdout, &L, &out, file, redact))
			fprintf(stderr, "%s: no changes\n", PROG);
	} else {
		commit_file(file, &out);
	}
	lines_free_borrowing(&out, &L);
	lines_free(&L);
	if (opts[FLAG_DRY_RUN])
		stdout_flush_check();

	return 0;
}
