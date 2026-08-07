/*
 * envctl — manage keys in env files.
 *
 * Build: make  (see Makefile; sources under src/)
 */
#define _GNU_SOURCE
#include "cli.h"
#include "diff.h"
#include "envsrc.h"
#include "fileio.h"
#include "filter.h"
#include "help.h"
#include "lines.h"
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

static const Command *command_by_id(CmdId id) {
	for (int i = 0; i < CMD_COUNT; i++) {
		if (cli_commands[i].id == id)
			return &cli_commands[i];
	}
	die("no such command id: %d", (int)id);
}

NORETURN static void die_flag_scope(const Flag *f) {
	char *list = NULL;
	size_t cap = 0, len = 0;
	int total = 0, seen = 0;

	for (int i = 0; i < CMD_COUNT; i++) {
		if (f->commands & CMD_BIT(cli_commands[i].id))
			total++;
	}
	for (int i = 0; i < CMD_COUNT; i++) {
		if (!(f->commands & CMD_BIT(cli_commands[i].id)))
			continue;
		if (seen > 0) {
			const char *sep = seen == total - 1 ? (total == 2 ? " and " : ", and ") : ", ";
			buf_put(&list, &cap, &len, sep, strlen(sep));
		}
		buf_put(&list, &cap, &len, cli_commands[i].name, strlen(cli_commands[i].name));
		seen++;
	}
	die("%s is only valid for %s", f->name, list);
}

static void check_flag_scope(const Command *cmd, const int *opts) {
	for (int i = 0; i < FLAG_COUNT; i++) {
		if (opts[cli_flags[i].id] && !(cli_flags[i].commands & CMD_BIT(cmd->id)))
			die_flag_scope(&cli_flags[i]);
	}
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
	int options = 1, np = 0;
	const char *pos[16];

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		const Flag *f = options ? cli_flag_by_name(a) : NULL;

		if (options && !strcmp(a, "--"))
			options = 0;
		else if (f)
			opts[f->id] = 1;
		else if (options && !strcmp(a, "-h"))
			print_help(0);
		else if (options && !strcmp(a, "--help"))
			print_help(1);
		else if (options && (!strcmp(a, "-V") || !strcmp(a, "-v") || !strcmp(a, "--version")))
			print_version();
		else if (np < (int)(sizeof(pos) / sizeof(*pos)))
			pos[np++] = a;
		else
			die("too many arguments");
	}

	if (np == 0)
		print_help(1);

	if (opts[FLAG_PARANOID]) {
		if (opts[FLAG_RAW])
			die("--paranoid cannot be --raw");
		redact_set_paranoid(1);
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

	int bare = cmd == NULL;
	if (bare) {
		if (nr < 1)
			die("usage: envctl [<cmd>] [file] <KEY> [VALUE]");
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
		act_env_dump(opts[FLAG_SORT]);
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

	int redact = want_redact(opts[FLAG_REDACT] || opts[FLAG_PARANOID], opts[FLAG_RAW]);
	display_set_escape(!opts[FLAG_RAW] && (redact || stdout_isatty()));

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
