/*
 * envctl — manage keys in env files.
 *
 * Build: make  (see Makefile; sources under src/)
 */
#define _GNU_SOURCE
#include "fileio.h"
#include "help.h"
#include "lines.h"
#include "redact.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#ifndef S_ISREG
#define S_ISREG(m) (((m)&_S_IFMT) == _S_IFREG)
#endif
#endif

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
 * Explicit existing file wins; else ./.env when present.
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
			print_help(0);
		else if (!strcmp(a, "--help"))
			print_help(1);
		else if (np < (int)(sizeof(pos) / sizeof(*pos)))
			pos[np++] = a;
		else
			die("too many arguments");
	}

	if (np == 0)
		print_help(1);

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
	else
		out = act_delete(&L, key, kl);

	if (dry)
		emit(stdout, &out, redact);
	else
		commit_file(file, &out);

	return 0;
}
