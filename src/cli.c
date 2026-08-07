#include "cli.h"

#include <string.h>

#define M_SET CMD_BIT(CMD_SET)
#define M_GET CMD_BIT(CMD_GET)
#define M_DISABLE CMD_BIT(CMD_DISABLE)
#define M_ENABLE CMD_BIT(CMD_ENABLE)
#define M_DELETE CMD_BIT(CMD_DELETE)
#define M_LIST CMD_BIT(CMD_LIST)
#define M_REDACT CMD_BIT(CMD_REDACT)
#define M_ENV CMD_BIT(CMD_ENV)

#define M_MUTATING (M_SET | M_DISABLE | M_ENABLE | M_DELETE)
#define M_DISPLAY (M_MUTATING | M_GET | M_LIST)
#define M_EVERY (M_DISPLAY | M_REDACT | M_ENV)

const Command cli_commands[CMD_COUNT] = {
    {CMD_SET, "set", NULL, "[file] <KEY> [VALUE]", 1, "edit",
     "set or replace KEY, uncommenting if commented",
     "Sets KEY to VALUE, creating the assignment when it is absent. The first active definition is "
     "updated in place, any further active duplicates are commented out, and when no active "
     "definition exists the first commented one is revived. Failing all of that the assignment is "
     "appended. VALUE is literal: no shell or regex reinterpretation. An omitted VALUE writes an "
     "empty value."},
    {CMD_GET, "get", NULL, "[file] <KEY>", 1, "read", "print the active value; exit 1 if unset",
     "Prints the active value of KEY followed by a newline and exits 1 when KEY has no active "
     "definition. A multiline value prints in full."},
    {CMD_DISABLE, "disable", NULL, "[file] <KEY>", 1, "edit", "comment KEY out, keeping its value",
     "Comments out every active definition of KEY, keeping the value and its position in the "
     "file."},
    {CMD_ENABLE, "enable", NULL, "[file] <KEY>", 1, "edit", "uncomment KEY",
     "Uncomments the first commented definition of KEY."},
    {CMD_DELETE, "delete", "rm", "[file] <KEY>", 1, "edit",
     "remove KEY entirely, active and commented",
     "Removes every definition of KEY, active and commented alike."},
    {CMD_LIST, "list", "ls", "[file]", 1, "read", "print active keys",
     "Prints the active key names one per line in file order. --values appends each value under "
     "the redaction rules, and --all adds the commented keys tagged (disabled). A masked "
     "multiline value collapses to one line; an unmasked one shows its first line."},
    {CMD_REDACT, "redact", NULL, "[file]", 1, "redact", "filter stdin to stdout, masking secrets",
     "Reads text on stdin and writes it to stdout with secrets masked. The positional names the "
     "env file supplying literal values, defaulting to ./.env when it exists. See FILTER MODE."},
    {CMD_ENV, "env", NULL, "", 0, "redact", "print the process environment, always redacted",
     "Prints the whole process environment as KEY=VALUE lines with redaction always on, making it "
     "the one-word replacement for env | envctl redact --no-env. The first line reads "
     "# envctl VERSION (redacted) and names the build that produced the dump. Entries follow "
     "environ order, or key order under --sort. Names outside [A-Za-z_][A-Za-z0-9_]* are skipped, "
     "matching list."},
    {CMD_COMPLETIONS, "completions", NULL, "<shell>", 0, "shell",
     "print a completion script for a shell",
     "Writes a completion script for bash, zsh, fish, or pwsh to stdout. The script is generated "
     "at run time from the same command and flag tables the parser uses, so it offers exactly the "
     "flags each command accepts. See the README for where each shell wants the file."},
};

const Shell cli_shells[SHELL_COUNT] = {
    {SHELL_BASH, "bash"},
    {SHELL_ZSH, "zsh"},
    {SHELL_FISH, "fish"},
    {SHELL_PWSH, "pwsh"},
};

const Flag cli_flags[FLAG_COUNT] = {
    {FLAG_DRY_RUN, "--dry-run", M_MUTATING, "print a unified diff and write nothing",
     "Prints a unified diff of the change to stdout and writes nothing. Only changed lines appear. "
     "When the command would change nothing, stdout stays empty and envctl: no changes goes to "
     "stderr. Under redaction the +++ header reads +++ FILE (redacted) and both sides are "
     "masked."},
    {FLAG_VALUES, "--values", M_LIST, "also print values",
     "Prints each key's value after its name. Secret-looking values follow the redaction rules."},
    {FLAG_ALL, "--all", M_LIST, "also print disabled keys",
     "Includes commented keys, each tagged (disabled). A process environment has no commented "
     "entries, so this is rejected together with --env."},
    {FLAG_SORT, "--sort", M_LIST | M_ENV, "print entries sorted by key",
     "Prints entries sorted by key instead of in file or environ order."},
    {FLAG_ENV, "--env", M_GET | M_LIST | M_REDACT, "use the process environment instead of a file",
     "Reads the process environment in place of an env file. For redact this makes the "
     "environment's values the literal mask set."},
    {FLAG_NO_ENV, "--no-env", M_REDACT, "skip the env file's literal values, use heuristics only",
     "Skips the env file entirely so only the value-shape heuristics run. redact takes a file, "
     "--env, or --no-env, never two of them."},
    {FLAG_REDACT, "--redact", M_EVERY, "mask secret-looking values",
     "Forces masking on, whatever the terminal and agent detection would have chosen. redact and "
     "env mask unconditionally, so there it changes nothing."},
    {FLAG_RAW, "--raw", M_DISPLAY, "never mask, and never escape control bytes",
     "Forces masking off, overriding auto-redaction and --redact, and prints control bytes as "
     "they are instead of in caret notation."},
    {FLAG_PARANOID, "--paranoid", M_EVERY, "apply the entropy bar to every value",
     "Applies the entropy bar to every value, whatever its key is named, closing values such as "
     "RANDOM_THING=<44 random chars>. Trivial values, plain paths, and digest-like key names stay "
     "visible. Implies --redact and rejects --raw."},
};

const Command *cli_command_by_name(const char *name) {
	for (int i = 0; i < CMD_COUNT; i++) {
		if (!strcmp(name, cli_commands[i].name))
			return &cli_commands[i];
		if (cli_commands[i].alias && !strcmp(name, cli_commands[i].alias))
			return &cli_commands[i];
	}
	return NULL;
}

const Flag *cli_flag_by_name(const char *name) {
	for (int i = 0; i < FLAG_COUNT; i++) {
		if (!strcmp(name, cli_flags[i].name))
			return &cli_flags[i];
	}
	return NULL;
}

const Shell *cli_shell_by_name(const char *name) {
	for (int i = 0; i < SHELL_COUNT; i++) {
		if (!strcmp(name, cli_shells[i].name))
			return &cli_shells[i];
	}
	return NULL;
}
