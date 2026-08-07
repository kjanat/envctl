#include "help.h"

#include "agent.h"
#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WRAP_WIDTH 78

static const char *AI_PREAMBLE =
    "You are an AI coding agent. Use envctl to change a key in any env / .env-style file.\n"
    "NEVER hand-edit an env file to add, change, comment, or remove a key -\n"
    "envctl does it in place, atomically, preserving order, comments, and mode.\n"
    "If ./.env exists you may omit the file argument. Secret-looking values are\n"
    "redacted on a TTY by default; use --raw only when you truly need full secrets.\n"
    "Pipe command output through 'envctl redact' to mask secrets in what you print.\n\n";

typedef struct {
	int col;
	int indent;
} Wrap;

static void wrap_start(Wrap *w, const char *label) {
	fputs(label, stdout);
	w->indent = (int)strlen(label);
	w->col = w->indent;
}

static void wrap_word(Wrap *w, const char *word) {
	int n = (int)strlen(word);
	if (w->col > w->indent) {
		if (w->col + 1 + n > WRAP_WIDTH) {
			printf("\n%*s", w->indent, "");
			w->col = w->indent;
		} else {
			fputc(' ', stdout);
			w->col++;
		}
	}
	fputs(word, stdout);
	w->col += n;
}

static int widest_command_name(void) {
	int w = 0;
	for (int i = 0; i < CMD_COUNT; i++) {
		int n = (int)strlen(cli_commands[i].name);
		if (n > w)
			w = n;
	}
	return w;
}

static int widest_command_args(void) {
	int w = 0;
	for (int i = 0; i < CMD_COUNT; i++) {
		int n = (int)strlen(cli_commands[i].args);
		if (n > w)
			w = n;
	}
	return w;
}

static int widest_flag_name(void) {
	int w = 0;
	for (int i = 0; i < FLAG_COUNT; i++) {
		int n = (int)strlen(cli_flags[i].name);
		if (n > w)
			w = n;
	}
	return w;
}

static void print_short_usage(void) {
	char word[64];
	Wrap w;

	fputs("usage: envctl <cmd> [file] [args...]\n"
	      "       envctl [file] <KEY> [VALUE]\n",
	      stdout);

	wrap_start(&w, "  commands: ");
	for (int i = 0; i < CMD_COUNT; i++) {
		if (cli_commands[i].alias)
			snprintf(word, sizeof word, "%s|%s", cli_commands[i].name, cli_commands[i].alias);
		else
			snprintf(word, sizeof word, "%s", cli_commands[i].name);
		wrap_word(&w, word);
	}
	fputc('\n', stdout);

	wrap_start(&w, "  flags:    ");
	for (int i = 0; i < FLAG_COUNT; i++)
		wrap_word(&w, cli_flags[i].name);
	fputc('\n', stdout);

	fputs("  file:     optional when ./.env exists\n"
	      "  bare:     envctl [file] <KEY> == get, with VALUE == set\n"
	      "  more:     --help, or man envctl\n"
	      "  version:  -v | -V | --version\n",
	      stdout);
}

static void print_long_usage(void) {
	int nw = widest_command_name();
	int aw = widest_command_args();
	int fw = widest_flag_name();

	fputs("envctl — manage keys in env files\n"
	      "\n"
	      "Usage:\n"
	      "  envctl <cmd> [file] [args...]\n"
	      "  envctl [file] <KEY>            get\n"
	      "  envctl [file] <KEY> <VALUE>    set\n"
	      "\n"
	      "Commands:\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++)
		printf("  %-*s  %-*s  %s\n", nw, cli_commands[i].name, aw, cli_commands[i].args,
		       cli_commands[i].summary);

	fputs("\nAliases:", stdout);
	for (int i = 0, seen = 0; i < CMD_COUNT; i++) {
		if (!cli_commands[i].alias)
			continue;
		printf("%s %s = %s", seen++ ? "," : "", cli_commands[i].alias, cli_commands[i].name);
	}
	fputs("\nFile: optional when ./.env exists as a regular file\n"
	      "\n"
	      "Flags:\n",
	      stdout);
	for (int i = 0; i < FLAG_COUNT; i++)
		printf("  %-*s  %s\n", fw, cli_flags[i].name, cli_flags[i].summary);
	printf("  %-*s  print short usage\n", fw, "-h");
	printf("  %-*s  print this help\n", fw, "--help");
	printf("  %-*s  print the version this binary was built from (also -v, -V)\n", fw, "--version");

	fputs("\nRedaction rules, filter mode, and guarantees: man envctl\n", stdout);
}

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
		print_short_usage();
	} else {
		if (detect_agent())
			fputs(AI_PREAMBLE, stdout);
		print_long_usage();
	}
	stdout_flush_check();
	exit(0);
}
