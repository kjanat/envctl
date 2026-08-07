#include "complete.h"

#include "util.h"

#include <stdio.h>
#include <string.h>

/* -h and --version are actions rather than table flags, so the generators carry them here. */
static const char *const help_flags[] = {"-h", "--help", "-v", "-V", "--version"};
#define HELP_FLAG_COUNT ((int)(sizeof help_flags / sizeof *help_flags))

static int flag_fits(const Command *c, const Flag *f) {
	return (f->commands & CMD_BIT(c->id)) != 0;
}

static void put_help_flags(int precedes, const char *sep, const char *quote) {
	for (int i = 0; i < HELP_FLAG_COUNT; i++) {
		if (i || precedes)
			fputs(sep, stdout);
		printf("%s%s%s", quote, help_flags[i], quote);
	}
}

static void put_zsh_help_specs(void) {
	fputs("\t\t\t\t\t\t'(- *)'{-h,--help}'[print help and exit]' \\\n"
	      "\t\t\t\t\t\t'(- *)'{-v,-V,--version}'[print the version and exit]' \\\n",
	      stdout);
}

/* fish names a long option without its dashes, so the table may not carry a short one. */
static const char *long_flag_body(const char *name) {
	if (strncmp(name, "--", 2) != 0)
		die("flag %s is not a long option; the fish generator cannot name it", name);
	return name + 2;
}

static int has_flags(const Command *c) {
	for (int i = 0; i < FLAG_COUNT; i++) {
		if (flag_fits(c, &cli_flags[i]))
			return 1;
	}
	return 0;
}

/* A backslash is an escape inside fish's single quotes, so it has to be doubled. */
static void put_sq(const char *s) {
	for (const char *p = s; *p; p++) {
		if (*p == '\'')
			fputs("'\\''", stdout);
		else if (*p == '\\')
			fputs("\\\\", stdout);
		else
			fputc(*p, stdout);
	}
}

static void put_pwsh_sq(const char *s) {
	for (const char *p = s; *p; p++) {
		if (*p == '\'')
			fputs("''", stdout);
		else
			fputc(*p, stdout);
	}
}

static void put_zsh_desc(const char *s) {
	for (const char *p = s; *p; p++) {
		if (*p == '\'')
			fputs("'\\''", stdout);
		else if (*p == '\\' || *p == ':' || *p == '[' || *p == ']')
			printf("\\%c", *p);
		else
			fputc(*p, stdout);
	}
}

static void put_command_words(const char *sep, int aliases) {
	int seen = 0;
	for (int i = 0; i < CMD_COUNT; i++) {
		printf("%s%s", seen++ ? sep : "", cli_commands[i].name);
		if (aliases && cli_commands[i].alias)
			printf("%s%s", sep, cli_commands[i].alias);
	}
}

static void put_command_flags(const Command *c, const char *sep) {
	int seen = 0;
	for (int i = 0; i < FLAG_COUNT; i++) {
		if (flag_fits(c, &cli_flags[i]))
			printf("%s%s", seen++ ? sep : "", cli_flags[i].name);
	}
}

static void put_shell_words(const char *sep) {
	for (int i = 0; i < SHELL_COUNT; i++)
		printf("%s%s", i ? sep : "", cli_shells[i].name);
}

static int any_file_command(void) {
	for (int i = 0; i < CMD_COUNT; i++) {
		if (cli_commands[i].takes_file)
			return 1;
	}
	return 0;
}

static void bash_script(void) {
	fputs("_envctl() {\n"
	      "\tlocal cur cmd i flags\n"
	      "\tlocal -a hits\n"
	      "\tcur=${COMP_WORDS[COMP_CWORD]}\n"
	      "\tcmd=\n"
	      "\tfor ((i = 1; i < COMP_CWORD; i++)); do\n"
	      "\t\tcase ${COMP_WORDS[i]} in\n"
	      "\t\t\t",
	      stdout);
	put_command_words(" | ", 0);
	fputs(")\n"
	      "\t\t\t\tcmd=${COMP_WORDS[i]}\n"
	      "\t\t\t\tbreak\n"
	      "\t\t\t\t;;\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		if (!cli_commands[i].alias)
			continue;
		printf("\t\t\t%s)\n"
		       "\t\t\t\tcmd=%s\n"
		       "\t\t\t\tbreak\n"
		       "\t\t\t\t;;\n",
		       cli_commands[i].alias, cli_commands[i].name);
	}
	fputs("\t\tesac\n"
	      "\tdone\n"
	      "\n"
	      "\tif [[ ${cmd} == completions ]]; then\n"
	      "\t\tmapfile -t COMPREPLY < <(compgen -W '",
	      stdout);
	put_shell_words(" ");
	fputs("' -- \"${cur}\")\n"
	      "\t\treturn\n"
	      "\tfi\n"
	      "\n"
	      "\tflags=\n"
	      "\tcase ${cmd} in\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		printf("\t\t%s) flags='", cli_commands[i].name);
		put_command_flags(&cli_commands[i], " ");
		put_help_flags(has_flags(&cli_commands[i]), " ", "");
		fputs("' ;;\n", stdout);
	}
	fputs("\t\t*) flags='", stdout);
	for (int i = 0; i < FLAG_COUNT; i++)
		printf("%s%s", i ? " " : "", cli_flags[i].name);
	put_help_flags(1, " ", "");
	fputs("' ;;\n"
	      "\tesac\n"
	      "\n"
	      "\tif [[ ${cur} == -* ]]; then\n"
	      "\t\tmapfile -t COMPREPLY < <(compgen -W \"${flags}\" -- \"${cur}\")\n"
	      "\t\treturn\n"
	      "\tfi\n"
	      "\n"
	      "\tif [[ -z ${cmd} ]]; then\n"
	      "\t\tmapfile -t COMPREPLY < <(compgen -W '",
	      stdout);
	put_command_words(" ", 1);
	fputs("' -- \"${cur}\")\n"
	      "\t\tmapfile -t hits < <(compgen -f -- \"${cur}\")\n"
	      "\t\t((${#hits[@]})) && COMPREPLY+=(\"${hits[@]}\")\n"
	      "\t\treturn\n"
	      "\tfi\n",
	      stdout);
	if (any_file_command()) {
		fputs("\n"
		      "\tcase ${cmd} in\n"
		      "\t\t",
		      stdout);
		int seen = 0;
		for (int i = 0; i < CMD_COUNT; i++) {
			if (cli_commands[i].takes_file)
				printf("%s%s", seen++ ? " | " : "", cli_commands[i].name);
		}
		fputs(")\n"
		      "\t\t\tmapfile -t COMPREPLY < <(compgen -f -- \"${cur}\")\n"
		      "\t\t\t;;\n"
		      "\tesac\n",
		      stdout);
	}
	fputs("}\n"
	      "\n"
	      "complete -F _envctl envctl\n",
	      stdout);
}

static void zsh_script(void) {
	fputs("#compdef envctl\n"
	      "\n"
	      "_envctl() {\n"
	      "\tlocal context state state_descr line\n"
	      "\ttypeset -A opt_args\n"
	      "\tlocal -a commands\n"
	      "\tcommands=(\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		printf("\t\t'%s:", cli_commands[i].name);
		put_zsh_desc(cli_commands[i].summary);
		fputs("'\n", stdout);
		if (cli_commands[i].alias)
			printf("\t\t'%s:alias for %s'\n", cli_commands[i].alias, cli_commands[i].name);
	}
	fputs("\t)\n"
	      "\n"
	      "\t_arguments -C \\\n"
	      "\t\t'(- *)'{-h,--help}'[print help and exit]' \\\n"
	      "\t\t'(- *)'{-v,-V,--version}'[print the version and exit]' \\\n"
	      "\t\t'1: :->command' \\\n"
	      "\t\t'*:: :->args' && return 0\n"
	      "\n"
	      "\tcase $state in\n"
	      "\t\tcommand)\n"
	      "\t\t\t_describe -t commands 'envctl command' commands\n"
	      "\t\t\t_files\n"
	      "\t\t\t;;\n"
	      "\t\targs)\n"
	      "\t\t\tcase $words[1] in\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		const Command *c = &cli_commands[i];
		printf("\t\t\t\t%s", c->name);
		if (c->alias)
			printf(" | %s", c->alias);
		fputs(")\n", stdout);
		fputs("\t\t\t\t\t_arguments \\\n", stdout);
		put_zsh_help_specs();
		if (c->id == CMD_COMPLETIONS) {
			fputs("\t\t\t\t\t\t'*:shell:(", stdout);
			put_shell_words(" ");
			fputs(")'\n\t\t\t\t\t;;\n", stdout);
			continue;
		}
		for (int f = 0; f < FLAG_COUNT; f++) {
			if (!flag_fits(c, &cli_flags[f]))
				continue;
			printf("\t\t\t\t\t\t'%s[", cli_flags[f].name);
			put_zsh_desc(cli_flags[f].summary);
			fputs("]' \\\n", stdout);
		}
		if (c->takes_file)
			fputs("\t\t\t\t\t\t'*:file:_files'\n", stdout);
		else
			fputs("\t\t\t\t\t\t'*: :'\n", stdout);
		fputs("\t\t\t\t\t;;\n", stdout);
	}
	fputs("\t\t\tesac\n"
	      "\t\t\t;;\n"
	      "\tesac\n"
	      "}\n"
	      "\n"
	      "_envctl \"$@\"\n",
	      stdout);
}

static void fish_script(void) {
	fputs("complete -c envctl -f\n"
	      "\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		printf("complete -c envctl -n __fish_use_subcommand -a %s -d '", cli_commands[i].name);
		put_sq(cli_commands[i].summary);
		fputs("'\n", stdout);
		if (cli_commands[i].alias)
			printf("complete -c envctl -n __fish_use_subcommand -a %s -d 'alias for %s'\n",
			       cli_commands[i].alias, cli_commands[i].name);
	}
	fputs("complete -c envctl -n __fish_use_subcommand -F\n"
	      "\n"
	      "complete -c envctl -s h -l help -d 'print help and exit'\n"
	      "complete -c envctl -s V -l version -d 'print the version and exit'\n"
	      "complete -c envctl -s v -l version -d 'print the version and exit'\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		const Command *c = &cli_commands[i];
		int printed = 0;
		for (int f = 0; f < FLAG_COUNT; f++) {
			if (!flag_fits(c, &cli_flags[f]))
				continue;
			if (!printed++)
				fputc('\n', stdout);
			printf("complete -c envctl -n '__fish_seen_subcommand_from %s", c->name);
			if (c->alias)
				printf(" %s", c->alias);
			printf("' -l %s -d '", long_flag_body(cli_flags[f].name));
			put_sq(cli_flags[f].summary);
			fputs("'\n", stdout);
		}
		if (c->takes_file) {
			if (!printed++)
				fputc('\n', stdout);
			printf("complete -c envctl -n '__fish_seen_subcommand_from %s", c->name);
			if (c->alias)
				printf(" %s", c->alias);
			fputs("' -F\n", stdout);
		}
		if (c->id == CMD_COMPLETIONS) {
			if (!printed++)
				fputc('\n', stdout);
			printf("complete -c envctl -n '__fish_seen_subcommand_from %s' -a '", c->name);
			put_shell_words(" ");
			fputs("'\n", stdout);
		}
	}
}

static void pwsh_script(void) {
	fputs("Register-ArgumentCompleter -Native -CommandName envctl -ScriptBlock {\n"
	      "\tparam($wordToComplete, $commandAst, $cursorPosition)\n"
	      "\n"
	      "\t$commands = @(",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++)
		printf("%s'%s'", i ? ", " : "", cli_commands[i].name);
	fputs(")\n"
	      "\t$aliases = @{",
	      stdout);
	{
		int seen = 0;
		for (int i = 0; i < CMD_COUNT; i++) {
			if (cli_commands[i].alias)
				printf("%s '%s' = '%s'", seen++ ? ";" : "", cli_commands[i].alias,
				       cli_commands[i].name);
		}
	}
	fputs(" }\n"
	      "\t$flags = @{\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		printf("\t\t'%s' = @(", cli_commands[i].name);
		int seen = 0;
		for (int f = 0; f < FLAG_COUNT; f++) {
			if (flag_fits(&cli_commands[i], &cli_flags[f]))
				printf("%s'%s'", seen++ ? ", " : "", cli_flags[f].name);
		}
		put_help_flags(seen, ", ", "'");
		fputs(")\n", stdout);
	}
	fputs("\t\t'' = @(", stdout);
	for (int f = 0; f < FLAG_COUNT; f++)
		printf("%s'%s'", f ? ", " : "", cli_flags[f].name);
	put_help_flags(1, ", ", "'");
	fputs(")\n"
	      "\t}\n"
	      "\t$tips = @{\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		printf("\t\t'%s' = '", cli_commands[i].name);
		put_pwsh_sq(cli_commands[i].summary);
		fputs("'\n", stdout);
		if (cli_commands[i].alias)
			printf("\t\t'%s' = 'alias for %s'\n", cli_commands[i].alias, cli_commands[i].name);
	}
	for (int f = 0; f < FLAG_COUNT; f++) {
		printf("\t\t'%s' = '", cli_flags[f].name);
		put_pwsh_sq(cli_flags[f].summary);
		fputs("'\n", stdout);
	}
	fputs("\t}\n"
	      "\n"
	      "\t$cmd = ''\n"
	      "\tforeach ($e in @($commandAst.CommandElements | Select-Object -Skip 1)) {\n"
	      "\t\t$t = $e.ToString()\n"
	      "\t\tif ($aliases.ContainsKey($t)) { $cmd = $aliases[$t]; break }\n"
	      "\t\tif ($commands -contains $t) { $cmd = $t; break }\n"
	      "\t}\n"
	      "\n"
	      "\t$candidates = @()\n"
	      "\tif ($cmd -eq 'completions') {\n"
	      "\t\t$candidates = @(",
	      stdout);
	for (int i = 0; i < SHELL_COUNT; i++)
		printf("%s'%s'", i ? ", " : "", cli_shells[i].name);
	fputs(
	    ")\n"
	    "\t} elseif ($wordToComplete.StartsWith('-')) {\n"
	    "\t\t$candidates = $flags[$cmd]\n"
	    "\t} elseif ($cmd -eq '') {\n"
	    "\t\t$candidates = $commands + $aliases.Keys\n"
	    "\t}\n"
	    "\n"
	    "\t$candidates | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {\n"
	    "\t\t$tip = $tips[$_]\n"
	    "\t\tif (-not $tip) { $tip = $_ }\n"
	    "\t\t[System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $tip)\n"
	    "\t}\n"
	    "}\n",
	    stdout);
}

void act_completions(ShellId shell) {
	switch (shell) {
	case SHELL_BASH:
		bash_script();
		break;
	case SHELL_ZSH:
		zsh_script();
		break;
	case SHELL_FISH:
		fish_script();
		break;
	case SHELL_PWSH:
		pwsh_script();
		break;
	case SHELL_COUNT:
		break;
	}
}
