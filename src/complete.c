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

static void put_value_words(const Flag *f, const char *sep) {
	int seen = 0;
	for (const char *p = f->values; *p;) {
		while (*p == ' ')
			p++;
		if (!*p)
			break;
		const char *e = p;
		while (*e && *e != ' ')
			e++;
		printf("%s%.*s", seen++ ? sep : "", (int)(e - p), p);
		p = e;
	}
}

static void put_value_spellings(const Flag *f, const char *sep, const char *quote) {
	for (const char *p = f->values; *p;) {
		while (*p == ' ')
			p++;
		if (!*p)
			break;
		const char *e = p;
		while (*e && *e != ' ')
			e++;
		printf("%s%s%s=%.*s%s", sep, quote, f->name, (int)(e - p), p, quote);
		p = e;
	}
}

static void put_command_flags(const Command *c, const char *sep) {
	int seen = 0;
	for (int i = 0; i < FLAG_COUNT; i++) {
		if (!flag_fits(c, &cli_flags[i]))
			continue;
		printf("%s%s", seen++ ? sep : "", cli_flags[i].name);
		if (cli_flags[i].values)
			put_value_spellings(&cli_flags[i], sep, "");
	}
}

static void put_zsh_flag_spec_body(const Flag *f, const char *indent) {
	printf("%s'%s", indent, f->name);
	if (f->values)
		fputs("=-", stdout);
	fputc('[', stdout);
	put_zsh_desc(f->summary);
	fputc(']', stdout);
	if (f->values) {
		fputs("::when:(", stdout);
		put_value_words(f, " ");
		fputc(')', stdout);
	}
	fputc('\'', stdout);
}

static void put_zsh_flag_spec(const Flag *f, const char *indent) {
	put_zsh_flag_spec_body(f, indent);
	fputc('\n', stdout);
}

static void put_zsh_flag_spec_cont(const Flag *f, const char *indent) {
	put_zsh_flag_spec_body(f, indent);
	fputs(" \\\n", stdout);
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
	      "\tif [[ ${cur} != -* && ${cmd} == completions ]]; then\n"
	      "\t\tmapfile -t COMPREPLY < <(compgen -W '",
	      stdout);
	put_shell_words(" ");
	fputs("' -- \"${cur}\")\n"
	      "\t\treturn\n"
	      "\tfi\n"
	      "\n"
	      "\tif [[ ${cur} != -* && ${cmd} == module ]]; then\n"
	      "\t\tmapfile -t COMPREPLY < <(compgen -W 'pwsh' -- \"${cur}\")\n"
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
	for (int i = 0; i < FLAG_COUNT; i++) {
		printf("%s%s", i ? " " : "", cli_flags[i].name);
		if (cli_flags[i].values)
			put_value_spellings(&cli_flags[i], " ", "");
	}
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

static int command_groups(const char **groups) {
	int n = 0;
	for (int i = 0; i < CMD_COUNT; i++) {
		int seen = 0;
		for (int g = 0; g < n; g++) {
			if (!strcmp(groups[g], cli_commands[i].group))
				seen = 1;
		}
		if (!seen)
			groups[n++] = cli_commands[i].group;
	}
	return n;
}

static const char *zsh_key_mode(CmdId id) {
	switch (id) {
	case CMD_ENABLE:
		return "disabled";
	case CMD_SET:
	case CMD_DELETE:
		return "all";
	default:
		return "active";
	}
}

static void put_zsh_usage_call(const Command *c) {
	fputs("\t\t\t\t\t_envctl_usage", stdout);
	for (const char *p = c->args; *p;) {
		while (*p == ' ')
			p++;
		if (!*p)
			break;
		const char *e = p;
		while (*e && *e != ' ')
			e++;
		printf(" '%.*s'", (int)(e - p), p);
		p = e;
	}
	fputc('\n', stdout);
}

static void zsh_script(void) {
	const char *groups[CMD_COUNT];
	int ngroups = command_groups(groups);

	fputs("#compdef envctl\n"
	      "\n"
	      "zstyle ':completion:*:*:envctl:*' file-patterns \\\n"
	      "\t'.*(-.):dotfiles:dotfile *(-.):plain-files:file *(-/):directories:directory'\n"
	      "\n"
	      "_envctl_usage() {\n"
	      "\tinteger done=0 i\n"
	      "\tlocal w msg\n"
	      "\tfor w in \"${(@)words[2,CURRENT-1]}\"; do\n"
	      "\t\t[[ $w == -* ]] || (( done++ ))\n"
	      "\tdone\n"
	      "\tmsg=\"%Benvctl ${words[1]}\"\n"
	      "\tfor ((i = 1; i <= $#; i++)); do\n"
	      "\t\tif (( i == done + 1 )); then\n"
	      "\t\t\tmsg+=\"%b %U${@[i]}%u\"\n"
	      "\t\telse\n"
	      "\t\t\tmsg+=\" ${@[i]}\"\n"
	      "\t\tfi\n"
	      "\tdone\n"
	      "\t(( done >= $# )) && msg+=\"%b\"\n"
	      "\tcompadd -x \"$msg\"\n"
	      "}\n"
	      "\n"
	      "_envctl_keys() {\n"
	      "\tlocal mode=$1 f=$2 txt\n"
	      "\tlocal -a lines active disabled\n"
	      "\tif [[ $f == --env ]]; then\n"
	      "\t\ttxt=$(\"$_envctl_cmd\" list --env 2>/dev/null) || return 1\n"
	      "\telse\n"
	      "\t\ttxt=$(\"$_envctl_cmd\" list --all -- \"$f\" 2>/dev/null) || {\n"
	      "\t\t\t_message -r \"not an env file: $f\"\n"
	      "\t\t\treturn 1\n"
	      "\t\t}\n"
	      "\tfi\n"
	      "\tlines=(${(f)txt})\n"
	      "\tactive=(${lines:#* \\(disabled\\)})\n"
	      "\tdisabled=(${${(M)lines:#* \\(disabled\\)}%% \\(disabled\\)})\n"
	      "\tcase $mode in\n"
	      "\t\tactive) lines=($active) ;;\n"
	      "\t\tdisabled) lines=($disabled) ;;\n"
	      "\t\tall) lines=($active $disabled) ;;\n"
	      "\tesac\n"
	      "\tif (( ! $#lines )); then\n"
	      "\t\t_message -r \"no matching keys in $f\"\n"
	      "\t\treturn 1\n"
	      "\tfi\n"
	      "\tcompadd -- $lines\n"
	      "}\n"
	      "\n"
	      "_envctl() {\n"
	      "\tlocal context state state_descr line\n"
	      "\tlocal _envctl_cmd=$words[1]\n"
	      "\ttypeset -A opt_args\n",
	      stdout);
	for (int g = 0; g < ngroups; g++) {
		printf("\tlocal -a cmds_%s\n", groups[g]);
		printf("\tcmds_%s=(\n", groups[g]);
		for (int i = 0; i < CMD_COUNT; i++) {
			if (strcmp(cli_commands[i].group, groups[g]) != 0)
				continue;
			printf("\t\t'%s:", cli_commands[i].name);
			put_zsh_desc(cli_commands[i].summary);
			fputs("'\n", stdout);
			if (cli_commands[i].alias)
				printf("\t\t'%s:alias for %s'\n", cli_commands[i].alias, cli_commands[i].name);
		}
		fputs("\t)\n", stdout);
	}
	fputs("\n"
	      "\tlocal -a cmdflags\n"
	      "\tlocal seen=\n"
	      "\tinteger i\n"
	      "\tfor ((i = 2; i < CURRENT; i++)); do\n"
	      "\t\tcase $words[i] in\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		printf("\t\t\t%s) seen=%s; break ;;\n", cli_commands[i].name, cli_commands[i].name);
		if (cli_commands[i].alias)
			printf("\t\t\t%s) seen=%s; break ;;\n", cli_commands[i].alias, cli_commands[i].name);
	}
	fputs("\t\tesac\n"
	      "\tdone\n"
	      "\tcase $seen in\n",
	      stdout);
	for (int i = 0; i < CMD_COUNT; i++) {
		const Command *c = &cli_commands[i];
		printf("\t\t%s)\n\t\t\tcmdflags=(\n", c->name);
		for (int f = 0; f < FLAG_COUNT; f++) {
			if (!flag_fits(c, &cli_flags[f]))
				continue;
			put_zsh_flag_spec(&cli_flags[f], "\t\t\t\t");
		}
		fputs("\t\t\t)\n\t\t\t;;\n", stdout);
	}
	fputs("\t\t*)\n\t\t\tcmdflags=(\n", stdout);
	for (int f = 0; f < FLAG_COUNT; f++) {
		put_zsh_flag_spec(&cli_flags[f], "\t\t\t\t");
	}
	fputs("\t\t\t)\n\t\t\t;;\n"
	      "\tesac\n"
	      "\n"
	      "\t_arguments -C \\\n"
	      "\t\t'(- *)'{-h,--help}'[print help and exit]' \\\n"
	      "\t\t'(- *)'{-v,-V,--version}'[print the version and exit]' \\\n"
	      "\t\t$cmdflags \\\n"
	      "\t\t'1: :->command' \\\n"
	      "\t\t'*:: :->args' && return 0\n"
	      "\n"
	      "\tcase $state in\n"
	      "\t\tcommand)\n",
	      stdout);
	for (int g = 0; g < ngroups; g++)
		printf("\t\t\t_describe -t %s-commands '%s command' cmds_%s -V %s\n", groups[g], groups[g],
		       groups[g], groups[g]);
	fputs("\t\t\t_files\n"
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
		put_zsh_usage_call(c);
		fputs("\t\t\t\t\t_arguments \\\n", stdout);
		put_zsh_help_specs();
		if (c->id == CMD_COMPLETIONS) {
			fputs("\t\t\t\t\t\t'1:shell:(", stdout);
			put_shell_words(" ");
			fputs(")' \\\n\t\t\t\t\t\t'*: :_default'\n\t\t\t\t\t;;\n", stdout);
			continue;
		}
		if (c->id == CMD_MODULE) {
			fputs("\t\t\t\t\t\t'1:shell:(pwsh)' \\\n"
			      "\t\t\t\t\t\t'*: :_default'\n\t\t\t\t\t;;\n",
			      stdout);
			continue;
		}
		for (int f = 0; f < FLAG_COUNT; f++) {
			if (!flag_fits(c, &cli_flags[f]))
				continue;
			put_zsh_flag_spec_cont(&cli_flags[f], "\t\t\t\t\t\t");
		}
		if (!c->takes_file) {
			fputs("\t\t\t\t\t\t'*: :'\n\t\t\t\t\t;;\n", stdout);
			continue;
		}
		int nparts = 0;
		for (const char *p = c->args; *p;) {
			while (*p == ' ')
				p++;
			if (!*p)
				break;
			nparts++;
			while (*p && *p != ' ')
				p++;
		}
		for (int n = 1; n <= nparts; n++)
			printf("\t\t\t\t\t\t'%d: :->pos%d'%s\n", n, n, n < nparts ? " \\" : "");
		fputs("\t\t\t\t\tcase $state in\n\t\t\t\t\t\tpos1)\n", stdout);
		if (c->id == CMD_GET)
			printf("\t\t\t\t\t\t\tif (( ${+opt_args[--env]} )); then\n"
			       "\t\t\t\t\t\t\t\t_envctl_keys active --env\n"
			       "\t\t\t\t\t\t\telse\n"
			       "\t\t\t\t\t\t\t\t_files\n"
			       "\t\t\t\t\t\t\t\t[[ -f .env ]] && _envctl_keys %s .env\n"
			       "\t\t\t\t\t\t\tfi\n",
			       zsh_key_mode(c->id));
		else if (c->id == CMD_LIST)
			fputs("\t\t\t\t\t\t\t(( ${+opt_args[--env]} )) || _files\n", stdout);
		else if (c->id == CMD_REDACT)
			fputs("\t\t\t\t\t\t\t(( ${+opt_args[--env]} || ${+opt_args[--no-env]} )) || _files\n",
			      stdout);
		else
			printf("\t\t\t\t\t\t\t_files\n"
			       "\t\t\t\t\t\t\t[[ -f .env ]] && _envctl_keys %s .env\n",
			       zsh_key_mode(c->id));
		fputs("\t\t\t\t\t\t\t;;\n", stdout);
		if (nparts >= 2)
			printf("\t\t\t\t\t\tpos2)\n"
			       "\t\t\t\t\t\t\tlocal f=$line[1]\n"
			       "\t\t\t\t\t\t\t[[ $f == \\~* ]] && f=${~f}\n"
			       "\t\t\t\t\t\t\tif [[ -e $f ]]; then\n"
			       "\t\t\t\t\t\t\t\t_envctl_keys %s \"$f\"\n"
			       "\t\t\t\t\t\t\telif [[ ! -f .env ]]; then\n"
			       "\t\t\t\t\t\t\t\t_message -r \"no such file: $line[1]\"\n"
			       "\t\t\t\t\t\t\tfi\n"
			       "\t\t\t\t\t\t\t;;\n",
			       zsh_key_mode(c->id));
		fputs("\t\t\t\t\tesac\n\t\t\t\t\t;;\n", stdout);
	}
	fputs("\t\t\tesac\n"
	      "\t\t\t;;\n"
	      "\tesac\n"
	      "}\n"
	      "\n"
	      "if [ \"${funcstack[1]}\" = \"_envctl\" ]; then\n"
	      "\t_envctl \"$@\"\n"
	      "else\n"
	      "\tcompdef _envctl envctl\n"
	      "fi\n",
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
	for (int f = 0; f < FLAG_COUNT; f++) {
		printf("complete -c envctl -n __fish_use_subcommand -l %s",
		       long_flag_body(cli_flags[f].name));
		if (cli_flags[f].values) {
			fputs(" -a '", stdout);
			put_value_words(&cli_flags[f], " ");
			fputc('\'', stdout);
		}
		fputs(" -d '", stdout);
		put_sq(cli_flags[f].summary);
		fputs("'\n", stdout);
	}
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
			printf("' -l %s", long_flag_body(cli_flags[f].name));
			if (cli_flags[f].values) {
				fputs(" -a '", stdout);
				put_value_words(&cli_flags[f], " ");
				fputc('\'', stdout);
			}
			fputs(" -d '", stdout);
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
		if (c->id == CMD_MODULE) {
			if (!printed++)
				fputc('\n', stdout);
			printf("complete -c envctl -n '__fish_seen_subcommand_from %s' -a 'pwsh'\n", c->name);
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
			if (!flag_fits(&cli_commands[i], &cli_flags[f]))
				continue;
			printf("%s'%s'", seen++ ? ", " : "", cli_flags[f].name);
			if (cli_flags[f].values)
				put_value_spellings(&cli_flags[f], ", ", "'");
		}
		put_help_flags(seen, ", ", "'");
		fputs(")\n", stdout);
	}
	fputs("\t\t'' = @(", stdout);
	for (int f = 0; f < FLAG_COUNT; f++) {
		printf("%s'%s'", f ? ", " : "", cli_flags[f].name);
		if (cli_flags[f].values)
			put_value_spellings(&cli_flags[f], ", ", "'");
	}
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
	    "\t} elseif ($cmd -eq 'module') {\n"
	    "\t\t$candidates = @('pwsh')\n"
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
