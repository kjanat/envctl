#ifndef ENVCTL_HELP_H
#define ENVCTL_HELP_H

#include "cli.h"
#include "util.h"

/* longform: 0 = short (-h); 1 = long (--help or no args). */
NORETURN void print_help(int longform);
NORETURN void print_command_help(const Command *cmd);
NORETURN void print_version(void);

#endif
