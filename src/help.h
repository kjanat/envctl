#ifndef ENVCTL_HELP_H
#define ENVCTL_HELP_H

#include "util.h"

/* longform: 0 = short (-h); 1 = long (--help or no args). */
NORETURN void print_help(int longform);

#endif
