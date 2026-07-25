#ifndef ENVCTL_DIFF_H
#define ENVCTL_DIFF_H

#include "lines.h"

#include <stdio.h>

int emit_diff(FILE *out, const Lines *before, const Lines *after, const char *file, int redact);

#endif
