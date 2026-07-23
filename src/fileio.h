#ifndef ENVCTL_FILEIO_H
#define ENVCTL_FILEIO_H

#include "lines.h"

#include <stdio.h>

void emit(FILE *out, Lines *L, int redact);
void commit_file(const char *file, Lines *out);

#endif
