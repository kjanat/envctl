#ifndef ENVCTL_FILEIO_H
#define ENVCTL_FILEIO_H

#include "lines.h"

#include <stdio.h>

size_t render_span(FILE *out, const Lines *L, size_t i, size_t span, const char *prefix,
                   int redact);
void emit(FILE *out, const Lines *L);
void commit_file(const char *file, Lines *out);

#endif
