#define _GNU_SOURCE
#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <stdio.h>
#define strdup _strdup
#else
#include <unistd.h>
#endif

const char *PROG = "envctl";

int stdout_isatty(void) {
#ifdef _WIN32
	return _isatty(_fileno(stdout));
#else
	return isatty(STDOUT_FILENO);
#endif
}

NORETURN void die(const char *fmt, ...) {
	va_list ap;

	fprintf(stderr, "%s: ", PROG);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(2);
}

void *xmalloc(size_t n) {
	void *p = malloc(n);
	if (!p)
		die("out of memory");
	return p;
}

void *xrealloc(void *q, size_t n) {
	void *p = realloc(q, n);
	if (!p)
		die("out of memory");
	return p;
}

char *xstrdup(const char *s) {
	char *p = strdup(s);
	if (!p)
		die("out of memory");
	return p;
}

void buf_need(char **buf, size_t *cap, size_t need) {
	if (need <= *cap)
		return;
	size_t c = *cap ? *cap : 256;
	while (c < need) {
		if (c > (size_t)-1 / 2)
			die("out of memory");
		c *= 2;
	}
	*buf = xrealloc(*buf, c);
	*cap = c;
}

void buf_put(char **buf, size_t *cap, size_t *len, const char *s, size_t n) {
	buf_need(buf, cap, *len + n + 1);
	memcpy(*buf + *len, s, n);
	*len += n;
	(*buf)[*len] = '\0';
}

void stdout_flush_check(void) {
	if (fflush(stdout) != 0 || ferror(stdout))
		die("write failed");
}
