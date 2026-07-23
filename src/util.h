#ifndef ENVCTL_UTIL_H
#define ENVCTL_UTIL_H

#include <stddef.h>

#if defined(_MSC_VER)
#define NORETURN __declspec(noreturn)
#else
#define NORETURN _Noreturn
#endif

extern const char *PROG;

int stdout_isatty(void);
NORETURN void die(const char *fmt, ...);
void *xmalloc(size_t n);
void *xrealloc(void *q, size_t n);
char *xstrdup(const char *s);

#endif
