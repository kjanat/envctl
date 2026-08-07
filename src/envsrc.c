/*
 * Process-environment source: read the environment like an env file.
 *
 * Each environ entry is one atomic KEY=VALUE pair; env-file span logic
 * never applies (a value with an unclosed quote or embedded newline is
 * still a single entry, never a continuation of the next one).
 */
#define _GNU_SOURCE
#include "envsrc.h"

#include "lines.h"
#include "redact.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
char *const *env_entries(void) { return _environ; }
#else
extern char **environ;

char *const *env_entries(void) { return environ; }
#endif

int act_env_get(const char *key, int redact) {
	const char *val = getenv(key);
	if (!val)
		return 1;
	print_value(key, val, redact);
	return 0;
}

typedef struct {
	const char *entry;
	size_t idx;
} EnvRef;

static void entry_key(const char *s, const char **k, size_t *kl) {
	const char *eq = strchr(s, '=');
	*k = s;
	*kl = eq ? (size_t)(eq - s) : 0;
}

static int entry_cmp(const void *pa, const void *pb) {
	const EnvRef *a = pa;
	const EnvRef *b = pb;
	const char *ka, *kb;
	size_t la, lb;
	entry_key(a->entry, &ka, &la);
	entry_key(b->entry, &kb, &lb);
	size_t m = la < lb ? la : lb;
	int c = m ? memcmp(ka, kb, m) : 0;
	if (c)
		return c;
	if (la != lb)
		return la < lb ? -1 : 1;
	return a->idx < b->idx ? -1 : (a->idx > b->idx);
}

void act_env_list(int values, int redact, int sort) {
	char *const *e = env_entries();
	size_t n = 0;
	while (e && e[n])
		n++;
	EnvRef *v = xmalloc((n ? n : 1) * sizeof(*v));
	for (size_t i = 0; i < n; i++)
		v[i] = (EnvRef){e[i], i};
	if (sort)
		qsort(v, n, sizeof(*v), entry_cmp);
	for (size_t i = 0; i < n; i++) {
		const char *s = v[i].entry;
		const char *eq = strchr(s, '=');
		if (!eq)
			continue;
		size_t kl = (size_t)(eq - s);
		if (!valid_keychars(s, kl))
			continue;
		if (!values) {
			printf("%.*s\n", (int)kl, s);
			continue;
		}
		char *kbuf = xmalloc(kl + 1);
		memcpy(kbuf, s, kl);
		kbuf[kl] = '\0';
		const char *shown = eq + 1;
		if (redact && should_mask(kbuf, eq + 1))
			shown = redact_token(kbuf, eq + 1);
		printf("%.*s=", (int)kl, s);
		fputs_display(shown);
		putchar('\n');
		free(kbuf);
	}
	free(v);
}

#ifndef ENVCTL_VERSION
#define ENVCTL_VERSION "unknown"
#endif

void act_env_dump(int sort) {
	display_set_escape(1);
	printf("# envctl %s (redacted)\n", ENVCTL_VERSION);
	act_env_list(1, 1, sort);
}
