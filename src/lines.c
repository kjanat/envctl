#define _GNU_SOURCE
#include "lines.h"

#include "redact.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void lpush(Lines *L, char *s) {
	if (L->n == L->cap) {
		L->cap = L->cap ? L->cap * 2 : 64;
		L->v = xrealloc(L->v, L->cap * sizeof(char *));
	}
	L->v[L->n++] = s;
}

static void push_char(char **buf, size_t *cap, size_t *len, char c) {
	if (*len + 1 > *cap) {
		*cap = *cap ? *cap * 2 : 128;
		*buf = xrealloc(*buf, *cap);
	}
	(*buf)[(*len)++] = c;
}

/*
 * Portable line reader (no getline): splits on '\n', strips a trailing '\r'
 * so CRLF files read cleanly on any platform.
 */
Lines read_file(const char *file) {
	FILE *f = fopen(file, "rb");
	if (!f)
		die("cannot open file: %s", file);

	Lines L = {0};
	char *buf = NULL;
	size_t cap = 0, len = 0;
	int c;

	while ((c = fgetc(f)) != EOF) {
		if (c == '\n') {
			if (len && buf[len - 1] == '\r')
				len--;
			push_char(&buf, &cap, &len, '\0');
			lpush(&L, xstrdup(buf));
			len = 0;
		} else {
			push_char(&buf, &cap, &len, (char)c);
		}
	}

	if (len > 0) {
		if (buf[len - 1] == '\r')
			len--;
		push_char(&buf, &cap, &len, '\0');
		lpush(&L, xstrdup(buf));
	}

	free(buf);
	fclose(f);
	return L;
}

const char *skip_ws(const char *s) {
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

const char *skip_export(const char *s) {
	if (!strncmp(s, "export", 6) && (s[6] == ' ' || s[6] == '\t'))
		s = skip_ws(s + 6);
	return s;
}

int key_at(const char *s, const char *key, size_t kl) {
	return strncmp(s, key, kl) == 0 && s[kl] == '=';
}

int is_active_def(const char *line, const char *key, size_t kl) {
	if (*skip_ws(line) == '#')
		return 0;
	return key_at(skip_export(line), key, kl);
}

int is_comment_def(const char *line, const char *key, size_t kl) {
	const char *p = skip_ws(line);
	if (*p != '#')
		return 0;
	p = skip_ws(p + 1);
	return key_at(skip_export(p), key, kl);
}

void find_defs(const Lines *L, const char *key, size_t kl, long *active, long *commented) {
	*active = -1;
	*commented = -1;
	for (size_t i = 0; i < L->n; i++) {
		if (*active < 0 && is_active_def(L->v[i], key, kl))
			*active = (long)i;
		if (*commented < 0 && is_comment_def(L->v[i], key, kl))
			*commented = (long)i;
		if (*active >= 0 && *commented >= 0)
			break;
	}
}

int valid_keychars(const char *k, size_t kl) {
	if (kl < 1)
		return 0;
	if (!(isalpha((unsigned char)k[0]) || k[0] == '_'))
		return 0;
	for (size_t i = 1; i < kl; i++) {
		if (!(isalnum((unsigned char)k[i]) || k[i] == '_'))
			return 0;
	}
	return 1;
}

char *mk_kv(const char *key, const char *val) {
	size_t n = strlen(key) + 1 + strlen(val) + 1;
	char *s = xmalloc(n);
	snprintf(s, n, "%s=%s", key, val);
	return s;
}

char *mk_comment(const char *line) {
	size_t n = strlen(line) + 3;
	char *s = xmalloc(n);
	snprintf(s, n, "# %s", line);
	return s;
}

char *uncomment(const char *line) {
	const char *p = skip_ws(line);
	return xstrdup(skip_ws(p + 1));
}

Lines act_set(Lines *L, const char *key, size_t kl, const char *val) {
	long first_active, first_comment;
	find_defs(L, key, kl, &first_active, &first_comment);

	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];

		if (first_active >= 0) {
			if ((long)i == first_active)
				line = mk_kv(key, val);
			else if (is_active_def(L->v[i], key, kl))
				line = mk_comment(L->v[i]);
		} else if (first_comment >= 0 && (long)i == first_comment) {
			line = mk_kv(key, val);
		}

		lpush(&out, line);
	}

	if (first_active < 0 && first_comment < 0)
		lpush(&out, mk_kv(key, val));

	return out;
}

Lines act_disable(Lines *L, const char *key, size_t kl) {
	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];
		if (is_active_def(line, key, kl))
			line = mk_comment(line);
		lpush(&out, line);
	}
	return out;
}

Lines act_enable(Lines *L, const char *key, size_t kl) {
	long first_active, first_comment;
	find_defs(L, key, kl, &first_active, &first_comment);

	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		char *line = L->v[i];
		if (first_active < 0 && first_comment >= 0 && (long)i == first_comment)
			line = uncomment(line);
		lpush(&out, line);
	}
	return out;
}

Lines act_delete(Lines *L, const char *key, size_t kl) {
	Lines out = {0};
	for (size_t i = 0; i < L->n; i++) {
		if (!is_active_def(L->v[i], key, kl) && !is_comment_def(L->v[i], key, kl))
			lpush(&out, L->v[i]);
	}
	return out;
}

int act_get(Lines *L, const char *key, size_t kl, int redact) {
	for (size_t i = 0; i < L->n; i++) {
		if (is_active_def(L->v[i], key, kl)) {
			const char *s = skip_export(L->v[i]);
			print_value(key, s + kl + 1, redact);
			return 0;
		}
	}
	return 1;
}

void act_list(Lines *L, int values, int all, int redact) {
	for (size_t i = 0; i < L->n; i++) {
		const char *orig = L->v[i];
		const char *s;
		int commented = 0;
		const char *p = skip_ws(orig);

		if (*p == '#') {
			if (!all)
				continue;
			commented = 1;
			s = skip_ws(p + 1);
		} else {
			s = orig;
		}

		s = skip_export(s);
		const char *eq = strchr(s, '=');
		if (!eq)
			continue;

		size_t kl = (size_t)(eq - s);
		if (!valid_keychars(s, kl))
			continue;

		const char *tag = commented ? " (disabled)" : "";
		if (!values) {
			printf("%.*s%s\n", (int)kl, s, tag);
			continue;
		}

		const char *val = eq + 1;
		char kbuf[256];
		size_t kn = kl < sizeof(kbuf) - 1 ? kl : sizeof(kbuf) - 1;
		memcpy(kbuf, s, kn);
		kbuf[kn] = '\0';

		if (redact && should_mask(kbuf, val))
			printf("%.*s=%s%s\n", (int)kl, s, redact_token(kbuf, val), tag);
		else
			printf("%.*s=%s%s\n", (int)kl, s, val, tag);
	}
}
