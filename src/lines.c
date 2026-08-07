#define _GNU_SOURCE
#include "lines.h"

#include "redact.h"
#include "util.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PEM_LABEL_MAX 64

void lpush(Lines *L, char *s) {
	if (L->n == L->cap) {
		L->cap = L->cap ? L->cap * 2 : 64;
		L->v = xrealloc(L->v, L->cap * sizeof(char *));
	}
	L->v[L->n++] = s;
}

void lines_free(Lines *L) {
	for (size_t i = 0; i < L->n; i++)
		free(L->v[i]);
	free(L->v);
	*L = (Lines){0};
}

static int line_ptr_cmp(const void *a, const void *b) {
	uintptr_t x = (uintptr_t)*(char *const *)a;
	uintptr_t y = (uintptr_t)*(char *const *)b;
	if (x < y)
		return -1;
	return x > y;
}

void lines_free_borrowing(Lines *L, const Lines *borrowed) {
	if (borrowed->n > SIZE_MAX / sizeof(char *))
		die("out of memory");
	char **shared = xmalloc((borrowed->n ? borrowed->n : 1) * sizeof(char *));
	if (borrowed->n) {
		memcpy(shared, borrowed->v, borrowed->n * sizeof(char *));
		qsort(shared, borrowed->n, sizeof(char *), line_ptr_cmp);
	}
	for (size_t i = 0; i < L->n; i++) {
		if (!bsearch(&L->v[i], shared, borrowed->n, sizeof(char *), line_ptr_cmp))
			free(L->v[i]);
	}
	free(shared);
	free(L->v);
	*L = (Lines){0};
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

int read_stream_line(FILE *f, StreamLine *sl) {
	int c;

	sl->len = 0;
	sl->eol = 0;
	sl->crlf = 0;

	while ((c = fgetc(f)) != EOF) {
		if (c == '\n') {
			sl->eol = 1;
			if (sl->len && sl->buf[sl->len - 1] == '\r') {
				sl->len--;
				sl->crlf = 1;
			}
			break;
		}
		push_char(&sl->buf, &sl->cap, &sl->len, (char)c);
	}

	if (ferror(f))
		die("read error on input");

	if (!sl->eol && sl->len == 0)
		return 0;

	push_char(&sl->buf, &sl->cap, &sl->len, '\0');
	sl->len--;
	return 1;
}

void streamline_free(StreamLine *sl) {
	free(sl->buf);
	sl->buf = NULL;
	sl->cap = 0;
	sl->len = 0;
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
	const char *p = skip_ws(line);
	if (*p == '#')
		return 0;
	return key_at(skip_export(p), key, kl);
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
	for (size_t i = 0; i < L->n;) {
		if (*active < 0 && is_active_def(L->v[i], key, kl))
			*active = (long)i;
		if (*commented < 0 && is_comment_def(L->v[i], key, kl))
			*commented = (long)i;
		if (*active >= 0 && *commented >= 0)
			break;
		i += logical_span(L, i, NULL);
	}
}

static const char *head_body(const char *line, int *commented) {
	const char *p = skip_ws(line);
	if (commented)
		*commented = 0;
	if (*p == '#') {
		if (commented)
			*commented = 1;
		p = skip_ws(p + 1);
	}
	return skip_export(p);
}

static int pem_open_at(const char *s, char *label, size_t cap) {
	static const char beg[] = "-----BEGIN ";
	if (strncmp(s, beg, sizeof(beg) - 1) != 0)
		return 0;
	const char *p = s + sizeof(beg) - 1;
	const char *e = strstr(p, "-----");
	if (!e || e == p || (size_t)(e - p) >= cap)
		return 0;
	memcpy(label, p, (size_t)(e - p));
	label[(size_t)(e - p)] = '\0';
	return 1;
}

static int pem_close_at(const char *s, const char *label) {
	static const char pre[] = "-----END ";
	char end[PEM_LABEL_MAX + sizeof(pre) + 8];
	size_t n = sizeof(pre) - 1;
	size_t ln = strlen(label);
	memcpy(end, pre, n);
	memcpy(end + n, label, ln);
	n += ln;
	memcpy(end + n, "-----", 5);
	end[n + 5] = '\0';
	return strstr(s, end) != NULL;
}

static const char *quote_close_at(const char *s, char qc) {
	for (const char *p = s; *p; p++) {
		if (qc == '"' && *p == '\\' && p[1]) {
			p++;
			continue;
		}
		if (*p != qc)
			continue;
		const char *q = skip_ws(p + 1);
		if (*q == '\0' || *q == '#')
			return p;
	}
	return NULL;
}

static const char *quote_any_at(const char *s, char qc) {
	for (const char *p = s; *p; p++) {
		if (qc == '"' && *p == '\\' && p[1]) {
			p++;
			continue;
		}
		if (*p == qc)
			return p;
	}
	for (const char *p = s; *p; p++) {
		if (*p == qc)
			return p;
	}
	return NULL;
}

static int lenient_head(const char *p, const char *eq) {
	const char *e = eq;
	while (e > p && (e[-1] == ' ' || e[-1] == '\t'))
		e--;
	if (e == p)
		return 0;
	for (const char *q = p; q < e; q++) {
		if (*q == ' ' || *q == '\t')
			return 0;
	}
	return 1;
}

static const char *span_value_start(const char *line) {
	const char *p = head_body(line, NULL);
	const char *eq = strchr(p, '=');
	if (eq && valid_keychars(p, (size_t)(eq - p)))
		return eq + 1;
	return line;
}

size_t logical_span(const Lines *L, size_t i, int *unterminated) {
	if (unterminated)
		*unterminated = 0;
	if (i >= L->n)
		return 1;

	int commented = 0;
	const char *p = head_body(L->v[i], &commented);
	const char *eq = strchr(p, '=');
	const char *v;
	char label[PEM_LABEL_MAX];

	if (eq && lenient_head(p, eq))
		v = skip_ws(eq + 1);
	else if (pem_open_at(p, label, sizeof(label)))
		v = p;
	else
		return 1;

	char qc = 0;
	int quote_open = 0, pem_open = 0;

	if (*v == '"' || *v == '\'' || *v == '`') {
		qc = *v;
		quote_open = 1;
		v++;
	}
	if (pem_open_at(v, label, sizeof(label)))
		pem_open = 1;

	if (quote_open && quote_any_at(v, qc))
		quote_open = 0;
	if (pem_open && pem_close_at(v, label))
		pem_open = 0;
	if (!quote_open && !pem_open)
		return 1;

	size_t span = 1;
	while (i + span < L->n && span < SPAN_MAX) {
		const char *c = L->v[i + span];
		if (commented) {
			c = skip_ws(c);
			if (*c != '#')
				break;
			c = skip_ws(c + 1);
		}
		span++;
		if (quote_open && quote_close_at(c, qc))
			quote_open = 0;
		if (pem_open && pem_close_at(c, label))
			pem_open = 0;
		if (!quote_open && !pem_open)
			return span;
	}

	if (unterminated)
		*unterminated = 1;
	return 1;
}

char *join_span(const Lines *L, size_t i, size_t span) {
	const char *head = span_value_start(L->v[i]);
	size_t n = strlen(head) + 1;
	for (size_t j = 1; j < span && i + j < L->n; j++)
		n += strlen(L->v[i + j]) + 1;

	char *s = xmalloc(n);
	size_t o = strlen(head);
	memcpy(s, head, o);
	for (size_t j = 1; j < span && i + j < L->n; j++) {
		size_t ln = strlen(L->v[i + j]);
		s[o++] = '\n';
		memcpy(s + o, L->v[i + j], ln);
		o += ln;
	}
	s[o] = '\0';
	return s;
}

static void require_terminated(int unterminated, const char *key) {
	if (unterminated)
		die("unterminated value for %s", key);
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
	for (size_t i = 0; i < L->n;) {
		int unterm = 0;
		size_t span = logical_span(L, i, &unterm);

		if (first_active >= 0 && (long)i == first_active) {
			require_terminated(unterm, key);
			lpush(&out, mk_kv(key, val));
		} else if (first_active >= 0 && is_active_def(L->v[i], key, kl)) {
			require_terminated(unterm, key);
			for (size_t j = 0; j < span; j++)
				lpush(&out, mk_comment(L->v[i + j]));
		} else if (first_active < 0 && first_comment >= 0 && (long)i == first_comment) {
			require_terminated(unterm, key);
			lpush(&out, mk_kv(key, val));
		} else {
			for (size_t j = 0; j < span; j++)
				lpush(&out, L->v[i + j]);
		}

		i += span;
	}

	if (first_active < 0 && first_comment < 0)
		lpush(&out, mk_kv(key, val));

	return out;
}

Lines act_disable(Lines *L, const char *key, size_t kl) {
	Lines out = {0};
	for (size_t i = 0; i < L->n;) {
		int unterm = 0;
		size_t span = logical_span(L, i, &unterm);

		if (is_active_def(L->v[i], key, kl)) {
			require_terminated(unterm, key);
			for (size_t j = 0; j < span; j++)
				lpush(&out, mk_comment(L->v[i + j]));
		} else {
			for (size_t j = 0; j < span; j++)
				lpush(&out, L->v[i + j]);
		}

		i += span;
	}
	return out;
}

Lines act_enable(Lines *L, const char *key, size_t kl) {
	long first_active, first_comment;
	find_defs(L, key, kl, &first_active, &first_comment);

	Lines out = {0};
	for (size_t i = 0; i < L->n;) {
		int unterm = 0;
		size_t span = logical_span(L, i, &unterm);

		if (first_active < 0 && first_comment >= 0 && (long)i == first_comment) {
			require_terminated(unterm, key);
			for (size_t j = 0; j < span; j++)
				lpush(&out, uncomment(L->v[i + j]));
		} else {
			for (size_t j = 0; j < span; j++)
				lpush(&out, L->v[i + j]);
		}

		i += span;
	}
	return out;
}

Lines act_delete(Lines *L, const char *key, size_t kl) {
	Lines out = {0};
	for (size_t i = 0; i < L->n;) {
		int unterm = 0;
		size_t span = logical_span(L, i, &unterm);

		if (is_active_def(L->v[i], key, kl) || is_comment_def(L->v[i], key, kl))
			require_terminated(unterm, key);
		else
			for (size_t j = 0; j < span; j++)
				lpush(&out, L->v[i + j]);

		i += span;
	}
	return out;
}

int act_get(Lines *L, const char *key, size_t kl, int redact) {
	for (size_t i = 0; i < L->n;) {
		size_t span = logical_span(L, i, NULL);
		if (is_active_def(L->v[i], key, kl)) {
			char *val = join_span(L, i, span);
			print_value(key, val, redact);
			free(val);
			return 0;
		}
		i += span;
	}
	return 1;
}

static void list_span(const Lines *L, size_t i, size_t span, int values, int all, int redact) {
	const char *orig = L->v[i];
	const char *s;
	int commented = 0;
	const char *p = skip_ws(orig);

	if (*p == '#') {
		if (!all)
			return;
		commented = 1;
		s = skip_ws(p + 1);
	} else {
		s = p;
	}

	s = skip_export(s);
	const char *eq = strchr(s, '=');
	if (!eq)
		return;

	size_t kl = (size_t)(eq - s);
	if (!valid_keychars(s, kl))
		return;

	const char *tag = commented ? " (disabled)" : "";
	if (!values) {
		printf("%.*s%s\n", (int)kl, s, tag);
		return;
	}

	char *kbuf = xmalloc(kl + 1);
	memcpy(kbuf, s, kl);
	kbuf[kl] = '\0';

	char *joined = join_span(L, i, span);
	const char *shown = eq + 1;
	if (redact && should_mask(kbuf, joined))
		shown = redact_token(kbuf, joined);
	printf("%.*s=", (int)kl, s);
	fputs_display(shown);
	printf("%s\n", tag);
	free(joined);
	free(kbuf);
}

void act_list(Lines *L, int values, int all, int redact) {
	for (size_t i = 0; i < L->n;) {
		size_t span = logical_span(L, i, NULL);
		list_span(L, i, span, values, all, redact);
		i += span;
	}
}
