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
		if (c == '\0')
			die("binary data in %s", file);
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
	return strncmp(s, key, kl) == 0 && *skip_ws(s + kl) == '=';
}

int is_active_def(const char *line, const char *key, size_t kl) {
	Assignment a;
	return parse_assignment(line, &a) && !a.commented && a.key_len == kl && !memcmp(a.key, key, kl);
}

int is_comment_def(const char *line, const char *key, size_t kl) {
	Assignment a;
	return parse_assignment(line, &a) && a.commented && a.key_len == kl && !memcmp(a.key, key, kl);
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
	if (!strncmp(line, "\xef\xbb\xbf", 3))
		line += 3;
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

int parse_assignment(const char *line, Assignment *a) {
	const char *p = head_body(line, &a->commented);
	const char *eq = strchr(p, '=');
	if (!eq)
		return 0;
	const char *end = eq;
	while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	if (!valid_keychars(p, (size_t)(end - p)))
		return 0;
	a->key = p;
	a->key_len = (size_t)(end - p);
	a->value = eq + 1;
	return 1;
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

static const char *quote_end(const char *s, char qc) {
	for (const char *p = s; *p; p++) {
		if (*p == '\\' && p[1]) {
			p++;
			continue;
		}
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
	Assignment a;
	return parse_assignment(line, &a) ? a.value : line;
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
	if (!quote_open && pem_open_at(v, label, sizeof(label)))
		pem_open = 1;

	if (quote_open && quote_end(v, qc))
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
		if (quote_open) {
			const char *end = quote_end(c, qc);
			if (end && (*skip_ws(end + 1) == '\0' || *skip_ws(end + 1) == '#'))
				quote_open = 0;
		}
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
	Assignment a;
	int commented = parse_assignment(L->v[i], &a) && a.commented;
	size_t n = strlen(head) + 1;
	for (size_t j = 1; j < span && i + j < L->n; j++)
		n += strlen(L->v[i + j]) + 1;

	char *s = xmalloc(n);
	size_t o = strlen(head);
	memcpy(s, head, o);
	for (size_t j = 1; j < span && i + j < L->n; j++) {
		const char *line = L->v[i + j];
		if (commented) {
			line = skip_ws(line);
			if (*line == '#') {
				line++;
				if (*line == ' ')
					line++;
			}
		}
		size_t ln = strlen(line);
		s[o++] = '\n';
		memcpy(s + o, line, ln);
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

/* Decode file syntax without interpolation or shell evaluation. Unknown
 * escapes retain their backslash; single/backtick quotes only escape their
 * delimiter and a backslash. NULL denotes malformed quoted input. */
char *decode_value(const char *raw) {
	const char *p = skip_ws(raw);
	char qc = *p;
	int quoted = qc == '"' || qc == '\'' || qc == '`';
	const char *end;
	if (quoted) {
		end = quote_end(++p, qc);
		if (!end)
			return NULL;
		const char *tail = skip_ws(end + 1);
		if (*tail && *tail != '#')
			return NULL;
	} else {
		end = p;
		while (*end && !(*end == '#' && end > raw && (end[-1] == ' ' || end[-1] == '\t')))
			end++;
		while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
	}
	char *out = xmalloc((size_t)(end - p) + 1);
	size_t n = 0;
	while (p < end) {
		char c = *p++;
		if (quoted && c == '\\' && p < end) {
			if (*p == qc || *p == '\\') {
				c = *p++;
			} else if (qc == '"') {
				const char *escapes = "abfnrtv'";
				const char *decoded = "\a\b\f\n\r\t\v'";
				const char *e = strchr(escapes, *p);
				if (e) {
					c = decoded[e - escapes];
					p++;
				}
			}
		}
		out[n++] = c;
	}
	out[n] = '\0';
	return out;
}

static char *encode_value(const char *val) {
	char *decoded = decode_value(val);
	int quoted = !decoded || strcmp(decoded, val);
	free(decoded);
	char label[PEM_LABEL_MAX];
	if (pem_open_at(val, label, sizeof(label)))
		quoted = 1;
	for (const unsigned char *p = (const unsigned char *)val; *p; p++) {
		if (*p < 0x20 || *p == 0x7f)
			quoted = 1;
	}
	if (!quoted)
		return xstrdup(val);
	char *out = NULL;
	size_t cap = 0, n = 0;
	buf_put(&out, &cap, &n, "\"", 1);
	for (const char *p = val; *p; p++) {
		const char *special = "\a\b\f\n\r\t\v\\\"";
		const char *escaped = "abfnrtv\\\"";
		const char *e = strchr(special, *p);
		if (e) {
			buf_put(&out, &cap, &n, "\\", 1);
			buf_put(&out, &cap, &n, escaped + (e - special), 1);
		} else {
			buf_put(&out, &cap, &n, p, 1);
		}
	}
	buf_put(&out, &cap, &n, "\"", 1);
	return out;
}

char *mk_kv(const char *key, const char *val) {
	char *encoded = encode_value(val);
	size_t n = strlen(key) + 1 + strlen(encoded) + 1;
	char *s = xmalloc(n);
	snprintf(s, n, "%s=%s", key, encoded);
	free(encoded);
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
	p++;
	if (*p == ' ')
		p++;
	return xstrdup(p);
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
		int unterm = 0;
		size_t span = logical_span(L, i, &unterm);
		if (is_active_def(L->v[i], key, kl)) {
			require_terminated(unterm, key);
			char *val = join_span(L, i, span);
			char *decoded = decode_value(val);
			if (!decoded)
				die("invalid quoted value for %s", key);
			print_value(key, decoded, redact);
			free(decoded);
			free(val);
			return 0;
		}
		i += span;
	}
	return 1;
}

static void list_span(const Lines *L, size_t i, size_t span, int values, int all, int redact) {
	Assignment a;
	if (!parse_assignment(L->v[i], &a) || (a.commented && !all))
		return;
	const char *s = a.key;
	size_t kl = a.key_len;
	const char *tag = a.commented ? " (disabled)" : "";
	if (!values) {
		printf("%.*s%s\n", (int)kl, s, tag);
		return;
	}

	char *kbuf = xmalloc(kl + 1);
	memcpy(kbuf, s, kl);
	kbuf[kl] = '\0';

	char *joined = join_span(L, i, span);
	char *decoded = redact ? decode_value(joined) : NULL;
	const char *masked = decoded && should_mask(kbuf, decoded) ? decoded : joined;
	const char *shown = a.value;
	if (redact && should_mask(kbuf, masked))
		shown = redact_token(kbuf, masked);
	printf("%.*s=", (int)kl, s);
	fputs_display(shown);
	printf("%s\n", tag);
	free(decoded);
	free(joined);
	free(kbuf);
}

typedef struct {
	const char *line;
	size_t idx;
	size_t span;
} SpanRef;

static void sort_key(const char *line, const char **k, size_t *kl) {
	Assignment a;
	int valid = parse_assignment(line, &a);
	*k = valid ? a.key : line;
	*kl = valid ? a.key_len : 0;
}

static int span_cmp(const void *pa, const void *pb) {
	const SpanRef *a = pa;
	const SpanRef *b = pb;
	const char *ka, *kb;
	size_t la, lb;
	sort_key(a->line, &ka, &la);
	sort_key(b->line, &kb, &lb);
	size_t m = la < lb ? la : lb;
	int c = m ? memcmp(ka, kb, m) : 0;
	if (c)
		return c;
	if (la != lb)
		return la < lb ? -1 : 1;
	return a->idx < b->idx ? -1 : (a->idx > b->idx);
}

void act_list(Lines *L, int values, int all, int redact, int sort) {
	size_t nspans = 0;
	SpanRef *refs = sort ? xmalloc((L->n ? L->n : 1) * sizeof(*refs)) : NULL;
	for (size_t i = 0; i < L->n;) {
		size_t span = logical_span(L, i, NULL);
		if (sort)
			refs[nspans++] = (SpanRef){L->v[i], i, span};
		else
			list_span(L, i, span, values, all, redact);
		i += span;
	}
	if (sort) {
		qsort(refs, nspans, sizeof(*refs), span_cmp);
		for (size_t j = 0; j < nspans; j++)
			list_span(L, refs[j].idx, refs[j].span, values, all, redact);
		free(refs);
	}
}
