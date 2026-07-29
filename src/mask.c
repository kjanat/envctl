#define _GNU_SOURCE
#include "mask.h"

#include "redact.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

#define MASK_MIN 8
#define MASK_MIN_LITERAL 6

static const char B64STD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char HEXU[] = "0123456789ABCDEF";
static const char HEXL[] = "0123456789abcdef";

static size_t alloc_size(size_t n, size_t mul, size_t add) {
	if (n > ((size_t)-1 - add) / mul)
		die("out of memory");
	return n * mul + add;
}

char *enc_b64(const char *s, size_t n, int urlsafe, int pad) {
	const char *A = urlsafe ? B64URL : B64STD;
	if (n > (size_t)-1 - 2)
		die("out of memory");
	size_t groups = (n + 2) / 3;
	char *o = xmalloc(alloc_size(groups, 4, 1));
	size_t j = 0;

	for (size_t i = 0; i < n; i += 3) {
		unsigned b0 = (unsigned char)s[i];
		unsigned b1 = i + 1 < n ? (unsigned char)s[i + 1] : 0;
		unsigned b2 = i + 2 < n ? (unsigned char)s[i + 2] : 0;

		o[j++] = A[b0 >> 2];
		o[j++] = A[((b0 & 3) << 4) | (b1 >> 4)];
		if (i + 1 < n)
			o[j++] = A[((b1 & 15) << 2) | (b2 >> 6)];
		else if (pad)
			o[j++] = '=';
		if (i + 2 < n)
			o[j++] = A[b2 & 63];
		else if (pad)
			o[j++] = '=';
	}

	o[j] = '\0';
	return o;
}

static int is_unreserved(unsigned char c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
	       c == '.' || c == '_' || c == '~';
}

char *enc_hex(const char *s, size_t n, int upper) {
	const char *tab = upper ? HEXU : HEXL;
	char *o = xmalloc(alloc_size(n, 2, 1));
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		o[i * 2] = tab[c >> 4];
		o[i * 2 + 1] = tab[c & 15];
	}
	o[n * 2] = '\0';
	return o;
}

char *enc_urlenc(const char *s, size_t n) {
	char *o = xmalloc(alloc_size(n, 3, 1));
	size_t j = 0;

	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (is_unreserved(c)) {
			o[j++] = (char)c;
		} else {
			o[j++] = '%';
			o[j++] = HEXU[c >> 4];
			o[j++] = HEXU[c & 15];
		}
	}

	o[j] = '\0';
	return o;
}

char *enc_jsonesc(const char *s, size_t n) {
	char *o = xmalloc(alloc_size(n, 6, 1));
	size_t j = 0;

	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		char esc = 0;

		switch (c) {
		case '"':
			esc = '"';
			break;
		case '\\':
			esc = '\\';
			break;
		case '\n':
			esc = 'n';
			break;
		case '\r':
			esc = 'r';
			break;
		case '\t':
			esc = 't';
			break;
		case '\b':
			esc = 'b';
			break;
		case '\f':
			esc = 'f';
			break;
		default:
			break;
		}

		if (esc) {
			o[j++] = '\\';
			o[j++] = esc;
		} else if (c < 0x20) {
			o[j++] = '\\';
			o[j++] = 'u';
			o[j++] = '0';
			o[j++] = '0';
			o[j++] = HEXL[c >> 4];
			o[j++] = HEXL[c & 15];
		} else {
			o[j++] = (char)c;
		}
	}

	o[j] = '\0';
	return o;
}

void maskset_init(MaskSet *M) {
	M->v = NULL;
	M->n = 0;
	M->cap = 0;
	M->minlen = 0;
	M->maxlen = 0;
	for (int i = 0; i < 256; i++)
		M->bucket[i] = -1;
}

static void add_pat_min(MaskSet *M, const char *p, size_t n, const char *tok, size_t min) {
	if (n < min)
		return;

	for (size_t i = 0; i < M->n; i++) {
		if (M->v[i].len == n && memcmp(M->v[i].pat, p, n) == 0)
			return;
	}

	if (M->n == M->cap) {
		if (M->cap > (size_t)-1 / 2 / sizeof(*M->v))
			die("out of memory");
		M->cap = M->cap ? M->cap * 2 : 32;
		M->v = xrealloc(M->v, M->cap * sizeof(*M->v));
	}

	char *c = xmalloc(n);
	memcpy(c, p, n);
	M->v[M->n].pat = c;
	M->v[M->n].len = n;
	M->v[M->n].tok = tok;
	M->v[M->n].next = -1;
	M->n++;
}

static void add_pat(MaskSet *M, const char *p, size_t n, const char *tok) {
	add_pat_min(M, p, n, tok, MASK_MIN);
}

static void add_b64_phase(MaskSet *M, const char *b, size_t bn, size_t phase, const char *tok) {
	if (bn > (size_t)-1 - phase)
		die("out of memory");
	size_t tn = bn + phase;
	char *tmp = xmalloc(tn);

	for (size_t i = 0; i < phase; i++)
		tmp[i] = 'A';
	memcpy(tmp + phase, b, bn);

	char *e = enc_b64(tmp, tn, 0, 1);
	size_t en = strlen(e);
	size_t lead = phase == 0 ? 0 : (phase == 1 ? 2 : 3);
	size_t whole = (tn / 3) * 4;

	if (en > lead)
		add_pat(M, e + lead, en - lead, tok);
	if (whole > lead && whole < en)
		add_pat(M, e + lead, whole - lead, tok);

	free(e);
	free(tmp);
}

static void add_body(MaskSet *M, const char *b, size_t bn, const char *tok) {
	char *e;

	add_pat_min(M, b, bn, tok, MASK_MIN_LITERAL);

	for (size_t phase = 0; phase <= 2; phase++)
		add_b64_phase(M, b, bn, phase, tok);

	e = enc_b64(b, bn, 1, 0);
	size_t en = strlen(e), whole = (bn / 3) * 4;
	add_pat(M, e, en, tok);
	if (whole && whole < en)
		add_pat(M, e, whole, tok);
	free(e);

	e = enc_urlenc(b, bn);
	add_pat(M, e, strlen(e), tok);
	free(e);

	e = enc_jsonesc(b, bn);
	add_pat(M, e, strlen(e), tok);
	free(e);

	e = enc_hex(b, bn, 0);
	add_pat(M, e, strlen(e), tok);
	free(e);

	e = enc_hex(b, bn, 1);
	add_pat(M, e, strlen(e), tok);
	free(e);
}

static void add_value(MaskSet *M, const char *key, const char *raw) {
	size_t bn;
	const char *b = value_body(raw, &bn);
	const char *tok = redact_token(key, raw);
	add_body(M, b, bn, tok);

	size_t newlines = 0;
	for (size_t i = 0; i < bn; i++) {
		if (b[i] == '\n')
			newlines++;
	}
	if (!newlines)
		return;
	if (bn > (size_t)-1 - newlines)
		die("out of memory");
	char *crlf = xmalloc(bn + newlines);
	size_t j = 0;
	for (size_t i = 0; i < bn; i++) {
		if (b[i] == '\n')
			crlf[j++] = '\r';
		crlf[j++] = b[i];
	}
	add_pat_min(M, crlf, j, tok, MASK_MIN_LITERAL);
	free(crlf);
}

static void add_segments(MaskSet *M, const char *key, const char *raw) {
	size_t bn;
	const char *b = value_body(raw, &bn);
	const char *tok = redact_token(key, raw);

	for (size_t s = 0, i = 0; i <= bn; i++) {
		if (i < bn && b[i] != '\n')
			continue;
		size_t n = i - s;
		if (n) {
			char *seg = xmalloc(n + 1);
			memcpy(seg, b + s, n);
			seg[n] = '\0';
			if (literal_maskable(key, seg))
				add_body(M, seg, n, tok);
			free(seg);
		}
		s = i + 1;
	}
}

void maskset_load_lines(MaskSet *M, const Lines *L) {
	for (size_t i = 0; i < L->n;) {
		size_t span = logical_span(L, i, NULL);
		const char *p = skip_ws(L->v[i]);

		if (*p == '#')
			p = skip_ws(p + 1);
		p = skip_export(p);

		const char *eq = strchr(p, '=');
		size_t kl = eq ? (size_t)(eq - p) : 0;

		if (eq && valid_keychars(p, kl)) {
			char *kbuf = xmalloc(kl + 1);
			memcpy(kbuf, p, kl);
			kbuf[kl] = '\0';
			char *val = join_span(L, i, span);
			if (literal_maskable(kbuf, val)) {
				add_value(M, kbuf, val);
				if (span > 1 && !is_pem_private(val))
					add_segments(M, kbuf, val);
			}
			free(val);
			free(kbuf);
		}

		i += span;
	}
}

void maskset_build(MaskSet *M) {
	for (int i = 0; i < 256; i++)
		M->bucket[i] = -1;
	M->minlen = 0;
	M->maxlen = 0;

	for (size_t i = 0; i < M->n; i++) {
		int *link = &M->bucket[(unsigned char)M->v[i].pat[0]];
		while (*link >= 0 && M->v[*link].len >= M->v[i].len)
			link = &M->v[*link].next;
		M->v[i].next = *link;
		*link = (int)i;
		if (!M->minlen || M->v[i].len < M->minlen)
			M->minlen = M->v[i].len;
		if (M->v[i].len > M->maxlen)
			M->maxlen = M->v[i].len;
	}
}

static const MaskPat *mask_at(const MaskSet *M, const char *in, size_t inlen) {
	if (!M->n || inlen < M->minlen)
		return NULL;
	for (int idx = M->bucket[(unsigned char)in[0]]; idx >= 0; idx = M->v[idx].next) {
		const MaskPat *mp = &M->v[idx];
		if (mp->len <= inlen && memcmp(in, mp->pat, mp->len) == 0)
			return mp;
	}
	return NULL;
}

size_t maskset_apply(const MaskSet *M, const char *in, size_t inlen, char **out, size_t *outcap) {
	size_t len = 0;

	for (size_t p = 0; p < inlen;) {
		const MaskPat *hit = mask_at(M, in + p, inlen - p);

		if (hit) {
			buf_put(out, outcap, &len, hit->tok, strlen(hit->tok));
			p += hit->len;
		} else {
			buf_put(out, outcap, &len, in + p, 1);
			p++;
		}
	}

	buf_need(out, outcap, len + 1);
	(*out)[len] = '\0';
	return len;
}

void maskstream_init(MaskStream *S) {
	S->pending = NULL;
	S->len = 0;
	S->cap = 0;
}

size_t maskstream_apply(const MaskSet *M, MaskStream *S, const char *in, size_t inlen, int final,
                        char **out, size_t *outcap) {
	size_t len = 0;
	if (inlen)
		buf_put(&S->pending, &S->cap, &S->len, in, inlen);

	size_t p = 0;
	while (p < S->len && (final || !M->n || S->len - p >= M->maxlen)) {
		const MaskPat *hit = mask_at(M, S->pending + p, S->len - p);
		if (hit) {
			buf_put(out, outcap, &len, hit->tok, strlen(hit->tok));
			p += hit->len;
		} else {
			buf_put(out, outcap, &len, S->pending + p, 1);
			p++;
		}
	}

	if (p) {
		S->len -= p;
		memmove(S->pending, S->pending + p, S->len);
		if (S->pending)
			S->pending[S->len] = '\0';
	}
	buf_need(out, outcap, len + 1);
	(*out)[len] = '\0';
	return len;
}

void maskstream_free(MaskStream *S) {
	free(S->pending);
	maskstream_init(S);
}

void maskset_free(MaskSet *M) {
	for (size_t i = 0; i < M->n; i++)
		free(M->v[i].pat);
	free(M->v);
	maskset_init(M);
}
