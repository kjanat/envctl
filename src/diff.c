#define _GNU_SOURCE
#include "diff.h"

#include "fileio.h"
#include "lines.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	FILE *out;
	const Lines *before;
	const Lines *after;
	const char *file;
	int redact;
	int headers;
	int wrote;
	int open;
	size_t of, on, nf, nn;
} Diff;

static int same_line_object(const char *a, const char *b) { return a == b; }

static int ptr_cmp(const void *a, const void *b) {
	uintptr_t x = (uintptr_t) * (char *const *)a;
	uintptr_t y = (uintptr_t) * (char *const *)b;

	if (x < y)
		return -1;
	return x > y;
}

static void mark_present(char *const *hay, size_t hn, char *const *needle, size_t nn,
                         unsigned char *found) {
	char **sorted = xmalloc((hn ? hn : 1) * sizeof(char *));

	if (hn)
		memcpy(sorted, hay, hn * sizeof(char *));
	qsort(sorted, hn, sizeof(char *), ptr_cmp);
	for (size_t i = 0; i < nn; i++)
		found[i] = bsearch(&needle[i], sorted, hn, sizeof(char *), ptr_cmp) != NULL;
	free(sorted);
}

static size_t render_range(FILE *out, const Lines *L, size_t first, size_t n, const char *prefix,
                           int redact) {
	size_t end = first + n, emitted = 0;

	for (size_t k = first; k < end;) {
		size_t span = logical_span(L, k, NULL);
		if (k + span > end)
			span = end - k;
		emitted += render_span(out, L, k, span, prefix, redact);
		k += span;
	}
	return emitted;
}

static void flush_hunk(Diff *d) {
	if (!d->open)
		return;

	if (!d->headers) {
		fprintf(d->out, "--- %s\n", d->file);
		fprintf(d->out, "+++ %s%s\n", d->file, d->redact ? " (redacted)" : "");
		d->headers = 1;
	}

	size_t oe = render_range(NULL, d->before, d->of, d->on, "-", d->redact);
	size_t ne = render_range(NULL, d->after, d->nf, d->nn, "+", d->redact);

	fprintf(d->out, "@@ -%lu,%lu +%lu,%lu @@\n", (unsigned long)(d->of + (oe != 0)),
	        (unsigned long)oe, (unsigned long)(d->nf + (ne != 0)), (unsigned long)ne);
	render_range(d->out, d->before, d->of, d->on, "-", d->redact);
	render_range(d->out, d->after, d->nf, d->nn, "+", d->redact);

	d->open = 0;
	d->wrote = 1;
}

static void open_hunk(Diff *d, size_t i, size_t j) {
	if (d->open)
		return;
	d->open = 1;
	d->of = i;
	d->on = 0;
	d->nf = j;
	d->nn = 0;
}

int emit_diff(FILE *out, const Lines *before, const Lines *after, const char *file, int redact) {
	size_t bn = before->n, an = after->n;
	unsigned char *kept = xmalloc(bn ? bn : 1);
	unsigned char *fresh = xmalloc(an ? an : 1);

	mark_present(after->v, an, before->v, bn, kept);
	mark_present(before->v, bn, after->v, an, fresh);
	for (size_t j = 0; j < an; j++)
		fresh[j] = (unsigned char)!fresh[j];

	Diff d = {out, before, after, file, redact, 0, 0, 0, 0, 0, 0, 0};
	size_t i = 0, j = 0;

	while (i < bn || j < an) {
		if (i < bn && j < an && same_line_object(before->v[i], after->v[j])) {
			flush_hunk(&d);
			i++;
			j++;
			continue;
		}
		if (i < bn && j < an && !kept[i] && fresh[j] && !strcmp(before->v[i], after->v[j])) {
			flush_hunk(&d);
			i++;
			j++;
			continue;
		}

		int adv = 0;
		if (i < bn && !kept[i]) {
			open_hunk(&d, i, j);
			d.on++;
			i++;
			adv = 1;
		}
		if (j < an && fresh[j]) {
			open_hunk(&d, i, j);
			d.nn++;
			j++;
			adv = 1;
		}
		if (!adv) {
			if (i < bn)
				i++;
			else
				j++;
		}
	}
	flush_hunk(&d);

	free(kept);
	free(fresh);
	return d.wrote;
}
