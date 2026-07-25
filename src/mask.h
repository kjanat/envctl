#ifndef ENVCTL_MASK_H
#define ENVCTL_MASK_H

#include "lines.h"

#include <stddef.h>

typedef struct {
	char *pat;
	size_t len;
	const char *tok;
	int next;
} MaskPat;

typedef struct {
	MaskPat *v;
	size_t n;
	size_t cap;
	int bucket[256];
	size_t minlen;
} MaskSet;

void maskset_init(MaskSet *M);
void maskset_load_lines(MaskSet *M, const Lines *L);
void maskset_build(MaskSet *M);
size_t maskset_apply(const MaskSet *M, const char *in, size_t inlen, char **out, size_t *outcap);
void maskset_free(MaskSet *M);

char *enc_b64(const char *s, size_t n, int urlsafe, int pad);
char *enc_hex(const char *s, size_t n, int upper);
char *enc_urlenc(const char *s, size_t n);
char *enc_jsonesc(const char *s, size_t n);

#endif
