#ifndef ENVCTL_LINES_H
#define ENVCTL_LINES_H

#include <stddef.h>
#include <stdio.h>

#define SPAN_MAX 512

typedef struct {
	char **v;
	size_t n;
	size_t cap;
} Lines;

typedef struct {
	char *buf;
	size_t cap;
	size_t len;
	int eol;
	int crlf;
} StreamLine;

void lpush(Lines *L, char *s);
Lines read_file(const char *file);
void lines_free(Lines *L);
void lines_free_borrowing(Lines *L, const Lines *borrowed);

int read_stream_line(FILE *f, StreamLine *sl);
void streamline_free(StreamLine *sl);

size_t logical_span(const Lines *L, size_t i, int *unterminated);
char *join_span(const Lines *L, size_t i, size_t span);

const char *skip_ws(const char *s);
const char *skip_export(const char *s);
int key_at(const char *s, const char *key, size_t kl);
int is_active_def(const char *line, const char *key, size_t kl);
int is_comment_def(const char *line, const char *key, size_t kl);
void find_defs(const Lines *L, const char *key, size_t kl, long *active, long *commented);

int valid_keychars(const char *k, size_t kl);

char *mk_kv(const char *key, const char *val);
char *mk_comment(const char *line);
char *uncomment(const char *line);

Lines act_set(Lines *L, const char *key, size_t kl, const char *val);
Lines act_disable(Lines *L, const char *key, size_t kl);
Lines act_enable(Lines *L, const char *key, size_t kl);
Lines act_delete(Lines *L, const char *key, size_t kl);
int act_get(Lines *L, const char *key, size_t kl, int redact);
void act_list(Lines *L, int values, int all, int redact, int sort);

#endif
