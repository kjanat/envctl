#ifndef ENVCTL_LINES_H
#define ENVCTL_LINES_H

#include <stddef.h>

typedef struct {
	char **v;
	size_t n;
	size_t cap;
} Lines;

void lpush(Lines *L, char *s);
Lines read_file(const char *file);

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
void act_list(Lines *L, int values, int all, int redact);

#endif
