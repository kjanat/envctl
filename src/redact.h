#ifndef ENVCTL_REDACT_H
#define ENVCTL_REDACT_H

#include <stddef.h>

/* Presentation hygiene: agent + TTY auto-redact; pipes stay raw. */
int want_redact(int flag_redact, int flag_raw);
const char *value_body(const char *raw, size_t *len);
int should_mask(const char *key, const char *val);
const char *redact_token(const char *key, const char *val);
const char *redact_token_n(const char *b, size_t bn);
int literal_maskable(const char *key, const char *val);
int should_mask_token(const char *s, size_t n);
int scan_text_line(const char *in, size_t inlen, char **out, size_t *outcap, int *pem_open,
                   char *pem_label, size_t pem_label_cap);
int is_pem_private(const char *v);
void print_value(const char *key, const char *val, int redact);

#endif
