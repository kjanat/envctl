#ifndef ENVCTL_REDACT_H
#define ENVCTL_REDACT_H

#include "cli.h"

#include <stddef.h>

/* Presentation hygiene: agent + TTY auto-redact; pipes stay raw. */
int want_redact(RedactWhen when);
void redact_set_paranoid(int on);
const char *value_body(const char *raw, size_t *len);
int should_mask(const char *key, const char *val);
const char *redact_token(const char *key, const char *val);
const char *redact_token_n(const char *b, size_t bn);
int literal_maskable(const char *key, const char *val);
int should_mask_token(const char *s, size_t n);

typedef struct {
	int pem_open;
	char pem_label[64];
	int putty_phase;
	size_t putty_lines;
	size_t putty_recovery;
	int putty_emit;
	int putty_declared;
	char quote_ch;
	size_t quote_n;
	int quote_backslash;
	char *json_buf;
	size_t json_len;
	size_t json_cap;
	size_t json_lines;
	long json_depth;
	int json_string;
	int json_escape;
	int json_drop;
} ScanState;

void scan_state_init(ScanState *st);
int scan_text_line(const char *in, size_t inlen, const char *eol, size_t eollen, char **out,
                   size_t *outcap, size_t *outlen, ScanState *st);
int scan_text_finish(char **out, size_t *outcap, size_t *outlen, ScanState *st);
void scan_state_free(ScanState *st);
int is_pem_private(const char *v);
void print_value(const char *key, const char *val, int redact);

#endif
