#ifndef ENVCTL_REDACT_H
#define ENVCTL_REDACT_H

/* Presentation hygiene: agent + TTY auto-redact; pipes stay raw. */
int want_redact(int flag_redact, int flag_raw);
int should_mask(const char *key, const char *val);
const char *redact_token(const char *key, const char *val);
int is_pem_private(const char *v);
void print_value(const char *key, const char *val, int redact);

#endif
