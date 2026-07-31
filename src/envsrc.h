#ifndef ENVCTL_ENVSRC_H
#define ENVCTL_ENVSRC_H

char *const *env_entries(void);
int act_env_get(const char *key, int redact);
void act_env_list(int values, int redact);
void act_env_dump(void);

#endif
