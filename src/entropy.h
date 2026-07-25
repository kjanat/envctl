#ifndef ENVCTL_ENTROPY_H
#define ENVCTL_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#define ENT_MAX_SCAN 4096u

uint32_t log2_q16(uint32_t x);
uint32_t shannon_q16(const char *s, size_t n);

#endif
