#include "entropy.h"

uint32_t log2_q16(uint32_t x) {
	if (x == 0)
		return 0;
	int hi = 31;
	while (!(x & (1u << hi)))
		hi--;
	uint64_t y = ((uint64_t)x << 16) >> hi;
	uint32_t frac = 0;
	for (int i = 1; i <= 16; i++) {
		y = (y * y) >> 16;
		if (y >= (2u << 16)) {
			y >>= 1;
			frac |= 1u << (16 - i);
		}
	}
	return ((uint32_t)hi << 16) | frac;
}

uint32_t shannon_q16(const char *s, size_t n) {
	uint32_t c[256] = {0};
	if (n == 0)
		return 0;
	if (n > ENT_MAX_SCAN)
		n = ENT_MAX_SCAN;
	for (size_t i = 0; i < n; i++)
		c[(unsigned char)s[i]]++;
	uint64_t acc = (uint64_t)n * log2_q16((uint32_t)n);
	for (int i = 0; i < 256; i++)
		if (c[i])
			acc -= (uint64_t)c[i] * log2_q16(c[i]);
	return (uint32_t)(acc / n);
}
