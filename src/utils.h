#ifndef __UTILS_H__
#define __UTILS_H__

#include "config.h"

void *sk_sodium_malloc(size_t s);
void *sk_malloc(size_t s);
FILE *sk_fopen(const char *path, const char *flags);
void sk_zero_free(unsigned char *buf, size_t buf_len);

#endif