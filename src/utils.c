#include "stb_lib.h"
#include "utils.h"

void *sk_sodium_malloc(size_t s) {
    assert(s > 0);
    void *buf = sodium_malloc(s);
    if (buf == NULL) {
        stb_fatal("cannot allocate memory.");
    }
    return buf;
}

void *sk_malloc(size_t s) {
    assert(s > 0);
    void *buf = malloc(s);
    if (buf == NULL) {
        stb_fatal("cannot allocate memory.");
    }
    return buf;
}

void sk_zero_free(unsigned char *buf, size_t buf_len) {
    assert(buf_len > 0);
    assert(buf != NULL);
    sodium_memzero(buf, buf_len);
    sodium_free(buf);
}

FILE *sk_fopen(const char *path, const char *flags) {
    FILE *f = stb__fopen(path, flags);
    if (f == NULL) {
        stb_fatal("cannot open file.");
    }
    return f;
}