#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "config.h"

void sk_hmac(const unsigned char *const input, size_t in_len, unsigned char *output, const unsigned char *const hmac_key);

struct sk_key_t {
    unsigned char t3f_enc_key[T3F_KEY_LEN];
    unsigned char t3f_tweak[T3F_TWEAK_LEN];
    unsigned char hmac_key[SKEIN_HMAC_KEY_LEN];
    unsigned char ctr_key[crypto_stream_xchacha20_KEYBYTES];
    unsigned char ctr_nonce[crypto_stream_xchacha20_NONCEBYTES];
};
typedef struct sk_key_t sk_key_t;

void sk_encrypt(const unsigned char *const input, size_t in_len,
                unsigned char *output, sk_key_t *keys);
void sk_decrypt(const unsigned char *const input, size_t in_len,
                unsigned char *output, sk_key_t *keys);

#endif