#include "crypto.h"
#include "skein3fish/skeinApi.h"
#include "skein3fish/threefishApi.h"
#include "stb_lib.h"

void sk_hmac(const unsigned char *const input, size_t in_len,
             unsigned char *output, const unsigned char *const hmac_key) {
    assert(input != NULL);
    assert(in_len > 0);
    assert(output != NULL);
    assert(hmac_key != NULL);

    SkeinCtx_t *skein_x = (SkeinCtx_t *)sk_malloc(sizeof(SkeinCtx_t));

    int rc = skeinCtxPrepare(skein_x, Skein512);
    if (rc != SKEIN_SUCCESS) {
        stb_fatal("cannot generate Skein HMAC.");
    }
    rc = skeinMacInit(skein_x, hmac_key, SKEIN_HMAC_KEY_LEN, Skein512);
    if (rc != SKEIN_SUCCESS) {
        stb_fatal("cannot generate Skein HMAC.");
    }
    rc = skeinUpdate(skein_x, input, in_len);
    if (rc != SKEIN_SUCCESS) {
        stb_fatal("cannot generate Skein HMAC.");
    }
    rc = skeinFinal(skein_x, output);
    if (rc != SKEIN_SUCCESS) {
        stb_fatal("cannot generate Skein HMAC.");
    }
    free(skein_x);
}

void sk_encrypt(const unsigned char *const input, size_t in_len,
                unsigned char *output, sk_key_t *keys) {
    assert(input != NULL);
    assert(in_len > 0);
    assert(output != NULL);
    assert(keys != NULL);

    ThreefishKey_t *t3f_x = (ThreefishKey_t *)sk_malloc(sizeof(ThreefishKey_t));
    threefishSetKey(t3f_x, Threefish1024, (uint64_t *)keys->t3f_enc_key, (uint64_t *)keys->t3f_tweak);

    unsigned char *t3f_buf = (unsigned char *)sk_malloc(T3F_BLOCK_LEN);
    size_t num_blocks = in_len/T3F_BLOCK_LEN + (in_len % T3F_BLOCK_LEN != 0);
    size_t ctr_buf_size = num_blocks * T3F_BLOCK_LEN;
    unsigned char *ctr_buf = (unsigned char *)sk_malloc(ctr_buf_size);
    sodium_memzero(ctr_buf, ctr_buf_size);
    int rc = crypto_stream_xchacha20_xor(ctr_buf, ctr_buf, ctr_buf_size,
                                         keys->ctr_nonce, keys->ctr_key);
    if (rc != 0) {
        stb_fatal("cannot encrypt using libsodium.");
    }

    uint32_t i = 0;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        threefishEncryptBlockBytes(t3f_x, &ctr_buf[i * T3F_BLOCK_LEN], t3f_buf);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            output[i * T3F_BLOCK_LEN + j] =
                input[i * T3F_BLOCK_LEN + j] ^ t3f_buf[j];
        }
    }
    if (in_len > 0) {
        threefishEncryptBlockBytes(t3f_x, &ctr_buf[i * T3F_BLOCK_LEN], t3f_buf);
        for (uint32_t j = 0; j < in_len; ++j) {
            output[i * T3F_BLOCK_LEN + j] =
                input[i * T3F_BLOCK_LEN + j] ^ t3f_buf[j];
        }
    }

    free(t3f_x);
    free(t3f_buf);
    free(ctr_buf);
}

void sk_decrypt(const unsigned char *const input, size_t in_len,
                unsigned char *output, sk_key_t *keys) {
    sk_encrypt(input, in_len, output, keys);
}