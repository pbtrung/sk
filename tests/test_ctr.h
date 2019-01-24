#include "crypto.h"
#include "utils.h"
#include "minunit.h"

MU_TEST(test_ctr_enc_dec) {
    sk_key_t *keys = (sk_key_t *)sk_malloc(sizeof(sk_key_t));
    sodium_memzero(keys, sizeof(sk_key_t));

    size_t in_len = T3F_BLOCK_LEN * 10 + 64;
    unsigned char *input = (unsigned char *)sk_malloc(in_len);
    unsigned char *output = (unsigned char *)sk_malloc(in_len);
    unsigned char *dec_output = (unsigned char *)sk_malloc(in_len);

    sk_encrypt(input, in_len, output, keys);
    sk_decrypt(output, in_len, dec_output, keys);
    mu_check(memcmp(input, dec_output, in_len) == 0);

    free(input);
    free(keys);
    free(output);
    free(dec_output);
}

MU_TEST_SUITE(test_ctr) { MU_RUN_TEST(test_ctr_enc_dec); }