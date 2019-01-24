#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <sodium.h>
#include <assert.h>

#define X_PWD_LEN 256
#define X_SALT_LEN 32
#define Y_PWD_LEN 256
#define Y_SALT_LEN 32
#define PWD_FILE_SIZE (X_PWD_LEN + X_SALT_LEN + Y_PWD_LEN + Y_SALT_LEN)

#define X_T 8
#define X_M (1 << 18)
#define X_P 1
#define Y_T 5
#define Y_M (1 << 15)
#define Y_P 1

#define T3F_KEY_LEN 128
#define T3F_TWEAK_LEN 16
#define T3F_BLOCK_LEN 128
#define SKEIN_HMAC_KEY_LEN 64
#define SKEIN_HMAC_LEN 64

#endif