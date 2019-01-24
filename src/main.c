#include <sodium.h>

#define STB_LIB_IMPLEMENTATION
#include "stb_lib.h"

#include "argon2/argon2.h"

int main(int argc, char **argv) {

    if (sodium_init() < 0) {
        stb_fatal("libsodium cannot be initialized.");
    }

    return EXIT_SUCCESS;
}