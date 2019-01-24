#define STB_LIB_IMPLEMENTATION
#include "stb_lib.h"

#include "config.h"

#include "test_ctr.h"

int main(int argc, const char **argv) {

    if (sodium_init() < 0) {
        stb_fatal("libsodium cannot be initialized.");
    }

    MU_RUN_SUITE(test_ctr);

    MU_REPORT();
    return 0;
}