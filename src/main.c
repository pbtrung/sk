#define STB_LIB_IMPLEMENTATION
#include "stb_lib.h"

#include "argparse/argparse.h"
#include "argon2/argon2.h"
#include "sqlite3/sqlite3.h"
#include "utils.h"
#include "db.h"
#include "config.h"

void sk_create_new_db(const char *pwd_file_path, const char *path, int path_type) {
    FILE *pwd_file = sk_fopen(pwd_file_path, "rb");

    size_t file_size = stb_filelen(pwd_file);
    if (file_size != PWD_FILE_SIZE) {
        stb_fatal("password file does not have required size (%d bytes).", PWD_FILE_SIZE);
    }

    unsigned char *fc = (unsigned char *)sk_malloc(PWD_FILE_SIZE);
    size_t len = fread(fc, 1, PWD_FILE_SIZE, pwd_file);
    if (len != PWD_FILE_SIZE) {
        stb_fatal("cannot read file.");
    }
    fclose(pwd_file);    

    if (path_type == 1) {
        sqlite3 *db = sk_create_db();
        sk_encrypt_db(fc, db, path, 1);
        sqlite3_close(db);
    }
    
    free(fc);
}

static const char *const usage[] = {
    "sk [options] [[--] args]",
    "sk [options]",
    NULL,
};

int main(int argc, const char **argv) {

    if (sodium_init() < 0) {
        stb_fatal("libsodium cannot be initialized.");
    }

    const char *pwd_file_path = NULL;
    const char *local_path = NULL;
    const char *url = NULL;
    int new = 0;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_BOOLEAN('n', "new", &new, "create new database"),
        OPT_STRING('p', "pwd-file", &pwd_file_path, "path to password file (REQUIRED)"),
        OPT_STRING('l', "local-path", &local_path, "local path to database"),
        OPT_STRING('u', "url", &url, "remote path (URL) to database"),
        OPT_END(),
    };
    struct argparse argparse;
    argparse_init(&argparse, options, usage, 0);
    argparse_describe(&argparse, "\nSecret Keeper (sk). Options:", "");
    argparse_parse(&argparse, argc, argv);

    if (new != 0) {
        if (argc == 6 && pwd_file_path != NULL && (local_path != NULL || url != NULL)) {
            if (local_path != NULL)
                sk_create_new_db(pwd_file_path, local_path, 1);
            if (url != NULL)
                sk_create_new_db(pwd_file_path, url, 2);
        }
    }

    return EXIT_SUCCESS;
}