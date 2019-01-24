#define STB_LIB_IMPLEMENTATION
#include "stb_lib.h"

#include "argparse/argparse.h"
#include "argon2/argon2.h"
#include "sqlite3/sqlite3.h"
#include "utils.h"
#include "config.h"

unsigned char *sk_create_local_db(size_t *db_buf_size) {
    sqlite3 *db = NULL;
    char *err_msg = NULL;
    
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        stb_fatal("cannot create a new database.");
    }
    char *sql = "DROP TABLE IF EXISTS keys;"
                "CREATE TABLE keys(version INT, hc256_iv BLOB, ciphertext BLOB, hmac BLOB);"
                "DROP TABLE IF EXISTS secrets;"
                "CREATE TABLE secrets(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, username TEXT, url TEXT, ic INT, notes TEXT, length INT, special INT);"
                "DROP TABLE IF EXISTS tags;"
                "CREATE TABLE tags(secret_id INT, name TEXT, notes TEXT);";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        stb_fatal("SQL error: %s\n", err_msg);
    }
    unsigned char *db_buf = sqlite3_serialize(db, "main", db_buf_size, 0);
    if (db_buf == NULL) {
        stb_fatal("cannot serialize database.");
    }
    sqlite3_close(db);
    return db_buf;
}

void sk_create_new_db(const char *pwd_file_path, const char *path, int path_type) {
    FILE *pwd_file = sk_fopen(pwd_file_path, "rb");

    size_t file_size = stb_filelen(pwd_file);
    if (file_size != PWD_FILE_SIZE) {
        stb_fatal("password file does not have required size (%d bytes).", PWD_FILE_SIZE);
    }

    unsigned char *fc = (unsigned char *)sk_sodium_malloc(PWD_FILE_SIZE);
    size_t len = fread(fc, 1, PWD_FILE_SIZE, pwd_file);
    if (len != PWD_FILE_SIZE) {
        stb_fatal("cannot read file.");
    }
    fclose(pwd_file);

    unsigned char *pwd = (unsigned char *)sk_sodium_malloc(X_PWD_LEN);
    unsigned char *salt = (unsigned char *)sk_sodium_malloc(X_SALT_LEN);
    
    memcpy(pwd, fc, X_PWD_LEN);
    memcpy(salt, &fc[X_PWD_LEN], X_SALT_LEN);
    sk_zero_free(fc, PWD_FILE_SIZE);

    if (path_type == 1) {
        size_t db_buf_size = 0;
        unsigned char *db_buf = sk_create_local_db(&db_buf_size);
        // sk_encrypt(pwd, salt, path, db_buf, db_buf_size);
        sqlite3_free(db_buf);
    }

    sk_zero_free(pwd, X_PWD_LEN);
    sk_zero_free(salt, X_SALT_LEN);
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