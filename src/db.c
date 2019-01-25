#include "db.h"
#include "utils.h"
#include "crypto.h"
#include "argon2/argon2.h"
#include "lz4/lz4.h"
#include "stb_lib.h"

sqlite3 *sk_create_db() {
    sqlite3 *db = NULL;
    char *err_msg = NULL;
    
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        stb_fatal("cannot create a new database.");
    }
    char *sql = "DROP TABLE IF EXISTS keys;"
                "CREATE TABLE keys(id INTEGER PRIMARY KEY, version INT, y_salt BLOB, ciphertext BLOB, hmac BLOB);"
                "DROP TABLE IF EXISTS secrets;"
                "CREATE TABLE secrets(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, username TEXT, url TEXT, ic INT, notes TEXT, length INT, special INT);"
                "DROP TABLE IF EXISTS tags;"
                "CREATE TABLE tags(secret_id INT, name TEXT, notes TEXT);"
                "DROP TABLE IF EXISTS search;"
                "CREATE VIRTUAL TABLE search USING FTS5(title, username, url, notes);";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        stb_fatal("SQL error: %s\n", err_msg);
    }
    
    return db;
}

void sk_encrypt_db(unsigned char *fc, sqlite3 *db, const char *path, int path_type) {
       
    unsigned char *x_enc_key = (unsigned char *)sk_malloc(X_ENC_KEY_LEN);
    int rc = argon2id_hash_raw(X_T, X_M, X_P, fc, X_PWD_LEN, &fc[X_PWD_LEN], X_SALT_LEN, x_enc_key, X_ENC_KEY_LEN);
    if (rc != ARGON2_OK) {
        stb_fatal("cannot derive key(s) using Argon2.");
    }
    unsigned char *y_enc_key = (unsigned char *)sk_malloc(Y_ENC_KEY_LEN);
    rc = argon2id_hash_raw(Y_T, Y_M, Y_P, &fc[X_PWD_LEN + X_SALT_LEN], Y_PWD_LEN, &fc[X_PWD_LEN + X_SALT_LEN + Y_PWD_LEN], Y_SALT_LEN, y_enc_key, Y_ENC_KEY_LEN);
    if (rc != ARGON2_OK) {
        stb_fatal("cannot derive key(s) using Argon2.");
    }
    
    unsigned char *x_salt = (unsigned char *)sk_malloc(X_SALT_LEN);
    randombytes_buf(x_salt, X_SALT_LEN);
    sk_key_t *x_key = (sk_key_t *)sk_malloc(sizeof(sk_key_t));
    sk_make_key(x_key, x_enc_key, X_ENC_KEY_LEN, x_salt, X_SALT_LEN, 1);
    
    unsigned char *y_salt = (unsigned char *)sk_malloc(Y_SALT_LEN);
    randombytes_buf(y_salt, Y_SALT_LEN);
    sk_key_t *y_key = (sk_key_t *)sk_malloc(sizeof(sk_key_t));
    sk_make_key(y_key, y_enc_key, Y_ENC_KEY_LEN, y_salt, Y_SALT_LEN, 2);
    
    unsigned char *pass_key = (unsigned char *)sk_malloc(PASS_KEY_LEN);
    randombytes_buf(pass_key, PASS_KEY_LEN);
    unsigned char *enc_pass_key = (unsigned char *)sk_malloc(PASS_KEY_LEN);
    unsigned char *hmac_pass_key = (unsigned char *)sk_malloc(SKEIN_HMAC_LEN);
    
    sk_encrypt(pass_key, PASS_KEY_LEN, enc_pass_key, y_key);
    sk_hmac(enc_pass_key, PASS_KEY_LEN, hmac_pass_key, y_key->hmac_key);
    
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "INSERT INTO keys(id, version, y_salt, ciphertext, hmac) VALUES(1, 1, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        stb_fatal("SQL error: %s\n", sqlite3_errmsg(db));
    }
    rc = sqlite3_bind_blob(stmt, 1, y_salt, Y_SALT_LEN, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        stb_fatal("SQL error: %s\n", sqlite3_errmsg(db));
    }
    rc = sqlite3_bind_blob(stmt, 2, enc_pass_key, PASS_KEY_LEN, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        stb_fatal("SQL error: %s\n", sqlite3_errmsg(db));
    }
    rc = sqlite3_bind_blob(stmt, 3, hmac_pass_key, SKEIN_HMAC_LEN, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        stb_fatal("SQL error: %s\n", sqlite3_errmsg(db));
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        stb_fatal("SQL error: %s\n", sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
    
    size_t db_buf_size = 0;
    unsigned char *db_buf = sqlite3_serialize(db, "main", &db_buf_size, 0);
    if (db_buf == NULL) {
        stb_fatal("cannot serialize database.");
    }

    size_t max_compressed_size = LZ4_compressBound(db_buf_size);
    unsigned char *compressed_buf = (unsigned char *)sk_malloc(max_compressed_size);
    uint64_t compressed_size = LZ4_compress_default(db_buf, (char *)compressed_buf, db_buf_size, max_compressed_size);
    printf("db_buf_size: %ld\n", db_buf_size);
    printf("compressed_size: %ld\n", compressed_size);

    unsigned char *enc_db_buf = (unsigned char *)sk_malloc(compressed_size);
    unsigned char *hmac_enc_db = (unsigned char *)sk_malloc(SKEIN_HMAC_LEN);
    sk_encrypt(compressed_buf, compressed_size, enc_db_buf, x_key);
    sk_hmac(enc_db_buf, compressed_size, hmac_enc_db, x_key->hmac_key);
    FILE *enc_db = sk_fopen(path, "wb");
    unsigned char header[4] = {'s', 'k', '0', '1'};
    fwrite(header, 1, 4, enc_db);
    fwrite(x_salt, 1, X_SALT_LEN, enc_db);
    fwrite(hmac_enc_db, 1, SKEIN_HMAC_LEN, enc_db);
    fwrite(enc_db_buf, 1, compressed_size, enc_db);
    fclose(enc_db);
    
    sqlite3_free(db_buf);
    free(x_enc_key);
    free(y_enc_key);
    free(x_key);
    free(y_key);
    free(x_salt);
    free(y_salt);
    free(pass_key);
    free(enc_pass_key);
    free(hmac_pass_key);
    free(enc_db_buf);
    free(compressed_buf);
    free(hmac_enc_db);
}