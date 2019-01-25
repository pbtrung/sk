#ifndef __DB_H__
#define __DB_H__

#include "config.h"
#include "sqlite3/sqlite3.h"

sqlite3 *sk_create_db(void);
void sk_encrypt_db(unsigned char *fc, sqlite3 *db, const char *path, int path_type);

#endif