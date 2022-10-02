#include "magicnet.h"
#include "log.h"
#include "misc.h"
#include <sqlite3.h>
#include <assert.h>
#include <limits.h>

sqlite3 *db = NULL;

const char *create_tables[] = {"CREATE TABLE \"blocks\" ( \
                                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT, \
                                                \"hash\"	TEXT,\
                                                \"prev_hash\"	TEXT\
                                                );",

                               "CREATE TABLE \"transactions\" ( \
                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
                                \"hash\"	TEXT,  \
                                \"signature\"	BLOB,  \
                                \"key\"	BLOB,  \
                                \"program_name\"	TEXT,  \
                                \"time\"	REAL,   \
                                \"data\"	BLOB,  \
                                \"data_size\"	INTEGER);",

                               "CREATE TABLE \"ip_addresses\" ("
                               "\"id\"	INTEGER,"
                               "\"found_at\"	REAL,"
                               "\"ip_address\"	TEXT,"
                               "PRIMARY KEY(\"id\") "
                               ");",
                               NULL};

const char *magicnet_database_path()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(MAGICNET_DATA_BASE_DIRECTORY_ENV), MAGICNET_DATA_BASE, MAGICNET_DATABASE_SQLITE_FILEPATH);
    return filepath;
}

int magicnet_database_create()
{
    int res = 0;
    const char *sql = NULL;
    int index = 0;
    while ((sql = create_tables[index]) != NULL)
    {
        char *err_msg = NULL;
        res = sqlite3_exec(db, sql, 0, 0, &err_msg);
        if (res < 0)
        {
            magicnet_log("%s issue creating database %s\n", __FUNCTION__, err_msg);
            break;
        }
        index++;
    }

    return res;
}
int magicnet_database_load()
{
    int res = 0;
    bool first_creation = false;
    first_creation = !file_exists(magicnet_database_path());

    if (db)
    {
        magicnet_log("the database has already been loaded before\n");
        res = -1;
        goto out;
    }

    int rc = sqlite3_open(magicnet_database_path(), &db);
    if (rc)
    {
        magicnet_log("could not open the magicnet database\n");
        res = -1;
        goto out;
    }

    if (first_creation)
    {
        // First time creating this database? then we need to initialize it
        res = magicnet_database_create();
        if (res < 0)
        {
            goto out;
        }
    }
out:
    return res;
}

int magicnet_database_save_block(struct block *block)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;

    const char *insert_block_sql = "INSERT INTO blocks (hash, prev_hash) VALUES(?, ?)";
    sqlite3_bind_text(stmt, 1, block->hash, strlen(block->hash), NULL);
    sqlite3_bind_text(stmt, 2, block->prev_hash, strlen(block->hash), NULL);
    res = sqlite3_prepare_v2(db, insert_block_sql, -1, &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        goto out;
    }

    sqlite3_finalize(stmt);


    const char *insert_transaction_sql = "INSERT INTO  transactions (hash, signature, key, program_name, time, data, data_size) VALUES (?,?,?,?,?,?,?);";
    for (int i = 0; i < block->data->total_transactions; i++)
    {
        struct block_transaction *transaction = block->data->transactions[i];
        sqlite3_bind_text(stmt, 1, transaction->hash, strlen(transaction->hash), NULL);
        sqlite3_bind_blob(stmt, 2, &transaction->signature, sizeof(transaction->signature), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 3, &transaction->key, sizeof(transaction->key), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, transaction->data.program_name, strlen(transaction->data.program_name), NULL);
        sqlite3_bind_int64(stmt, 5, transaction->data.time);
        sqlite3_bind_blob(stmt, 6, transaction->data.ptr, transaction->data.size, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, transaction->data.size);
        res = sqlite3_prepare_v2(db, insert_transaction_sql, -1, &stmt, 0);
        if (res != SQLITE_OK)
        {
            goto out;
        }

        int step = sqlite3_step(stmt);
        if (step != SQLITE_ROW)
        {
            res = -1;
            goto out;
        }

        sqlite3_finalize(stmt);
        stmt = NULL;
    }


out:
    return res;
}

int magicnet_database_load_block(const char *hash, char *prev_hash_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT prev_hash  FROM blocks WHERE hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, -1, &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, hash, strlen(hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        goto out;
    }

    bzero(prev_hash_out, SHA256_STRING_LENGTH);
    strncpy(prev_hash_out, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}