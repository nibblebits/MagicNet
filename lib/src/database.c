#include "magicnet.h"
#include "log.h"
#include "misc.h"
#include <sqlite3.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <vector.h>
sqlite3 *db = NULL;
pthread_mutex_t db_lock;

const char *create_tables[] = {"CREATE TABLE \"blocks\" ( \
                                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT, \
                                                \"hash\"	TEXT,\
                                                \"prev_hash\"	TEXT,\
                                                \"blockchain_id\" INTEGER, \
                                                \"transaction_group_hash\" TEXT \
                                                );",

                               "CREATE TABLE \"blockchains\" ( \
                                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT, \
                                                \"type\" INTEGER , \
                                                \"begin_hash\"	TEXT,\
                                                \"last_hash\"	TEXT,\
                                                \"proven_verified_blocks\"  INTEGER);",

                               "CREATE TABLE \"transaction_groups\" ( \
                                \"hash\"  PRIMARY KEY	TEXT,  \
                                \"total_transactions\" INTEGER \
                                );",

                               "CREATE TABLE \"transactions\" ( \
                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
                                \"hash\"	TEXT,  \
                                \"transaction_group_hash\" TEXT, \
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

    if (pthread_mutex_init(&db_lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the database lock\n");
        goto out;
    }

out:
    return res;
}

int magicnet_database_load_block_with_previous_hash(const char *prev_hash, char *hash_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT hash  FROM blocks WHERE prev_hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, prev_hash, strlen(prev_hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NO_BLOCK_FOUND;
        goto out;
    }

    if (hash_out)
    {
        bzero(hash_out, SHA256_STRING_LENGTH);
        strncpy(hash_out, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}
int magicnet_database_load_last_block_no_locks(char *hash_out, char *prev_hash_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_last_block_sql = "SELECT hash, prev_hash from blocks ORDER BY blocks.id DESC LIMIT 1";
    res = sqlite3_prepare_v2(db, load_last_block_sql, strlen(load_last_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    res = sqlite3_step(stmt);
    if (res != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NO_BLOCK_FOUND;
        goto out;
    }

    if (hash_out)
    {
        bzero(hash_out, SHA256_STRING_LENGTH);
        strncpy(hash_out, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);
    }

    if (prev_hash_out)
    {
        bzero(prev_hash_out, SHA256_STRING_LENGTH);
        strncpy(prev_hash_out, sqlite3_column_text(stmt, 1), SHA256_STRING_LENGTH);
    }
out:
    return res;
}

int magicnet_database_blockchain_all(struct vector *blockchain_vector_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);
    const char *blockchain_load_sql = "SELECT id, type, begin_hash, proven_verified_blocks, last_hash from blockchains";
    res = sqlite3_prepare_v2(db, blockchain_load_sql, strlen(blockchain_load_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    int step = sqlite3_step(stmt);
    while (step == SQLITE_ROW)
    {
        struct blockchain *blockchain = blockchain_new();
        blockchain->id = sqlite3_column_int(stmt, 0);
        blockchain->type = sqlite3_column_int(stmt, 1);
        strncpy(blockchain->begin_hash, sqlite3_column_text(stmt, 2), SHA256_STRING_LENGTH);
        blockchain->proved_verified_blocks = sqlite3_column_int(stmt, 3);
        strncpy(blockchain->last_hash, sqlite3_column_text(stmt, 4), SHA256_STRING_LENGTH);
        vector_push(blockchain_vector_out, &blockchain);
        step = sqlite3_step(stmt);
    }

out:
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
    return res;
}
int magicnet_database_blockchain_update_last_hash(int blockchain_id, const char *new_last_hash)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *create_blockchain_sql = "UPDATE blockchains SET last_hash=?  WHERE id=?;";
    res = sqlite3_prepare_v2(db, create_blockchain_sql, strlen(create_blockchain_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, new_last_hash, strlen(new_last_hash), NULL);
    sqlite3_bind_int(stmt, 2, blockchain_id);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }
    sqlite3_finalize(stmt);

out:
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_blockchain_increment_proven_verified_blocks(int blockchain_id)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *update_blockchain_sql = "UPDATE blockchains SET proven_verified_blocks = proven_verified_blocks + 1 WHERE id = ?";
    res = sqlite3_prepare_v2(db, update_blockchain_sql, strlen(update_blockchain_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_int(stmt, 1, blockchain_id);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }
    sqlite3_finalize(stmt);

out:
    pthread_mutex_unlock(&db_lock);
    return res;
}
int magicnet_database_blockchain_load_from_last_hash(const char *last_hash, struct blockchain *blockchain_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);
    const char *blockchain_load_sql = "SELECT id, type, begin_hash, proven_verified_blocks, last_hash from blockchains WHERE last_hash = ?";
    res = sqlite3_prepare_v2(db, blockchain_load_sql, strlen(blockchain_load_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, last_hash, strlen(last_hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NO_BLOCK_FOUND;
        goto out;
    }
    blockchain_out->id = sqlite3_column_int(stmt, 0);
    blockchain_out->type = sqlite3_column_int(stmt, 1);
    strncpy(blockchain_out->begin_hash, sqlite3_column_text(stmt, 2), SHA256_STRING_LENGTH);
    blockchain_out->proved_verified_blocks = sqlite3_column_int(stmt, 3);
    strncpy(blockchain_out->last_hash, sqlite3_column_text(stmt, 4), SHA256_STRING_LENGTH);

out:
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int _magicnet_database_blockchain_load_from_begin_hash(const char *begin_hash, struct blockchain *blockchain_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *blockchain_load_sql = "SELECT id, type, begin_hash,  proven_verified_blocks, last_hash from blockchains WHERE begin_hash = ?";
    res = sqlite3_prepare_v2(db, blockchain_load_sql, strlen(blockchain_load_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, begin_hash, strlen(begin_hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NO_BLOCK_FOUND;
        goto out;
    }
    blockchain_out->id = sqlite3_column_int(stmt, 0);
    blockchain_out->type = sqlite3_column_int(stmt, 1);
    strncpy(blockchain_out->begin_hash, sqlite3_column_text(stmt, 2), SHA256_STRING_LENGTH);
    blockchain_out->proved_verified_blocks = sqlite3_column_int(stmt, 3);
    strncpy(blockchain_out->last_hash, sqlite3_column_text(stmt, 4), SHA256_STRING_LENGTH);

out:
    sqlite3_finalize(stmt);
    return res;
}

/**
 * Creates a new blockchain due to the block provided.
 * No checks are preformed you must ensure this is what you want to do before you call this function
 */
int magicnet_database_blockchain_create(BLOCKCHAIN_TYPE type, const char *begin_hash, struct blockchain *blockchain_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *create_blockchain_sql = "INSERT INTO blockchains (type, begin_hash, last_hash, proven_verified_blocks) VALUES (?, ?, ?, ?);";
    res = sqlite3_prepare_v2(db, create_blockchain_sql, strlen(create_blockchain_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_int(stmt, 1, type);
    sqlite3_bind_text(stmt, 2, begin_hash, strlen(begin_hash), NULL);
    sqlite3_bind_text(stmt, 3, begin_hash, strlen(begin_hash), NULL);
    sqlite3_bind_int(stmt, 4, 0);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }
    sqlite3_finalize(stmt);

    res = _magicnet_database_blockchain_load_from_begin_hash(begin_hash, blockchain_out);
    if (res < 0)
    {
        goto out;
    }
out:
    pthread_mutex_unlock(&db_lock);
    return res;
}
int magicnet_database_load_last_block(char *hash_out, char *prev_hash_out)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_last_block_no_locks(hash_out, prev_hash_out);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_block_no_locks(const char *hash, char *prev_hash_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT prev_hash  FROM blocks WHERE hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, hash, strlen(hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NO_BLOCK_FOUND;
        goto out;
    }

    if (prev_hash_out)
    {
        bzero(prev_hash_out, SHA256_STRING_LENGTH);
        strncpy(prev_hash_out, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}
int magicnet_database_load_block(const char *hash, char *prev_hash_out)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_block_no_locks(hash, prev_hash_out);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magincet_database_save_transaction_group(struct block_transaction_group *transaction_group)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    if (transaction_group->total_transactions == 0)
    {
        // What transaction group... Just accept it as if we did something.
        return 0;
    }

    pthread_mutex_lock(&db_lock);
    const char *insert_transaction_groups_sql = "INSERT INTO  transaction_groups (hash, total_transactions) VALUES (?,?);";
    res = sqlite3_prepare_v2(db, insert_transaction_groups_sql, strlen(insert_transaction_groups_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, transaction_group->hash, strlen(transaction_group->hash), NULL);
    sqlite3_bind_int(stmt, 2, transaction_group->total_transactions);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }

    sqlite3_finalize(stmt);

    for (int i = 0; i < transaction_group->total_transactions; i++)
    {
        const char *insert_transaction_groups_sql = "INSERT INTO  transactions (hash, signature, key, program_name, time, data, data_size, transaction_group_hash) VALUES (?,?,?,?,?,?,?, ?);";
        res = sqlite3_prepare_v2(db, insert_transaction_groups_sql, strlen(insert_transaction_groups_sql), &stmt, 0);
        if (res != SQLITE_OK)
        {
            res = -1;
            goto out;
        }

        struct block_transaction *transaction = transaction_group->transactions[i];
        sqlite3_bind_text(stmt, 1, transaction->hash, strlen(transaction->hash), NULL);
        sqlite3_bind_blob(stmt, 2, &transaction->signature, sizeof(transaction->signature), NULL);
        sqlite3_bind_blob(stmt, 3, &transaction->key, sizeof(transaction->key), NULL);
        sqlite3_bind_text(stmt, 4, transaction->data.program_name, sizeof(transaction->data.program_name), NULL);
        sqlite3_bind_int64(stmt, 5, transaction->data.time);
        sqlite3_bind_blob(stmt, 6, transaction->data.ptr, transaction->data.size, NULL);
        sqlite3_bind_int(stmt, 7, transaction->data.size);
        sqlite3_bind_text(stmt, 8, transaction_group->hash, strlen(transaction_group->hash), NULL);
        int step = sqlite3_step(stmt);
        if (step != SQLITE_DONE)
        {
            res = -1;
            goto out;
        }

        sqlite3_finalize(stmt);
        stmt = NULL;
    }

out:
    pthread_mutex_unlock(&db_lock);
    return res;
}
int magicnet_database_save_block(struct block *block)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);

    sqlite3_stmt *stmt = NULL;

    // Let's see if we already have the block saved
    res = magicnet_database_load_block_no_locks(block->hash, NULL);
    if (res >= 0)
    {
        // The block was already saved before
        res = MAGICNET_ERROR_ALREADY_EXISTANT;
        goto out;
    }

    const char *insert_block_sql = "INSERT INTO blocks (hash, prev_hash, blockchain_id, transaction_group_hash) VALUES(?, ?, ?, ?)";
    res = sqlite3_prepare_v2(db, insert_block_sql, strlen(insert_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, block->hash, strlen(block->hash), NULL);
    sqlite3_bind_text(stmt, 2, block->prev_hash, strlen(block->prev_hash), NULL);
    sqlite3_bind_int(stmt, 3, block->blockchain_id);

    // transaction group hash is NULL in the case of zero transactions in a group
    if (block->transaction_group->total_transactions != 0)
    {
        sqlite3_bind_text(stmt, 4, block->transaction_group->hash, strlen(block->transaction_group->hash), NULL);
    }
    else
    {
        sqlite3_bind_null(stmt, 4);
    }
    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        goto out;
    }

    sqlite3_finalize(stmt);

out:
    pthread_mutex_unlock(&db_lock);
    return res;
}
