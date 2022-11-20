#include "magicnet.h"
#include "database.h"
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
                                                \"transaction_group_hash\" TEXT, \
                                                \"key\"	BLOB, \
                                                \"signature\");",

                               "CREATE TABLE \"blockchains\" ( \
                                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT, \
                                                \"type\" INTEGER , \
                                                \"begin_hash\"	TEXT,\
                                                \"last_hash\"	TEXT,\
                                                \"proven_verified_blocks\"  INTEGER);",

                               "CREATE TABLE \"transaction_groups\" ( \
                                \"hash\"	TEXT, \
                                \"total_transactions\"	INTEGER DEFAULT 0, \
                                PRIMARY KEY(\"hash\") \
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

                               "CREATE TABLE \"peers\" ( \
                                \"id\"	INTEGER,        \
                                \"ip_address\"	TEXT,   \
                                \"name\"	TEXT,       \
                                \"email\"	TEXT,       \
                                \"key\"	BLOB,           \
                                \"found_at\"	INTEGER, \
                                PRIMARY KEY(\"id\" AUTOINCREMENT) \
                            );",
                               NULL};

const char *magicnet_database_path()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(MAGICNET_DATA_BASE_DIRECTORY_ENV), MAGICNET_DATA_BASE, MAGICNET_DATABASE_SQLITE_FILEPATH);
    return filepath;
}

int magicnet_database_peer_add_no_locks(const char *ip_address, struct key *key, const char *name, const char *email)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *insert_peer_sql = "INSERT INTO  peers (found_at, ip_address, key, name, email) VALUES (?,?, ?, ?, ?);";
    res = sqlite3_prepare_v2(db, insert_peer_sql, strlen(insert_peer_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_int(stmt, 1, time(NULL));
    sqlite3_bind_text(stmt, 2, ip_address, strlen(ip_address), NULL);
    sqlite3_bind_null(stmt, 3);
    if (key)
    {
        sqlite3_bind_blob(stmt, 3, &key, sizeof(key), NULL);
    }
    sqlite3_bind_null(stmt, 4);
    if (name)
    {
        sqlite3_bind_text(stmt, 4, name, strlen(name), NULL);
    }
    sqlite3_bind_null(stmt, 5);

    if (email)
    {
        sqlite3_bind_text(stmt, 5, email, strlen(email), NULL);
    }

    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }

    sqlite3_finalize(stmt);
out:
    return res;
}

int magicnet_database_peer_add(const char *ip_address, struct key *key, const char *name, const char *email)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_peer_add_no_locks(ip_address, key, name, email);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_peer_load_by_key_no_locks(struct key *key, struct magicnet_peer_information *peer_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;

    const char *get_random_ip_sql = "SELECT ip_address, name, email, found_at FROM peers WHERE key=?;";
    res = sqlite3_prepare_v2(db, get_random_ip_sql, strlen(get_random_ip_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    res = sqlite3_bind_blob(stmt, 1, key, sizeof(struct key), NULL);
    if (res < 0)
    {
        goto out;
    }

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    if (peer_out)
    {
        strncpy(peer_out->ip_address, sqlite3_column_text(stmt, 0), sizeof(peer_out->ip_address));
        strncpy(peer_out->name, sqlite3_column_text(stmt, 1), sizeof(peer_out->name));
        strncpy(peer_out->email, sqlite3_column_text(stmt, 2), sizeof(peer_out->email));
        peer_out->found_out = sqlite3_column_int(stmt, 3);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

int magicnet_database_peer_load_by_key(struct key *key, struct magicnet_peer_information *peer_out)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_peer_load_by_key_no_locks(key, peer_out);
    pthread_mutex_unlock(&db_lock);
    return res;
}
int magicnet_database_peer_update_or_create(struct magicnet_peer_information *peer_info)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    struct magicnet_peer_information tmp_info;
    int load_res = magicnet_database_peer_load_by_key_no_locks(&peer_info->key, &tmp_info);
    if (load_res == MAGICNET_ERROR_NOT_FOUND)
    {
       res = magicnet_database_peer_add_no_locks(peer_info->ip_address, &peer_info->key, peer_info->name, peer_info->email);
       goto out;
    }

    // Already exists then update?
    const char *update_peer_info = "UPDATE peers SET ip_address=?, key=?, name=?, email=?  WHERE key=?;";
    res = sqlite3_prepare_v2(db, update_peer_info, strlen(update_peer_info), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_blob(stmt, 1, &peer_info->ip_address, sizeof(peer_info->ip_address), NULL);
    sqlite3_bind_blob(stmt, 2, &peer_info->key, sizeof(peer_info->key), NULL);
    sqlite3_bind_text(stmt, 3, peer_info->name, strlen(peer_info->name), NULL);
    sqlite3_bind_text(stmt, 4, peer_info->email, strlen(peer_info->email), NULL);
    sqlite3_bind_blob(stmt, 5, &peer_info->key, sizeof(peer_info->key), NULL);

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

int magicnet_database_peer_get_random_ip(char *ip_address_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;

    pthread_mutex_lock(&db_lock);
    const char *get_random_ip_sql = "SELECT DISTINCT ip_address FROM peers order by RANDOM() LIMIT 1;";
    res = sqlite3_prepare_v2(db, get_random_ip_sql, strlen(get_random_ip_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    if (ip_address_out)
    {
        bzero(ip_address_out, MAGICNET_MAX_IP_STRING_SIZE);
        strncpy(ip_address_out, sqlite3_column_text(stmt, 0), MAGICNET_MAX_IP_STRING_SIZE);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);
    return res;
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

    // This is the root host the peer everybody knows about.
    magicnet_database_peer_add_no_locks("104.248.237.170", NULL, "Root Host", "hello@dragonzap.com");

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
        res = MAGICNET_ERROR_NOT_FOUND;
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
        res = MAGICNET_ERROR_NOT_FOUND;
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

int magicnet_database_blockchain_get_active(struct blockchain **blockchain_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);
    const char *blockchain_load_sql = "SELECT id, type, begin_hash, proven_verified_blocks, last_hash from blockchains ORDER BY proven_verified_blocks desc LIMIT 0,1";
    res = sqlite3_prepare_v2(db, blockchain_load_sql, strlen(blockchain_load_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = -1;
        goto out;
    }
    struct blockchain *blockchain = blockchain_new();
    blockchain->id = sqlite3_column_int(stmt, 0);
    blockchain->type = sqlite3_column_int(stmt, 1);
    strncpy(blockchain->begin_hash, sqlite3_column_text(stmt, 2), SHA256_STRING_LENGTH);
    blockchain->proved_verified_blocks = sqlite3_column_int(stmt, 3);
    strncpy(blockchain->last_hash, sqlite3_column_text(stmt, 4), SHA256_STRING_LENGTH);
    *blockchain_out = blockchain;

out:
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_blockchain_blocks_count(int blockchain_id)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *create_blockchain_sql = "SELECT count(*) from blocks where blockchain_id=?";
    res = sqlite3_prepare_v2(db, create_blockchain_sql, strlen(create_blockchain_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_int(stmt, 1, blockchain_id);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = -1;
        goto out;
    }
    res = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

out:
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_blockchain_delete(int blockchain_id)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *create_blockchain_sql = "DELETE FROM blockchains where id=?";
    res = sqlite3_prepare_v2(db, create_blockchain_sql, strlen(create_blockchain_sql), &stmt, 0);
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

int magicnet_database_blocks_swap_chain(int blockchain_id_to_swap, int blockchain_id_to_swap_to)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *create_blockchain_sql = "UPDATE blocks SET blockchain_id=?  WHERE blockchain_id=?;";
    res = sqlite3_prepare_v2(db, create_blockchain_sql, strlen(create_blockchain_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_int(stmt, 1, blockchain_id_to_swap_to);
    sqlite3_bind_int(stmt, 2, blockchain_id_to_swap);

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

int magicnet_database_blockchain_save(struct blockchain *blockchain)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *update_blockchain_sql = "UPDATE blockchains SET type=?, begin_hash=?, last_hash=?, proven_verified_blocks=?  WHERE id=?;";
    res = sqlite3_prepare_v2(db, update_blockchain_sql, strlen(update_blockchain_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }
    sqlite3_bind_int(stmt, 1, blockchain->type);
    sqlite3_bind_text(stmt, 2, blockchain->begin_hash, strlen(blockchain->begin_hash), NULL);
    sqlite3_bind_text(stmt, 3, blockchain->last_hash, strlen(blockchain->last_hash), NULL);
    sqlite3_bind_int(stmt, 4, blockchain->proved_verified_blocks);
    sqlite3_bind_int(stmt, 5, blockchain->id);

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
        res = MAGICNET_ERROR_NOT_FOUND;
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
        res = MAGICNET_ERROR_NOT_FOUND;
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

int _magicnet_database_blockchain_load_from_id(int id, struct blockchain *blockchain_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *blockchain_load_sql = "SELECT id, type, begin_hash,  proven_verified_blocks, last_hash from blockchains WHERE id = ?";
    res = sqlite3_prepare_v2(db, blockchain_load_sql, strlen(blockchain_load_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_int(stmt, 1, id);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }
    blockchain_out->id = sqlite3_column_int(stmt, 0);
    blockchain_out->type = sqlite3_column_int(stmt, 1);
    strncpy(blockchain_out->begin_hash, sqlite3_column_text(stmt, 2), SHA256_STRING_LENGTH);
    blockchain_out->proved_verified_blocks = sqlite3_column_int(stmt, 3);
    strncpy(blockchain_out->last_hash, sqlite3_column_text(stmt, 4), SHA256_STRING_LENGTH);
    res = blockchain_out->id;

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
    int last_insert_id = 0;
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

    const char *get_max_id_query = "SELECT MAX(id) FROM  blockchains  ";
    res = sqlite3_prepare_v2(db, get_max_id_query, strlen(get_max_id_query), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = -1;
        goto out;
    }

    last_insert_id = sqlite3_column_int(stmt, 0);
    res = _magicnet_database_blockchain_load_from_id(last_insert_id, blockchain_out);
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

int magicnet_database_load_block_from_previous_hash(const char *prev_hash, char *hash_out, int *blockchain_id, char *transaction_group_hash)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_block_from_previous_hash_no_locks(prev_hash, hash_out, blockchain_id, transaction_group_hash);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_block_from_previous_hash_no_locks(const char *prev_hash, char *hash_out, int *blockchain_id, char *transaction_group_hash)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT hash, blockchain_id, transaction_group_hash FROM blocks WHERE prev_hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, prev_hash, strlen(prev_hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    if (hash_out)
    {
        bzero(hash_out, SHA256_STRING_LENGTH);
        strncpy(hash_out, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);
    }

    if (blockchain_id)
    {
        *blockchain_id = sqlite3_column_int(stmt, 1);
    }

    if (transaction_group_hash)
    {
        bzero(transaction_group_hash, SHA256_STRING_LENGTH);
        if (sqlite3_column_text(stmt, 2))
        {
            strncpy(transaction_group_hash, sqlite3_column_text(stmt, 2), SHA256_STRING_LENGTH);
        }
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}
int magicnet_database_load_block_transactions_no_locks(struct block *block)
{
    int res = 0;
    if (block->transaction_group->total_transactions > 0)
    {
        return MAGICNET_ERROR_ALREADY_EXISTANT;
    }
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT hash, signature, key, program_name, time, data_size, data FROM transactions WHERE transaction_group_hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, block->transaction_group->hash, sizeof(block->transaction_group->hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    while (step == SQLITE_ROW)
    {
        struct block_transaction *transaction = block_transaction_new();
        memcpy(transaction->hash, sqlite3_column_text(stmt, 0), strlen(sqlite3_column_text(stmt, 0)));
        memcpy(&transaction->signature, sqlite3_column_text(stmt, 1), sizeof(transaction->signature));
        memcpy(&transaction->key, sqlite3_column_text(stmt, 2), sizeof(transaction->key));
        memcpy(transaction->data.program_name, sqlite3_column_text(stmt, 3), strlen(sqlite3_column_text(stmt, 3)));
        transaction->data.time = sqlite3_column_int(stmt, 4);
        transaction->data.size = sqlite3_column_int(stmt, 5);
        transaction->data.ptr = calloc(1, transaction->data.size);
        memcpy(transaction->data.ptr, sqlite3_column_blob(stmt, 6), transaction->data.size);
        block_transaction_add(block->transaction_group, transaction);

        step = sqlite3_step(stmt);
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

int magicnet_database_load_block_transactions(struct block *block)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_block_transactions_no_locks(block);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_block(const char *hash, char *prev_hash_out, int *blockchain_id, char *transaction_group_hash, struct key *key, struct signature *signature)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_block_no_locks(hash, prev_hash_out, blockchain_id, transaction_group_hash, key, signature);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_block_no_locks(const char *hash, char *prev_hash_out, int *blockchain_id, char *transaction_group_hash, struct key *key, struct signature *signature)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT prev_hash, blockchain_id, transaction_group_hash, key, signature FROM blocks WHERE hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, hash, strlen(hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    if (prev_hash_out)
    {
        bzero(prev_hash_out, SHA256_STRING_LENGTH);
        strncpy(prev_hash_out, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);
    }

    if (blockchain_id)
    {
        *blockchain_id = sqlite3_column_int(stmt, 1);
    }

    if (transaction_group_hash)
    {
        bzero(transaction_group_hash, SHA256_STRING_LENGTH);
        if (sqlite3_column_text(stmt, 2))
        {
            strncpy(transaction_group_hash, sqlite3_column_text(stmt, 2), SHA256_STRING_LENGTH);
        }
    }

    if (key)
    {
        if (sqlite3_column_blob(stmt, 3))
        {
            memcpy(key, sqlite3_column_blob(stmt, 3), sizeof(struct key));
        }
    }

    if (signature)
    {
        if (sqlite3_column_blob(stmt, 4))
        {
            memcpy(signature, sqlite3_column_blob(stmt, 4), sizeof(struct signature));
        }
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
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

int magicnet_database_delete_all_chains_keep_blocks()
{
    int res = 0;
    pthread_mutex_lock(&db_lock);

    sqlite3_stmt *stmt = NULL;

    const char *delete_block_sql = "DELETE FROM blockchains";
    res = sqlite3_prepare_v2(db, delete_block_sql, strlen(delete_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }

    sqlite3_finalize(stmt);

    const char *reset_blockchain_on_blocks_sql = "UPDATE blocks set blockchain_id=0";
    res = sqlite3_prepare_v2(db, reset_blockchain_on_blocks_sql, strlen(reset_blockchain_on_blocks_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    step = sqlite3_step(stmt);
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
int magicnet_database_load_blocks(struct vector *block_vec_out, size_t amount)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    int pos = vector_count(block_vec_out);
    const char *load_block_sql = "SELECT hash, prev_hash, blockchain_id, transaction_group_hash, key, signature FROM blocks LIMIT ?, ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_int(stmt, 1, pos);
    sqlite3_bind_int(stmt, 2, amount);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    while (step == SQLITE_ROW)
    {
        char hash[SHA256_STRING_LENGTH];
        char prev_hash[SHA256_STRING_LENGTH];
        int blockchain_id = 0;
        char transaction_group_hash[SHA256_STRING_LENGTH];
        struct key key;
        struct signature signature;

        bzero(hash, SHA256_STRING_LENGTH);
        strncpy(hash, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);

        bzero(prev_hash, SHA256_STRING_LENGTH);
        strncpy(prev_hash, sqlite3_column_text(stmt, 1), SHA256_STRING_LENGTH);

        blockchain_id = sqlite3_column_int(stmt, 2);

        bzero(transaction_group_hash, SHA256_STRING_LENGTH);
        if (sqlite3_column_text(stmt, 3))
        {
            strncpy(transaction_group_hash, sqlite3_column_text(stmt, 3), SHA256_STRING_LENGTH);
        }

        if (sqlite3_column_blob(stmt, 4))
        {
            memcpy(&key, sqlite3_column_blob(stmt, 4), sizeof(struct key));
        }

        if (sqlite3_column_blob(stmt, 5))
        {
            memcpy(&signature, sqlite3_column_blob(stmt, 5), sizeof(struct signature));
        }
        struct block *block = block_create_with_group(hash, prev_hash, NULL);
        block->blockchain_id = blockchain_id;
        block->key = key;
        block->signature = signature;
        vector_push(block_vec_out, &block);
        step = sqlite3_step(stmt);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

int magicnet_database_load_blocks_with_no_chain(struct vector *block_vec_out, size_t amount)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    int pos = vector_count(block_vec_out);
    const char *load_block_sql = "SELECT hash, prev_hash, blockchain_id, transaction_group_hash, key, signature FROM blocks WHERE blockchain_id = 0 LIMIT ?, ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_int(stmt, 1, pos);
    sqlite3_bind_int(stmt, 2, amount);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    while (step == SQLITE_ROW)
    {
        char hash[SHA256_STRING_LENGTH];
        char prev_hash[SHA256_STRING_LENGTH];
        int blockchain_id = 0;
        char transaction_group_hash[SHA256_STRING_LENGTH];
        struct key key;
        struct signature signature;

        bzero(hash, SHA256_STRING_LENGTH);
        strncpy(hash, sqlite3_column_text(stmt, 0), SHA256_STRING_LENGTH);

        bzero(prev_hash, SHA256_STRING_LENGTH);
        strncpy(prev_hash, sqlite3_column_text(stmt, 1), SHA256_STRING_LENGTH);

        blockchain_id = sqlite3_column_int(stmt, 2);

        bzero(transaction_group_hash, SHA256_STRING_LENGTH);
        if (sqlite3_column_text(stmt, 3))
        {
            strncpy(transaction_group_hash, sqlite3_column_text(stmt, 3), SHA256_STRING_LENGTH);
        }

        if (sqlite3_column_blob(stmt, 4))
        {
            memcpy(&key, sqlite3_column_blob(stmt, 4), sizeof(struct key));
        }

        if (sqlite3_column_blob(stmt, 5))
        {
            memcpy(&signature, sqlite3_column_blob(stmt, 5), sizeof(struct signature));
        }
        struct block *block = block_create_with_group(hash, prev_hash, NULL);
        block->blockchain_id = blockchain_id;
        block->key = key;
        block->signature = signature;
        vector_push(block_vec_out, &block);
        step = sqlite3_step(stmt);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_count_blocks_with_previous_hash(const char *prev_hash)
{
    if (sha256_empty(prev_hash))
    {
        return 0;
    }
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *load_block_sql = "SELECT COUNT(*) FROM blocks WHERE prev_hash=?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, prev_hash, strlen(prev_hash), NULL);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    res = sqlite3_column_int(stmt, 0);
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_save_block(struct block *block)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);

    sqlite3_stmt *stmt = NULL;

    // Let's see if we already have the block saved
    res = magicnet_database_load_block_no_locks(block->hash, NULL, NULL, NULL, NULL, NULL);
    if (res >= 0)
    {
        // The block was already saved before
        res = MAGICNET_ERROR_ALREADY_EXISTANT;
        goto out;
    }

    const char *insert_block_sql = "INSERT INTO blocks (hash, prev_hash, blockchain_id, transaction_group_hash, key, signature) VALUES(?, ?, ?, ?, ?, ?)";
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

    sqlite3_bind_blob(stmt, 5, &block->key, sizeof(block->key), NULL);
    sqlite3_bind_blob(stmt, 6, &block->signature, sizeof(block->signature), NULL);

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

int magicnet_database_update_block(struct block *block)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);

    sqlite3_stmt *stmt = NULL;

    const char *insert_block_sql = "UPDATE blocks SET prev_hash=?, blockchain_id=?, transaction_group_hash=?, key=?,signature=? WHERE hash=?";
    res = sqlite3_prepare_v2(db, insert_block_sql, strlen(insert_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, block->prev_hash, strlen(block->prev_hash), NULL);
    sqlite3_bind_int(stmt, 2, block->blockchain_id);

    // transaction group hash is NULL in the case of zero transactions in a group
    if (block->transaction_group->total_transactions != 0)
    {
        sqlite3_bind_text(stmt, 3, block->transaction_group->hash, strlen(block->transaction_group->hash), NULL);
    }
    else
    {
        sqlite3_bind_null(stmt, 3);
    }

    sqlite3_bind_blob(stmt, 4, &block->key, sizeof(block->key), NULL);
    sqlite3_bind_blob(stmt, 5, &block->signature, sizeof(block->signature), NULL);

    sqlite3_bind_text(stmt, 6, block->hash, strlen(block->hash), NULL);
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
