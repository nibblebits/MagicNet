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

const char *create_tables[] = {

    "CREATE TABLE \"councils\" ( \
                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
                                \"name\"	TEXT,  \
                                \"total_certificates\" INTEGER, \
                                \"creation_time\"	INTEGER,  \
                                \"id_hash\" TEXT, \
                                \"hash\" TEXT, \
                                \"creator_signature\" TEXT, \
                                \"creator_key\" TEXT);",

    "CREATE TABLE \"council_certificate_transfer_votes\" ( \
                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
                                \"transfer_id\" INTEGER, \
                                \"certificate_to_transfer_hash\" TEXT, \
                                \"total_voters\" INTEGER, \
                                \"total_for_vote\"  INTEGER, \
                                \"total_against_vote\" INTEGER, \
                                \"certificate_expires_at\" INTEGER, \
                                \"certificate_valid_from\" INTEGER, \
                                \"new_owner_key\" TEXT, \
                                \"winning_key\" TEXT, \
                                \"hash\"    TEXT,   \
                                \"signature\" TEXT, \
                                \"voter_certificate_hash\" TEXT);",

    "CREATE TABLE \"council_certificate_transfers\" ( \
                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
                                \"old_certificate_hash\" TEXT, \
                                \"new_owner_key\" TEXT, \
                                \"total_voters\"  INTEGER);",
    "CREATE TABLE \"council_certificates\" ( \
                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
                                \"local_cert_id\" INTEGER, \
                                \"flags\" INTEGER, \
                                \"council_id_hash\"	TEXT,  \
                                \"expires_at\" TEXT, \
                                \"valid_from\" TEXT, \
                                \"transfer_id\" INTEGER, \
                                \"hash\"	TEXT,  \
                                \"owner_key\"	TEXT,  \
                                \"signature\"	TEXT);",

    "CREATE TABLE \"blocks\" ( \
                                                \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT, \
                                                \"hash\"	TEXT,\
                                                \"prev_hash\"	TEXT,\
                                                \"blockchain_id\" INTEGER, \
                                                \"transaction_group_hash\" TEXT, \
                                                \"signing_certificate_hash\"	TEXT, \
                                                \"signature\" TEXT, \
                                                \"time_created\" INTEGER);",

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
                                \"type\" INTEGER, \
                                \"key\"	TEXT,  \
                                \"target_key\"	TEXT,  \
                                \"prev_block_hash\"	TEXT,  \
                                \"program_name\"	TEXT,  \
                                \"time\"	REAL,   \
                                \"data\"	BLOB,  \
                                \"data_size\"	INTEGER);",

    // Create table on money transactions
    "CREATE TABLE \"money_transactions\" ( \
                                \"transaction_hash\"	TEXT,  \
                                \"from_key\"	BLOB,  \
                                \"recipient_key\"	BLOB,  \
                                \"amount_received\"	DECIMAL,  \
                                \"amount_spent\"	DECIMAL,  \
                                PRIMARY KEY(\"transaction_hash\") \
                                );",

    "CREATE TABLE \"keys\" ( \
                                                        \"pub_key\"	BLOB, \
                                                        \"pri_key\"	BLOB, \
                                                        \"pub_key_size\" INTEGER,   \
                                                        \"pri_key_size\" INTEGER, \
                                                         \"active\"	INTEGER,        \
                                                        PRIMARY KEY(\"pub_key\") \
                            );",

    "CREATE TABLE \"peers\" ( \
                                \"id\"	INTEGER,        \
                                \"ip_address\"	TEXT,   \
                                \"name\"	TEXT,       \
                                \"email\"	TEXT,       \
                                \"key\"	BLOB,           \
                                \"found_at\"	INTEGER, \
                                PRIMARY KEY(\"id\" AUTOINCREMENT) \
                            );",

    // This query creates a table of banned peers
    // that will be used to prevent the server from
    // connecting to them.
    "CREATE TABLE \"banned_peers\" ( \
    \"id\"    INTEGER,        \
    \"ip_address\" TEXT,   \
    \"key\"   BLOB,           \
    \"added_at\" INTEGER, \
    \"banned_until\" INTEGER, \
    PRIMARY KEY(\"id\" AUTOINCREMENT)\
);",

    "CREATE TABLE \"settings\" (    \
	\"id\"	INTEGER,    \
	\"key\"	TEXT,   \
	\"value\"	TEXT,   \
    PRIMARY KEY(\"id\") \
    );",
    NULL};

const char *magicnet_database_path()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(MAGICNET_DATA_BASE_DIRECTORY_ENV), MAGICNET_DATA_BASE, MAGICNET_DATABASE_SQLITE_FILEPATH);
    return filepath;
}

int magicnet_database_setting_set_create_no_locks(const char *key, const char *value)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *insert_setting_sql = "INSERT INTO settings (key, value) VALUES (?, ?);";
    res = sqlite3_prepare_v2(db, insert_setting_sql, strlen(insert_setting_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }
    sqlite3_bind_text(stmt, 1, key, strlen(key), NULL);
    sqlite3_bind_text(stmt, 2, value, strlen(value), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }
out:
    sqlite3_finalize(stmt);
    return res;
}

int magicnet_database_setting_set_update_no_locks(const char *key, const char *value)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *update_setting_sql = "UPDATE settings SET value=? WHERE key=?;";
    res = sqlite3_prepare_v2(db, update_setting_sql, strlen(update_setting_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }
    sqlite3_bind_text(stmt, 1, value, strlen(value), NULL);
    sqlite3_bind_text(stmt, 2, key, strlen(key), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }
out:
    sqlite3_finalize(stmt);
    return res;
}

int magicnet_database_setting_set(const char *key, const char *value)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);
    if (strlen(value) > MAGICNET_MAX_SETTING_VALUE_SIZE)
    {
        magicnet_log("%s The setting value is too large\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Check if the key exists if it does update it otherwise create it
    const char *get_setting_sql = "SELECT id FROM settings WHERE key=?;";
    res = sqlite3_prepare_v2(db, get_setting_sql, strlen(get_setting_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }
    sqlite3_bind_text(stmt, 1, key, strlen(key), NULL);

    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW)
    {
        res = magicnet_database_setting_set_update_no_locks(key, value);
        if (res < 0)
        {
            goto out;
        }
    }
    else
    {
        res = magicnet_database_setting_set_create_no_locks(key, value);
        if (res < 0)
        {
            goto out;
        }
    }

out:
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_setting_get(const char *key, char *value_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *get_setting_sql = "SELECT value FROM settings WHERE key=?;";
    res = sqlite3_prepare_v2(db, get_setting_sql, strlen(get_setting_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }
    sqlite3_bind_text(stmt, 1, key, strlen(key), NULL);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = -1;
        goto out;
    }

    if (value_out)
    {
        strncpy(value_out, sqlite3_column_text(stmt, 0), MAGICNET_MAX_SETTING_VALUE_SIZE);
    }

out:
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
    return res;
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
    sqlite3_bind_null(stmt, 2);
    if (ip_address)
    {
        sqlite3_bind_text(stmt, 2, ip_address, strlen(ip_address), NULL);
    }
    sqlite3_bind_null(stmt, 3);
    if (key)
    {
        sqlite3_bind_blob(stmt, 3, key->key, sizeof(key->key), NULL);
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
    if (res >= 0)
    {
        res = MAGICNET_CREATED;
    }
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

    memcpy(&peer_out->key, key, sizeof(peer_out->key));
    const char *get_random_ip_sql = "SELECT ip_address, name, email, found_at FROM peers WHERE key=?;";
    res = sqlite3_prepare_v2(db, get_random_ip_sql, strlen(get_random_ip_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    res = sqlite3_bind_blob(stmt, 1, key->key, sizeof(key->key), NULL);
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
        if (sqlite3_column_text(stmt, 0))
        {
            strncpy(peer_out->ip_address, sqlite3_column_text(stmt, 0), sizeof(peer_out->ip_address));
        }

        if (sqlite3_column_text(stmt, 1))
        {
            strncpy(peer_out->name, sqlite3_column_text(stmt, 1), sizeof(peer_out->name));
        }

        if (sqlite3_column_text(stmt, 2))
        {
            strncpy(peer_out->email, sqlite3_column_text(stmt, 2), sizeof(peer_out->email));
        }
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
    const char *update_peer_info = "UPDATE peers SET ip_address=?, name=?, email=?  WHERE key=?;";
    res = sqlite3_prepare_v2(db, update_peer_info, strlen(update_peer_info), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    // Bind them all to NULL
    sqlite3_bind_null(stmt, 1);
    sqlite3_bind_null(stmt, 2);
    sqlite3_bind_null(stmt, 3);
    sqlite3_bind_null(stmt, 4);

    if (peer_info->ip_address[0])
    {
        sqlite3_bind_text(stmt, 1, peer_info->ip_address, strlen(peer_info->ip_address), NULL);
    }
    if (peer_info->name[0])
    {
        sqlite3_bind_text(stmt, 2, peer_info->name, strlen(peer_info->name), NULL);
    }
    if (peer_info->email[0])
    {
        sqlite3_bind_text(stmt, 3, peer_info->email, strlen(peer_info->email), NULL);
    }

    sqlite3_bind_blob(stmt, 4, &peer_info->key.key, sizeof(peer_info->key.key), NULL);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }
out:
    if (res >= 0)
    {
        res = MAGICNET_UPDATED;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
    return res;
}

/**
 * THis function checks the banned peers table for the given ip address it then sets the output record if it exists which includes all columns and returns 0
 * if it doesnt exist it returns not found
 */
int magicnet_database_banned_peer_load_by_ip(const char *ip_address, struct magicnet_banned_peer_information *peer_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    pthread_mutex_lock(&db_lock);

    const char *get_random_ip_sql = "SELECT id, key, ip_address, banned_at, banned_until FROM banned_peers WHERE ip_address=?;";
    res = sqlite3_prepare_v2(db, get_random_ip_sql, strlen(get_random_ip_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    res = sqlite3_bind_text(stmt, 1, ip_address, strlen(ip_address), NULL);
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
        peer_out->id = sqlite3_column_int(stmt, 0);
        if (sqlite3_column_blob(stmt, 1))
        {
            memcpy(&peer_out->key.key, sqlite3_column_blob(stmt, 1), sizeof(peer_out->key.key));
        }
        if (sqlite3_column_text(stmt, 2))
        {
            strncpy(peer_out->ip_address, sqlite3_column_text(stmt, 2), sizeof(peer_out->ip_address));
        }
        peer_out->banned_at = sqlite3_column_int(stmt, 3);
        peer_out->banned_until = sqlite3_column_int(stmt, 4);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_peer_get_random_ip(char *ip_address_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;

    pthread_mutex_lock(&db_lock);
    const char *get_random_ip_sql = "SELECT DISTINCT ip_address FROM peers WHERE ip_address != '' order by RANDOM() LIMIT 1;";
    res = sqlite3_prepare_v2(db, get_random_ip_sql, strlen(get_random_ip_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
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
    magicnet_save_peer_info(&(struct magicnet_peer_information){.ip_address = "104.248.237.170", .email = "hello@dragonzap.com"});
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

        // Set the first ever runtime.
        magicnet_setting_set_timestamp("first_run", time(NULL));
    }

    if (pthread_mutex_init(&db_lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the database lock\n");
        goto out;
    }

out:
    return res;
}

void magicnet_database_close()
{
    sqlite3_close(db);
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

/**
 * A function that returns the blockchain ID of the active blockchain
 */
int magicnet_database_get_active_blockchain_id()
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_last_block_sql = "SELECT id from blockchains ORDER BY proven_verified_blocks desc LIMIT 0,1";
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

    res = sqlite3_column_int(stmt, 0);
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

int magicnet_database_keys_get_active(struct key *key_pub_out, struct key *key_pri_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT pub_key, pri_key, pub_key_size, pri_key_size FROM keys WHERE active = 1";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
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

    key_pub_out->size = sqlite3_column_int(stmt, 2);
    key_pri_out->size = sqlite3_column_int(stmt, 3);

    memcpy(key_pub_out->key, sqlite3_column_blob(stmt, 0), key_pub_out->size);
    memcpy(key_pri_out->key, sqlite3_column_blob(stmt, 1), key_pri_out->size);

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

int magicnet_database_keys_create(struct key *pub_key, struct key *pri_key)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    int last_insert_id = 0;
    pthread_mutex_lock(&db_lock);

    const char *create_key_sql = "INSERT INTO keys (pub_key, pri_key, pub_key_size, pri_key_size, active) VALUES (?, ?, ?, ?, ?);";
    res = sqlite3_prepare_v2(db, create_key_sql, strlen(create_key_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_blob(stmt, 1, pub_key, pub_key->size, NULL);
    sqlite3_bind_blob(stmt, 2, pri_key, pri_key->size, NULL);
    sqlite3_bind_int(stmt, 3, pub_key->size);
    sqlite3_bind_int(stmt, 4, pri_key->size);
    sqlite3_bind_int(stmt, 5, 0);

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

int magicnet_database_keys_set_default(struct key *pub_key)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    int last_insert_id = 0;
    pthread_mutex_lock(&db_lock);

    const char *update_key_sql_to_zero = "UPDATE keys SET active=0";
    res = sqlite3_prepare_v2(db, update_key_sql_to_zero, strlen(update_key_sql_to_zero), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_blob(stmt, 1, pub_key, sizeof(pub_key), NULL);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }
    sqlite3_finalize(stmt);

    const char *update_key_sql = "UPDATE keys SET active=1 WHERE pub_key=?";
    res = sqlite3_prepare_v2(db, update_key_sql, strlen(update_key_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_blob(stmt, 1, pub_key, pub_key->size, NULL);

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

int magicnet_database_load_last_block(char *hash_out, char *prev_hash_out)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_last_block_no_locks(hash_out, prev_hash_out);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_block_from_previous_hash(const char *prev_hash, char *hash_out, int *blockchain_id, char *transaction_group_hash, time_t *created_time)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_block_from_previous_hash_no_locks(prev_hash, hash_out, blockchain_id, transaction_group_hash, created_time);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_block_from_previous_hash_no_locks(const char *prev_hash, char *hash_out, int *blockchain_id, char *transaction_group_hash, time_t *created_time)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT hash, blockchain_id, transaction_group_hash, time_created FROM blocks WHERE prev_hash = ?";
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

    if (created_time)
    {
        *created_time = sqlite3_column_int(stmt, 3);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

// Load the block transaction no locks
int magicnet_database_load_block_transaction_no_locks(const char *transaction_hash, struct block_transaction **transaction_out)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT hash, signature, type, target_key, prev_block_hash, program_name, time, data_size, data FROM transactions WHERE hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, transaction_hash, strlen(transaction_hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    struct block_transaction *transaction = block_transaction_new();
    memcpy(transaction->hash, sqlite3_column_text(stmt, 0), strlen(sqlite3_column_text(stmt, 0)));
    memcpy(&transaction->signature, sqlite3_column_text(stmt, 1), sizeof(transaction->signature));
    transaction->type = sqlite3_column_int(stmt, 2);
    transaction->key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 3));
    transaction->target_key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 4));

    memcpy(&transaction->data.prev_block_hash, sqlite3_column_text(stmt, 5), sizeof(transaction->data.prev_block_hash));

    memcpy(transaction->data.program_name, sqlite3_column_text(stmt, 6), strlen(sqlite3_column_text(stmt, 6)));
    transaction->data.time = sqlite3_column_int(stmt, 7);
    transaction->data.size = sqlite3_column_int(stmt, 8);
    transaction->data.ptr = calloc(1, transaction->data.size);
    memcpy(transaction->data.ptr, sqlite3_column_blob(stmt, 9), transaction->data.size);
    *transaction_out = transaction;

out:
    return res;
}

// Load the block transaction
int magicnet_database_load_block_transaction(const char *transaction_hash, struct block_transaction **transaction_out)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_block_transaction_no_locks(transaction_hash, transaction_out);
    pthread_mutex_unlock(&db_lock);
    return res;
}

// Load transactions by condition no locks
int magicnet_database_load_transactions_no_locks(struct magicnet_transactions_request *transactions_request, struct block_transaction_group *transaction_group)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    int param_count = 1;
    int step = 0;
    char load_transactions_sql[256] = "SELECT hash, signature, type, key, target_key, prev_block_hash, program_name, time, data_size, data FROM transactions WHERE 1";
    if (transactions_request->type != -1)
    {
        strcat(load_transactions_sql, " AND type = ?");
    }

    if (!sha256_empty(transactions_request->transaction_group_hash))
    {
        strcat(load_transactions_sql, " AND transaction_group_hash = ?");
    }

    if (transactions_request->flags & MAGICNET_TRANSACTIONS_REQUEST_FLAG_KEY_OR_TARGET_KEY && key_loaded(&transactions_request->key) && key_loaded(&transactions_request->target_key))
    {
        // This is a key or target key request
        strcat(load_transactions_sql, " AND (key=? OR target_key=?)");
    }
    else
    {
        if (key_loaded(&transactions_request->key))
        {
            strcat(load_transactions_sql, " AND key=?");
        }

        if (key_loaded(&transactions_request->target_key))
        {
            strcat(load_transactions_sql, " AND target_key=?");
        }
    }

    res = sqlite3_prepare_v2(db, load_transactions_sql, -1, &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    if (transactions_request->type != -1)
    {
        sqlite3_bind_int(stmt, param_count, transactions_request->type);
        param_count++;
    }

    if (!sha256_empty(transactions_request->transaction_group_hash))
    {
        sqlite3_bind_text(stmt, param_count, transactions_request->transaction_group_hash, strlen(transactions_request->transaction_group_hash), NULL);
        param_count++;
    }

    if (key_loaded(&transactions_request->key))
    {
        sqlite3_bind_text(stmt, param_count, transactions_request->key.key, strnlen(transactions_request->key.key, sizeof(transactions_request->key.key)), NULL);
        param_count++;
    }

    if (key_loaded(&transactions_request->target_key))
    {
        sqlite3_bind_text(stmt, param_count, transactions_request->target_key.key, strnlen(transactions_request->target_key.key, sizeof(transactions_request->target_key.key)), NULL);
        param_count++;
    }

    step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    while (step == SQLITE_ROW)
    {
        struct block_transaction *transaction = block_transaction_new();
        struct key tmp_key = {0};
        if (sqlite3_column_text(stmt, 0))
        {
            memcpy(transaction->hash, sqlite3_column_text(stmt, 0), strlen(sqlite3_column_text(stmt, 0)));
        }
        memcpy(&transaction->signature, sqlite3_column_text(stmt, 1), sizeof(transaction->signature));
        transaction->type = sqlite3_column_int(stmt, 2);
        tmp_key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 3));
        transaction->key = tmp_key;
        tmp_key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 4));
        transaction->target_key = tmp_key;
        if (sqlite3_column_text(stmt, 5))
        {
            memcpy(transaction->data.prev_block_hash, sqlite3_column_text(stmt, 5), sizeof(transaction->data.prev_block_hash));
        }

        if (sqlite3_column_text(stmt, 6))
        {
            // program name
            memcpy(transaction->data.program_name, sqlite3_column_text(stmt, 6), strlen(sqlite3_column_text(stmt, 6)));
        }
        // time
        transaction->data.time = sqlite3_column_int(stmt, 7);
        // data size
        transaction->data.size = sqlite3_column_int(stmt, 8);
        // data
        transaction->data.ptr = calloc(1, transaction->data.size);
        memcpy(transaction->data.ptr, sqlite3_column_blob(stmt, 9), transaction->data.size);
        block_transaction_add(transaction_group, transaction);

        // Step
        step = sqlite3_step(stmt);
    }

out:
    return res;
}
// Load transactions by condition
int magicnet_database_load_transactions(struct magicnet_transactions_request *transactions_request, struct block_transaction_group *transaction_group)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_transactions_no_locks(transactions_request, transaction_group);
    pthread_mutex_unlock(&db_lock);
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
    const char *load_block_sql = "SELECT hash, signature, type, key, target_key, prev_block_hash, program_name, time, data_size, data FROM transactions WHERE transaction_group_hash = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, block->transaction_group->hash, strlen(block->transaction_group->hash), NULL);
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
        transaction->type = sqlite3_column_int(stmt, 2);
        transaction->key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 3));
        transaction->target_key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 4));
        memcpy(&transaction->data.prev_block_hash, sqlite3_column_text(stmt, 5), sizeof(transaction->data.prev_block_hash));

        memcpy(transaction->data.program_name, sqlite3_column_text(stmt, 6), strlen(sqlite3_column_text(stmt, 6)));
        transaction->data.time = sqlite3_column_int(stmt, 7);
        transaction->data.size = sqlite3_column_int(stmt, 8);
        transaction->data.ptr = calloc(1, transaction->data.size);
        memcpy(transaction->data.ptr, sqlite3_column_blob(stmt, 9), transaction->data.size);
        block_transaction_add(block->transaction_group, transaction);

        step = sqlite3_step(stmt);
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }

    block_transaction_group_hash_create(block->transaction_group, block->transaction_group->hash);

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

int magicnet_database_load_block(const char *hash, char *prev_hash_out, int *blockchain_id, char *transaction_group_hash, struct key *key, struct signature *signature, time_t *created_time)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_block_no_locks(hash, prev_hash_out, blockchain_id, transaction_group_hash, key, signature, created_time);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_block_no_locks(const char *hash, char *prev_hash_out, int *blockchain_id, char *transaction_group_hash, struct key *key, struct signature *signature, time_t *created_time)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;
    const char *load_block_sql = "SELECT prev_hash, blockchain_id, transaction_group_hash, key, signature, time_created FROM blocks WHERE hash = ?";
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

    if (created_time)
    {
        // Yes I know this not a long we will deal with it later..
        *created_time = sqlite3_column_int(stmt, 5);
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

/**
 * Saves a money transaction into the magicnet database without locks
 * For table with columns
 *   \"transaction_hash\"	TEXT,  \
                                \"from_key\"	BLOB,  \
                                \"recipient_key\"	BLOB,  \
                                \"amount_received\"	DECIMAL,  \
                                \"amount_spent\"	DECIMAL,  \
 *
*/
int magicnet_database_save_money_transaction_no_locks(struct block_transaction *transaction)
{
    int res = 0;
    struct block_transaction_money_transfer money_transaction;
    // Check that this transaction is a coin transfer type, if its not leave
    if (transaction->type != MAGICNET_TRANSACTION_TYPE_COIN_SEND)
    {
        return MAGICNET_ERROR_INCOMPATIBLE;
    }
    sqlite3_stmt *stmt = NULL;
    const char *insert_money_transaction_sql = "INSERT INTO money_transactions (transaction_hash, from_key, recipient_key, amount_received, amount_spent) VALUES (?,?,?,?,?);";
    res = sqlite3_prepare_v2(db, insert_money_transaction_sql, strlen(insert_money_transaction_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    // Cast block transaction into money transaction
    res = magicnet_money_transfer_data(transaction, &money_transaction);
    if (res < 0)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, transaction->hash, strlen(transaction->hash), NULL);
    sqlite3_bind_blob(stmt, 2, &transaction->key.key, sizeof(transaction->key.key), NULL);
    sqlite3_bind_blob(stmt, 3, &money_transaction.recipient_key.key, sizeof(money_transaction.recipient_key.key), NULL);
    sqlite3_bind_double(stmt, 4, money_transaction.amount);
    sqlite3_bind_double(stmt, 5, 0);

    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        res = -1;
        goto out;
    }

    res = 0;

out:
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
        const char *insert_transaction_groups_sql = "INSERT INTO  transactions (hash, signature, type, key, target_key, prev_block_hash, program_name, time, data, data_size, transaction_group_hash) VALUES (?,?,?, ?, ?, ?, ?,?,?, ?, ?);";
        res = sqlite3_prepare_v2(db, insert_transaction_groups_sql, strlen(insert_transaction_groups_sql), &stmt, 0);
        if (res != SQLITE_OK)
        {
            // Print a error message
            magicnet_log("%s %d: %s", __FILE__, __LINE__, sqlite3_errmsg(db));
            res = -1;
            goto out;
        }

        struct block_transaction *transaction = transaction_group->transactions[i];
        sqlite3_bind_text(stmt, 1, transaction->hash, strlen(transaction->hash), NULL);
        sqlite3_bind_blob(stmt, 2, &transaction->signature, sizeof(transaction->signature), NULL);
        sqlite3_bind_int(stmt, 3, transaction->type);
        sqlite3_bind_text(stmt, 4, transaction->key.key, strlen(transaction->key.key), NULL);
        sqlite3_bind_text(stmt, 5, transaction->target_key.key, strlen(transaction->target_key.key), NULL);
        sqlite3_bind_text(stmt, 6, transaction->data.prev_block_hash, sizeof(transaction->data.prev_block_hash), NULL);
        sqlite3_bind_text(stmt, 7, transaction->data.program_name, sizeof(transaction->data.program_name), NULL);
        sqlite3_bind_int64(stmt, 8, transaction->data.time);
        sqlite3_bind_blob(stmt, 9, transaction->data.ptr, transaction->data.size, NULL);
        sqlite3_bind_int(stmt, 10, transaction->data.size);
        sqlite3_bind_text(stmt, 11, transaction_group->hash, strlen(transaction_group->hash), NULL);
        int step = sqlite3_step(stmt);
        if (step != SQLITE_DONE)
        {
            // Print a error message
            magicnet_log("%s %d: %s", __FILE__, __LINE__, sqlite3_errmsg(db));
            res = -1;
            goto out;
        }

        sqlite3_finalize(stmt);
        stmt = NULL;

        // We must also save it as a money transaction IF it is a money transaction type
        if (transaction->type == MAGICNET_TRANSACTION_TYPE_COIN_SEND)
        {
            res = magicnet_database_save_money_transaction_no_locks(transaction);
            if (res != 0)
            {
                goto out;
            }
        }
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

int magicnet_database_load_certificate_no_locks(struct magicnet_council_certificate *certificate_out, const char *certificate_hash);

/**
 * Loads the initial council certificates that existed upon council creation.
 */
int magicnet_database_load_council_certificates_no_locks(const char *council_id_hash, struct magicnet_council_certificate *certificates, size_t max_certificates)
{

    // "CREATE TABLE \"council_certificates\" ( \
        //                         \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
        //                         \"local_cert_id\" INTEGER, \
        //                         \"flags\" INTEGER, \
        //                         \"council_id_hash\"	TEXT,  \
        //                         \"expires_at\" TEXT, \
        //                         \"valid_from\" TEXT, \
        //                         \"transfer_id\" INTEGER, \
        //                         \"hash\"	TEXT,  \
        //                         \"owner_key\"	TEXT,  \
        //                         \"signature\"	TEXT);",
    int res = 0;

    sqlite3_stmt *stmt = NULL;

    // Where the council hash is equal to the provided hash and the MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS flag is set
    const char *load_block_sql = "SELECT hash FROM council_certificates WHERE council_id_hash = ? AND (flags & ?) = ?";
    res = sqlite3_prepare_v2(db, load_block_sql, strlen(load_block_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, council_id_hash, strlen(council_id_hash), NULL);
    sqlite3_bind_int(stmt, 2, MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS);
    sqlite3_bind_int(stmt, 3, MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS);

    int step = sqlite3_step(stmt);
    size_t i = 0;
    while (step == SQLITE_ROW)
    {
        if (i >= max_certificates)
        {
            res = MAGICNET_ERROR_OUT_OF_BOUNDS;
            goto out;
        }

        res = magicnet_database_load_certificate_no_locks(&certificates[i], sqlite3_column_text(stmt, 0));
        if (res < 0)
        {
            goto out;
        }
        step = sqlite3_step(stmt);
        i++;
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}
int magicnet_database_load_council_no_locks(const char *id_hash, struct magicnet_council *council_out)
{

    // "CREATE TABLE \"councils\" ( \
        //                         \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
        //                         \"name\"	TEXT,  \
        //                         \"total_certificates\" INTEGER, \
        //                         \"creation_time\"	INTEGER,  \
        //                         \"id_hash\" TEXT, \
        //                         \"hash\" TEXT, \
        //                         \"creator_signature\" TEXT, \
        //                         \"creator_key\" TEXT);",

    int res = 0;
    sqlite3_stmt *stmt = NULL;
    res = sqlite3_prepare_v2(db, "SELECT id, name, total_certificates, creation_time, id_hash, hash, creator_signature, creator_key FROM councils WHERE id_hash = ?", -1, &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    res = sqlite3_bind_text(stmt, 1, id_hash, strlen(id_hash), NULL);
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
    memcpy(council_out->signed_data.id_signed_data.name, sqlite3_column_text(stmt, 1), sizeof(council_out->signed_data.id_signed_data.name));
    council_out->signed_data.id_signed_data.total_certificates = sqlite3_column_int(stmt, 2);
    council_out->signed_data.id_signed_data.creation_time = (time_t)sqlite3_column_int64(stmt, 3);
    memcpy(council_out->signed_data.id_hash, sqlite3_column_text(stmt, 4), sizeof(council_out->signed_data.id_hash));
    council_out->signed_data.certificates = magicnet_council_certificate_create_many(council_out->signed_data.id_signed_data.total_certificates);
    res = magicnet_database_load_council_certificates_no_locks(council_out->signed_data.id_hash, council_out->signed_data.certificates, council_out->signed_data.id_signed_data.total_certificates);
    if (res < 0)
    {
        goto out;
    }

    // Set all the council certificates to point to this council
    for (size_t i = 0; i < council_out->signed_data.id_signed_data.total_certificates; i++)
    {
        council_out->signed_data.certificates[i].council = council_out;
    }

    memcpy(council_out->hash, sqlite3_column_text(stmt, 5), sizeof(council_out->hash));
    memcpy(&council_out->creator.signature, sqlite3_column_blob(stmt, 6), sizeof(council_out->creator.signature));
    council_out->creator.key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 7));
out:

    if (stmt)
    {
        sqlite3_finalize(stmt);
    }

    if (res < 0)
    {
        if (council_out->signed_data.certificates)
        {
            magicnet_council_certificate_many_free(council_out->signed_data.certificates, council_out->signed_data.id_signed_data.total_certificates);
            council_out->signed_data.certificates = NULL;
        }
    }
    return res;
}
int magicnet_database_load_council(const char *id_hash, struct magicnet_council *council_out)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_council_no_locks(id_hash, council_out);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_write_council_no_locks(const struct magicnet_council *council_in)
{
    int res = 0;
    int council_id = 0;
    sqlite3_stmt *stmt = NULL;

    // Start a transaction
    res = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    // Prepare SQL statement for council insertion
    const char *insert_council_sql = "INSERT INTO councils (name, total_certificates, creation_time, id_hash, hash, creator_signature, creator_key) VALUES (?, ?, ?, ?, ?, ?, ?)";
    res = sqlite3_prepare_v2(db, insert_council_sql, strlen(insert_council_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        res = -1;
        goto out;
    }

    // Bind values for the council
    sqlite3_bind_text(stmt, 1, council_in->signed_data.id_signed_data.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, council_in->signed_data.id_signed_data.total_certificates);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)council_in->signed_data.id_signed_data.creation_time);
    sqlite3_bind_text(stmt, 4, council_in->signed_data.id_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, council_in->hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 6, &council_in->creator.signature, sizeof(council_in->creator.signature), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, council_in->creator.key.key, -1, SQLITE_TRANSIENT);

    // Execute the insert statement
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        goto out;
    }

    // Get the ID of the newly inserted council
    council_id = sqlite3_last_insert_rowid(db);

    // Write the associated certificates
    for (int i = 0; i < council_in->signed_data.id_signed_data.total_certificates; i++)
    {
        res = magicnet_database_write_certificate_no_locks(&council_in->signed_data.certificates[i]);
        if (res < 0)
        {
            goto out;
        }
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }

    if (res < 0)
    {
        sqlite3_exec(db, "ROLLBACK TRANSACTION;", NULL, NULL, NULL); // Rollback on error
    }
    else
    {
        sqlite3_exec(db, "COMMIT TRANSACTION;", NULL, NULL, NULL); // Commit if successful
    }

    return res;
}

int magicnet_database_write_council(const struct magicnet_council *council_in)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_write_council_no_locks(council_in);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_write_transfer_votes_no_locks(int transfer_id, struct council_certificate_transfer_vote *certificate_transfer_votes_in, size_t num_elements)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;

    // Prepare SQL statement for insertion
    const char *insert_vote_sql = "INSERT INTO council_certificate_transfer_votes (transfer_id, certificate_to_transfer_hash, total_voters, total_for_vote, total_against_vote, certificate_expires_at, certificate_valid_from, new_owner_key, winning_key, hash, signature, voter_certificate_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    res = sqlite3_prepare_v2(db, insert_vote_sql, -1, &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    for (size_t i = 0; i < num_elements; i++)
    {
        // Bind values for each vote
        sqlite3_bind_int(stmt, 1, transfer_id);
        sqlite3_bind_text(stmt, 2, certificate_transfer_votes_in[i].signed_data.certificate_to_transfer_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, certificate_transfer_votes_in[i].signed_data.total_voters);
        sqlite3_bind_int(stmt, 4, certificate_transfer_votes_in[i].signed_data.total_for_vote);
        sqlite3_bind_int(stmt, 5, certificate_transfer_votes_in[i].signed_data.total_against_vote);
        sqlite3_bind_int64(stmt, 6, (sqlite3_int64)certificate_transfer_votes_in[i].signed_data.certificate_expires_at);
        sqlite3_bind_int64(stmt, 7, (sqlite3_int64)certificate_transfer_votes_in[i].signed_data.certificate_valid_from);
        sqlite3_bind_text(stmt, 8, certificate_transfer_votes_in[i].signed_data.new_owner_key.key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, certificate_transfer_votes_in[i].signed_data.winning_key.key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, certificate_transfer_votes_in[i].hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 11, &certificate_transfer_votes_in[i].signature, sizeof(struct signature), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 12, certificate_transfer_votes_in[i].voter_certificate->hash, -1, SQLITE_TRANSIENT);

        // Execute the insert statement
        res = sqlite3_step(stmt);
        if (res != SQLITE_DONE)
        {
            goto out;
        }

        // Reset the statement for the next vote
        sqlite3_reset(stmt);
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}
int magicnet_database_load_transfer_votes_no_locks(int transfer_id, struct council_certificate_transfer_vote *certificate_transfer_votes_out, size_t max_elements)
{
    // "CREATE TABLE \"council_certificate_transfer_votes\" ( \
        //                         \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
        //                         \"transfer_id\" INTEGER, \
        //                         \"certificate_to_transfer_hash\" TEXT, \
        //                         \"total_voters\" INTEGER, \
        //                         \"total_for_vote\"  INTEGER, \
        //                         \"total_against_vote\" INTEGER, \
        //                         \"certificate_expires_at\" INTEGER, \
        //                         \"certificate_valid_from\" INTEGER, \
        //                         \"new_owner_key\" TEXT, \
        //                         \"winning_key\" TEXT, \
        //                         \"hash\"    TEXT,   \
        //                         \"signature\" TEXT, \
        //                         \"voter_certificate_hash\" TEXT);",

    int res = 0;
    sqlite3_stmt *stmt = NULL;

    const char *load_transfer_votes_sql = "SELECT id, transfer_id, certificate_to_transfer_hash, total_voters, total_for_vote, total_against_vote, certificate_expires_at, certificate_valid_from, new_owner_key, winning_key, hash, signature, voter_certificate_hash FROM council_certificate_transfer_votes WHERE transfer_id=? ";
    res = sqlite3_prepare_v2(db, load_transfer_votes_sql, strlen(load_transfer_votes_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    int i = 0;
    sqlite3_bind_int(stmt, 1, transfer_id);
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        memcpy(certificate_transfer_votes_out[i].signed_data.certificate_to_transfer_hash, sqlite3_column_text(stmt, 2), sizeof(certificate_transfer_votes_out[i].signed_data.certificate_to_transfer_hash));
        certificate_transfer_votes_out[i].signed_data.total_voters = sqlite3_column_int(stmt, 3);
        certificate_transfer_votes_out[i].signed_data.total_for_vote = sqlite3_column_int(stmt, 4);
        certificate_transfer_votes_out[i].signed_data.total_against_vote = sqlite3_column_int(stmt, 5);
        certificate_transfer_votes_out[i].signed_data.certificate_expires_at = (time_t)sqlite3_column_int64(stmt, 6);
        certificate_transfer_votes_out[i].signed_data.certificate_valid_from = (time_t)sqlite3_column_int64(stmt, 7);

        certificate_transfer_votes_out->signed_data.new_owner_key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 8));
        certificate_transfer_votes_out->signed_data.winning_key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 9));
        memcpy(certificate_transfer_votes_out[i].hash, sqlite3_column_text(stmt, 10), sizeof(certificate_transfer_votes_out[i].hash));
        if (sqlite3_column_blob(stmt, 11))
        {
            memcpy(&certificate_transfer_votes_out[i].signature, sqlite3_column_blob(stmt, 11), sizeof(struct signature));
        }

        certificate_transfer_votes_out->voter_certificate = magicnet_council_certificate_create();
        res = magicnet_database_load_certificate_no_locks(certificate_transfer_votes_out->voter_certificate, sqlite3_column_text(stmt, 12));
        if (res < 0)
        {
            goto out;
        }

        i++;
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }

    if (res < 0)
    {
        for (int j = 0; j < i; j++)
        {
            if (certificate_transfer_votes_out[j].voter_certificate)
            {
                magicnet_council_certificate_free(certificate_transfer_votes_out[j].voter_certificate);
            }
        }
    }
    return res;
}

int magicnet_database_write_transfer_no_locks(struct council_certificate_transfer *certificate_transfer_in)
{
    int res = 0;
    sqlite3_stmt *stmt = NULL;

    // Prepare SQL statement for insertion
    const char *insert_transfer_sql = "INSERT INTO council_certificate_transfers (old_certificate_hash, new_owner_key, total_voters) VALUES (?, ?, ?)";
    res = sqlite3_prepare_v2(db, insert_transfer_sql, -1, &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_null(stmt, 1);
    // Bind values for the transfer
    if (certificate_transfer_in->certificate)
    {
        sqlite3_bind_text(stmt, 1, certificate_transfer_in->certificate->hash, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt, 2, certificate_transfer_in->new_owner.key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, certificate_transfer_in->total_voters);

    // Execute the insert statement
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        goto out;
    }

    // Get the ID of the newly inserted transfer
    int transfer_id = sqlite3_last_insert_rowid(db);

    if (certificate_transfer_in->voters)
    {
        // Write the associated transfer votes
        res = magicnet_database_write_transfer_votes_no_locks(transfer_id, certificate_transfer_in->voters, certificate_transfer_in->total_voters);
        if (res < 0)
        {
            goto out;
        }
    }

    res = transfer_id;
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

int magicnet_database_load_transfer_no_locks(struct council_certificate_transfer *certificate_transfer_out, int local_id)
{

    //    "CREATE TABLE \"council_certificate_transfers\" ( \
    //                             \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
    //                             \"old_certificate_hash\" TEXT, \
    //                             \"new_owner_key\" TEXT, \
    //                             \"total_voters\"	LONG);",
    int res = 0;

    const char *load_transfer_sql = "SELECT id, old_certificate_hash, new_owner_key, total_voters FROM council_certificate_transfers WHERE id = ?";
    sqlite3_stmt *stmt = NULL;
    res = sqlite3_prepare_v2(db, load_transfer_sql, strlen(load_transfer_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_int(stmt, 1, local_id);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    if (sqlite3_column_text(stmt, 1))
    {
        certificate_transfer_out->certificate = magicnet_council_certificate_create();
        res = magicnet_database_load_certificate_no_locks(certificate_transfer_out->certificate, sqlite3_column_text(stmt, 1));
        if (res < 0)
        {
            goto out;
        }
    }
    certificate_transfer_out->new_owner = MAGICNET_key_from_string(sqlite3_column_text(stmt, 2));
    certificate_transfer_out->total_voters = sqlite3_column_int(stmt, 3);

    certificate_transfer_out->voters = calloc(certificate_transfer_out->total_voters, sizeof(struct council_certificate_transfer_vote));
    if (!certificate_transfer_out->voters)
    {
        res = -1;
        goto out;
    }

    res = magicnet_database_load_transfer_votes_no_locks(local_id, certificate_transfer_out->voters, certificate_transfer_out->total_voters);
    if (res < 0)
    {
        goto out;
    }
out:
    if (res < 0)
    {
        if (certificate_transfer_out->certificate)
        {
            magicnet_council_certificate_free(certificate_transfer_out->certificate);
        }
    }

    if (stmt)
    {
        sqlite3_finalize(stmt);
    }

    return res;
}

int magicnet_database_write_certificate_no_locks(struct magicnet_council_certificate *certificate_in)
{
    int res = 0;
    int transfer_id = 0;
    sqlite3_stmt *stmt = NULL;

    // Start by creating the transfer
    res = magicnet_database_write_transfer_no_locks(&certificate_in->signed_data.transfer);
    if (res < 0)
    {
        goto out;
    }

    transfer_id = res;

    // Prepare SQL statement for insertion
    const char *insert_certificate_sql = "INSERT INTO council_certificates (local_cert_id, flags, council_id_hash, expires_at, valid_from, transfer_id, hash, owner_key, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    res = sqlite3_prepare_v2(db, insert_certificate_sql, -1, &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    // Bind values for the certificate
    sqlite3_bind_int(stmt, 1, certificate_in->signed_data.id);
    sqlite3_bind_int(stmt, 2, certificate_in->signed_data.flags);
    sqlite3_bind_text(stmt, 3, certificate_in->signed_data.council_id_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)certificate_in->signed_data.expires_at);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)certificate_in->signed_data.valid_from);
    sqlite3_bind_int(stmt, 6, transfer_id);
    sqlite3_bind_text(stmt, 7, certificate_in->hash, -1, SQLITE_TRANSIENT); // Assuming hash is available
    sqlite3_bind_text(stmt, 8, certificate_in->owner_key.key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 9, &certificate_in->signature, sizeof(struct signature), SQLITE_TRANSIENT);

    // Execute the insert statement
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        goto out;
    }

out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}

int magicnet_database_write_certificate(struct magicnet_council_certificate *certificate_in)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_write_certificate_no_locks(certificate_in);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_load_certificate_no_locks(struct magicnet_council_certificate *certificate_out, const char *certificate_hash)
{
    int res = 0;

    //    "CREATE TABLE \"council_certificates\" ( \
    //                             \"id\"	INTEGER PRIMARY KEY AUTOINCREMENT,  \
    //                             \"local_cert_id\" INTEGER, \
    //                             \"flags\" INTEGER, \
    //                             \"council_id_hash\"	TEXT,  \
    //                             \"expires_at\" TEXT, \
    //                             \"valid_from\" TEXT, \
    //                             \"valid_from\" TEXT, \
    //                             \"transfer_id\" INTEGER, \
    //                             \"hash\"	TEXT,  \
    //                             \"owner_key\"	TEXT,  \
    //                             \"signature\"	TEXT);",
    const char *load_certificate_sql = "SELECT id, local_cert_id, flags, council_id_hash, expires_at, valid_from, transfer_id, hash, owner_key, signature FROM council_certificates WHERE hash = ?";
    sqlite3_stmt *stmt = NULL;
    res = sqlite3_prepare_v2(db, load_certificate_sql, strlen(load_certificate_sql), &stmt, 0);
    if (res != SQLITE_OK)
    {
        goto out;
    }

    sqlite3_bind_text(stmt, 1, certificate_hash, strlen(certificate_hash), NULL);
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }
    certificate_out->signed_data.id = sqlite3_column_int(stmt, 1);
    certificate_out->signed_data.flags = sqlite3_column_int(stmt, 2);
    memcpy(certificate_out->signed_data.council_id_hash, sqlite3_column_text(stmt, 3), sizeof(certificate_out->signed_data.council_id_hash));
    certificate_out->signed_data.expires_at = (time_t)sqlite3_column_int64(stmt, 4);
    certificate_out->signed_data.valid_from = (time_t)sqlite3_column_int64(stmt, 5);

    magicnet_database_load_transfer_no_locks(&certificate_out->signed_data.transfer, sqlite3_column_int(stmt, 6));
    strncpy(certificate_out->hash, sqlite3_column_text(stmt, 7), sizeof(certificate_out->hash));

    certificate_out->owner_key = MAGICNET_key_from_string(sqlite3_column_text(stmt, 8));

    if (sqlite3_column_blob(stmt, 9))
    {
        memcpy(&certificate_out->signature, sqlite3_column_blob(stmt, 9), sizeof(struct signature));
    }

out:

    if (res < 0)
    {
        if (certificate_out->signed_data.transfer.certificate)
        {
            magicnet_council_certificate_free(certificate_out->signed_data.transfer.certificate);
        }
    }
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }

    return res;
}

int magicnet_database_load_certificate(struct magicnet_council_certificate *certificate_out, const char *certificate_hash)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);
    res = magicnet_database_load_certificate_no_locks(certificate_out, certificate_hash);
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
        char signing_certificate_hash[SHA256_STRING_LENGTH];
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
            memcpy(signing_certificate_hash, sqlite3_column_blob(stmt, 4), sizeof(signing_certificate_hash));
        }

        if (sqlite3_column_blob(stmt, 5))
        {
            memcpy(&signature, sqlite3_column_blob(stmt, 5), sizeof(struct signature));
        }
        struct block *block = block_create_with_group(hash, prev_hash, NULL);
        block->blockchain_id = blockchain_id;

        block->certificate = magicnet_council_certificate_load(signing_certificate_hash);
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
    struct vector *hash_vec = vector_create(SHA256_STRING_LENGTH);
    pthread_mutex_lock(&db_lock);

    int pos = vector_count(block_vec_out);
    const char *load_block_sql = "SELECT hash FROM blocks WHERE blockchain_id = 0 LIMIT ?, ?";
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
        if (sqlite3_column_text(stmt, 0))
        {
            char hash[SHA256_STRING_LENGTH] = {0};
            strncpy(hash, sqlite3_column_text(stmt, 0), sizeof(hash));
            vector_push(hash_vec, hash);
        }
        step = sqlite3_step(stmt);
    }
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db_lock);

    // Now we no longer have a database lock we must load all the blocks for the hashes we obtained.
    vector_set_peek_pointer(hash_vec, 0);
    const char *hash = vector_peek(hash_vec);
    while (hash)
    {
        struct block *block = block_load(hash);
        if (block)
        {
            block_load_fully(block);
        }
        vector_push(block_vec_out, &block);
        hash = vector_peek(hash_vec);
    }
    vector_free(hash_vec);
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
    res = magicnet_database_load_block_no_locks(block->hash, NULL, NULL, NULL, NULL, NULL, NULL);
    if (res >= 0)
    {
        // The block was already saved before
        res = MAGICNET_ERROR_ALREADY_EXISTANT;
        goto out;
    }

    const char *insert_block_sql = "INSERT INTO blocks (hash, prev_hash, blockchain_id, transaction_group_hash, signing_certificate_hash, signature, time_created) VALUES(?, ?, ?, ?, ?, ?, ?)";
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

    sqlite3_bind_blob(stmt, 5, &block->certificate->hash, sizeof(block->certificate->hash), NULL);
    sqlite3_bind_blob(stmt, 6, &block->signature, sizeof(block->signature), NULL);

    // Yes we bind an int I know its a long we change this later.
    sqlite3_bind_int(stmt, 7, block->time);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE)
    {
        goto out;
    }

out:
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_lock);
    return res;
}

int magicnet_database_update_block(struct block *block)
{
    int res = 0;
    pthread_mutex_lock(&db_lock);

    sqlite3_stmt *stmt = NULL;

    const char *insert_block_sql = "UPDATE blocks SET prev_hash=?, blockchain_id=?, transaction_group_hash=?, signing_certificate_hash=?,signature=? WHERE hash=?";
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

    sqlite3_bind_blob(stmt, 4, &block->certificate->hash, sizeof(block->certificate->hash), NULL);
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
