#include "magicnet.h"
#include "log.h"
#include "misc.h"
#include <sqlite3.h>
#include <assert.h>
#include <limits.h>

sqlite3 *db = NULL;
const char *create_tables[] = {"CREATE TABLE \"blocks\" ( \
                                                \"hash\"	TEXT,\
                                                \"prev_hash\"	TEXT,\
                                                \"block_uri\"	TEXT\
                                                );",
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

int magicnet_database_load_block(const char* hash, struct block* block_out)
{
    assert(!block_out->data);
    int res = 0;
    sqlite3_stmt* stmt = NULL;
    const char* load_block_sql = "SELECT hash, prev_hash, block_uri  FROM blocks WHERE hash = ?";
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

    strncpy(block_out->hash, sqlite3_column_text(stmt, 0), sizeof(block_out->hash));
    strncpy(block_out->prev_hash, sqlite3_column_text(stmt, 1), sizeof(block_out->prev_hash));
    strncpy(block_out->block_uri, sqlite3_column_text(stmt, 2), sizeof(block_out->block_uri));

    char block_path[PATH_MAX];
    magicnet_get_block_path(block_out, block_path);

    if (!file_exists(block_path))
    {
        magicnet_log("%s the block data with hash %s cannot be found in the filesystem this is corruption\n", __FUNCTION__, block_out->hash);
        res = -1;
        goto out;
    }

    // We have the block path lets load it into memory
    FILE* block_fp = fopen(block_path, "r");
    if (!block_fp)
    {
        res = -1;
        goto out;
    }

    fseek(block_fp, 0, SEEK_END);
    size_t block_size= ftell(block_fp);
    fseek(block_fp, 0, SEEK_SET);
    
    char* block_data = calloc(1, block_size);
    res = fread(block_data, block_size, 1, block_fp);
    if (res != 1)
    {
        res = -1;
        goto out;
    }

    // Okay we have the block data.
    block_out->data = block_data;
out:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return res;
}