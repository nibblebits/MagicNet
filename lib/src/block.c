#include "magicnet.h"
#include "config.h"
#include "misc.h"
#include "log.h"
#include "database.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
struct block_data *block_data_new(char* data, size_t len)
{
    struct block_data* block_data =  calloc(1, sizeof(struct block_data));
    block_data->data = data;
    block_data->len = len;
    return block_data;
}

char *block_data(struct block *block)
{
    return block->data->data;
}

size_t block_data_len(struct block *block)
{
    return block->data->len;
}

void block_data_free(struct block_data* block_data)
{
    free(block_data->data);
    free(block_data);
}

struct block *block_create(const char *hash, const char *prev_hash, struct block_data *data)
{
    struct block *block = calloc(1, sizeof(struct block));
    strncpy(block->hash, hash, sizeof(block->hash));
    strncpy(block->prev_hash, prev_hash, sizeof(block->prev_hash));
    block->data = data;
    return block;
}

void block_free(struct block *block)
{
    block_data_free(block->data);
    free(block);
}

void magicnet_get_block_path(struct block *block, char *block_path_out)
{
    sprintf(block_path_out, "%s/%s/%s/%s", getenv("HOME"), ".magicnet", MAGICNET_BLOCK_DIRECTORY, block->hash);
}

void magicnet_get_block_path_for_hash(const char* hash, char *block_path_out)
{
    sprintf(block_path_out, "%s/%s/%s/%s.blk", getenv("HOME"), ".magicnet", MAGICNET_BLOCK_DIRECTORY, hash);
}

struct block *magicnet_block_load(const char *hash)
{
    int res = 0;
    FILE *block_fp = NULL;
    char block_path[PATH_MAX];
    char prev_hash[SHA256_STRING_LENGTH];
    res = magicnet_database_load_block(hash, prev_hash);
    if (res < 0)
    {
        goto out;
    }

    magicnet_get_block_path_for_hash(hash, block_path);

    if (!file_exists(block_path))
    {
        magicnet_log("%s the block data with hash %s cannot be found in the filesystem this is corruption\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    // We have the block path lets load it into memory
    block_fp = fopen(block_path, "r");
    if (!block_fp)
    {
        res = -1;
        goto out;
    }

    fseek(block_fp, 0, SEEK_END);
    size_t block_size = ftell(block_fp);
    fseek(block_fp, 0, SEEK_SET);

    char *block_data = calloc(1, block_size);
    res = fread(block_data, block_size, 1, block_fp);
    if (res != 1)
    {
        res = -1;
        goto out;
    }
    
out:
    fclose(block_fp);
    if (res < 0)
    {
        return NULL;
    }

    return block_create(hash, prev_hash, block_data_new(block_data, block_size));
}