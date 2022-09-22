#include "magicnet.h"
#include "config.h"
#include "misc.h"
#include "log.h"
#include "database.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
struct block_data *block_data_new(char* data, size_t len)
{
    struct block_data* block_data = calloc(1, sizeof(struct block_data));
    block_data->data = malloc(len);
    block_data->len = len;
    memcpy(block_data->data, data, len);
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

struct block* block_clone(struct block* block)
{
    return block_create(block->hash, block->prev_hash, block_data_new(block_data(block), block_data_len(block)));
}

const char* block_hash_create(struct block_data* data, const char* prev_hash, char* hash_out)
{
    struct buffer* tmp_buf = buffer_create();
    if (prev_hash)
    {
        buffer_write_bytes(tmp_buf, (void*)prev_hash, SHA256_STRING_LENGTH);
    }
    buffer_write_bytes(tmp_buf, (void*)data, data->len);
    sha256_data(buffer_ptr(tmp_buf), hash_out, buffer_len(tmp_buf));
    buffer_free(tmp_buf);
    return hash_out;
}

struct block *block_create(const char *hash, const char *prev_hash, struct block_data *data)
{
    // Let's verify the hash provided is correct for the block we are creating. 
    // We don't generate the hash for them to help minimize mistakes, we want them to tell us what the hash is.
    char block_hash[SHA256_STRING_LENGTH];
    bzero(block_hash, sizeof(block_hash));
    if (strncmp(block_hash_create(data, prev_hash, block_hash), block_hash, sizeof(block_hash)) != 0)
    {
        magicnet_log("%s you tried to create a block but provided us an illegal hash for the prev_hash and data combined\n", __FUNCTION__);
        return NULL;
    }
    struct block *block = calloc(1, sizeof(struct block));
    strncpy(block->hash, hash, sizeof(block->hash));
    if (prev_hash)
    {
        strncpy(block->prev_hash, prev_hash, sizeof(block->prev_hash));
    }
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