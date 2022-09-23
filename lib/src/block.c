#include "magicnet.h"
#include "config.h"
#include "misc.h"
#include "log.h"
#include "database.h"
#include "sha256.h"
#include "key.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
struct block_data *block_data_new()
{
    struct block_data *block_data = calloc(1, sizeof(struct block_data));
    return block_data;
}

void block_data_free(struct block_data *block_data)
{
    for (int i = 0; i < block_data->total_transactions; i++)
    {
        if (block_data->transactions[i]->data.ptr)
        {
            free(block_data->transactions[i]->data.ptr);
        }
        free(block_data->transactions[i]);
    }
    free(block_data);
}

struct block_transaction *block_transaction_new()
{
    return calloc(1, sizeof(struct block_transaction));
}

int block_transaction_add(struct block *block, struct block_transaction *transaction)
{
    int res = 0;
    if (block->data->total_transactions >= MAGICNET_MAX_TOTAL_TRANSACTIONS_IN_BLOCK)
    {
        res = -1;
        goto out;
    }
    int index = block->data->total_transactions;
    block->data->transactions[index] = transaction;
    block->data->total_transactions++;
out:
    return res;
}

int block_transaction_valid(struct block_transaction *transaction)
{
    if (transaction->data.size > MAGICNET_MAX_SIZE_FOR_TRANSACTION_DATA)
    {
        return -1;
    }

    char transaction_hash[SHA256_STRING_LENGTH];
    sha256_data(&transaction->data, transaction_hash, sizeof(transaction->data));

    if (memcmp(transaction_hash, transaction->hash, sizeof(transaction_hash)) != 0)
    {
        magicnet_log("%s the hash provided does not match the hash of the data\n", __FUNCTION__);
        return -1;
    }

    if (public_verify(&transaction->key, transaction_hash, sizeof(transaction_hash), &transaction->signature) < 0)
    {
        magicnet_log("%s transaction is invalid, signature did not sign this data\n", __FUNCTION__);
        return -1;
    }
    return 0;
}

struct block_transaction *block_transaction_clone(struct block_transaction *transaction)
{
    struct block_transaction *cloned_transaction = block_transaction_new();
    memcpy(cloned_transaction, transaction, sizeof(struct block_transaction));
    if (transaction->data.ptr)
    {
        cloned_transaction->data.ptr = calloc(1, transaction->data.size);
        memcpy(cloned_transaction->data.ptr, transaction->data.ptr, transaction->data.size);
    }
    return cloned_transaction;
}

struct block *block_clone(struct block *block)
{
    struct block_data *block_data = block_data_new();
    for (int i = 0; i < block->data->total_transactions; i++)
    {
        block_data->transactions[i] = block_transaction_clone(block->data->transactions[i]);
    }
    return block_create(block->hash, block->prev_hash, block_data);
}

const char *block_hash_create(struct block_data *data, const char *prev_hash, char *hash_out)
{
    struct buffer *tmp_buf = buffer_create();
    if (prev_hash)
    {
        buffer_write_bytes(tmp_buf, (void *)prev_hash, SHA256_STRING_LENGTH);
    }
    buffer_write_long(tmp_buf, data->total_transactions);
    for (int i = 0; i < data->total_transactions; i++)
    {
        buffer_write_bytes(tmp_buf, data->transactions[i]->hash, sizeof(data->transactions[i]->hash));
        buffer_write_bytes(tmp_buf, &data->transactions[i]->key, sizeof(data->transactions[i]->key));
        buffer_write_bytes(tmp_buf, &data->transactions[i]->signature, sizeof(data->transactions[i]->signature));
        buffer_write_bytes(tmp_buf, data->transactions[i]->data.program_name, sizeof(data->transactions[i]->data.program_name));
        buffer_write_long(tmp_buf, data->transactions[i]->data.size);
        buffer_write_long(tmp_buf, data->transactions[i]->data.time);

        if (data->transactions[i]->data.ptr)
        {
            buffer_write_bytes(tmp_buf, data->transactions[i]->data.ptr, data->transactions[i]->data.size);
        }
    }
    sha256_data(buffer_ptr(tmp_buf), hash_out, buffer_len(tmp_buf));
    buffer_free(tmp_buf);
    return hash_out;
}

bool block_prev_hash_exists(struct block* block)
{
    char empty_hash[SHA256_STRING_LENGTH];
    bzero(empty_hash, sizeof(empty_hash));
    return memcmp(block->prev_hash, empty_hash, sizeof(empty_hash)) != 0;
}

int block_verify(struct block* block)
{
    int res = 0;
    char block_hash[SHA256_STRING_LENGTH];
    block_hash_create(block->data, block_prev_hash_exists(block) ? block->prev_hash : NULL, block_hash);
    if (memcmp(block->hash, block_hash, sizeof(block_hash)) != 0)
    {
        magicnet_log("%s the hash in the block does not match the hash it should be\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    for (int i = 0; i < block->data->total_transactions; i++)
    {
        struct block_transaction* transaction = block->data->transactions[i];
        res = block_transaction_valid(transaction);
        if (res < 0)
        {
            goto out;
        }
    }

out:
    if (res < 0)
    {
        magicnet_log("%s the block is not valid\n", __FUNCTION__);
    }
    return res;
}
struct block *block_create(const char *hash, const char *prev_hash, struct block_data *data)
{
    char block_hash[SHA256_STRING_LENGTH];
    bzero(block_hash, sizeof(block_hash));

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
    if (block->data)
    {
        block_data_free(block->data);
    }
    free(block);
}

void magicnet_get_block_path(struct block *block, char *block_path_out)
{
    sprintf(block_path_out, "%s/%s/%s/%s", getenv("HOME"), ".magicnet", MAGICNET_BLOCK_DIRECTORY, block->hash);
}

void magicnet_get_block_path_for_hash(const char *hash, char *block_path_out)
{
    sprintf(block_path_out, "%s/%s/%s/%s.blk", getenv("HOME"), ".magicnet", MAGICNET_BLOCK_DIRECTORY, hash);
}

struct block *magicnet_block_load(const char *hash)
{
    int res = 0;
    return NULL;
    // FILE *block_fp = NULL;
    // char block_path[PATH_MAX];
    // char prev_hash[SHA256_STRING_LENGTH];
    // res = magicnet_database_load_block(hash, prev_hash);
    // if (res < 0)
    // {
    //     goto out;
    // }

    // magicnet_get_block_path_for_hash(hash, block_path);

    // if (!file_exists(block_path))
    // {
    //     magicnet_log("%s the block data with hash %s cannot be found in the filesystem this is corruption\n", __FUNCTION__, hash);
    //     res = -1;
    //     goto out;
    // }

    // // We have the block path lets load it into memory
    // block_fp = fopen(block_path, "r");
    // if (!block_fp)
    // {
    //     res = -1;
    //     goto out;
    // }

    // fseek(block_fp, 0, SEEK_END);
    // size_t block_size = ftell(block_fp);
    // fseek(block_fp, 0, SEEK_SET);

    // char *block_data = calloc(1, block_size);
    // res = fread(block_data, block_size, 1, block_fp);
    // if (res != 1)
    // {
    //     res = -1;
    //     goto out;
    // }

    // out:
    //     fclose(block_fp);
    //     if (res < 0)
    //     {
    //         return NULL;
    //     }

    //     return block_create(hash, prev_hash, block_data_new(block_data, block_size));
}