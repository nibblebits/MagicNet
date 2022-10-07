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
        if (!block_data->transactions[i])
        {
            continue;
        }

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
    struct block_transaction* transaction = calloc(1, sizeof(struct block_transaction));
    return transaction;
}

void block_transaction_free(struct block_transaction* transaction)
{
    free(transaction);
}

struct block_transaction* block_transaction_build(const char* program_name, char* data, size_t data_len)
{
    struct block_transaction* transaction = block_transaction_new();
    strncpy(transaction->data.program_name, program_name, sizeof(transaction->data.program_name));
    transaction->data.size = data_len;
    transaction->data.ptr = calloc(1, data_len);
    memcpy(transaction->data.ptr, data, data_len);
    transaction->data.time = time(NULL);
    return transaction;
}

void block_buffer_write_transaction_data(struct block_transaction_data* data, struct buffer* buffer)
{
  buffer_write_bytes(buffer, data->program_name, sizeof(data->program_name));
    buffer_write_long(buffer, data->size);
    buffer_write_long(buffer, data->time);

    if (data->ptr)
    {
        buffer_write_bytes(buffer,data->ptr, data->size);
    }
}

void block_buffer_write_transaction(struct block_transaction *block_transaction, struct buffer *buffer)
{
    buffer_write_bytes(buffer, block_transaction->hash, sizeof(block_transaction->hash));
    buffer_write_bytes(buffer, &block_transaction->key, sizeof(block_transaction->key));
    buffer_write_bytes(buffer, &block_transaction->signature, sizeof(block_transaction->signature));
    block_buffer_write_transaction_data(&block_transaction->data, buffer);
}



int block_transaction_hash_and_sign(struct block_transaction *transaction)
{
    if (transaction->data.size > MAGICNET_MAX_SIZE_FOR_TRANSACTION_DATA)
    {
        return -1;
    }

    char transaction_hash[SHA256_STRING_LENGTH];
    struct buffer* buffer = buffer_create();
    block_buffer_write_transaction_data(&transaction->data, buffer);
    sha256_data(buffer_ptr(buffer), transaction_hash, buffer_len(buffer));
    buffer_free(buffer);

    int res = 0;
    res = private_sign(transaction_hash, sizeof(transaction_hash),&transaction->signature);
    if (res < 0)
    {
        return res;
    }

    transaction->key = *MAGICNET_public_key();
    memcpy(transaction->hash, transaction_hash, sizeof(transaction->hash));

    return 0;
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
    struct buffer* buffer = buffer_create();
    block_buffer_write_transaction_data(&transaction->data, buffer);
    sha256_data(buffer_ptr(buffer), transaction_hash, buffer_len(buffer));
    buffer_free(buffer);

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

int block_save(struct block* block)
{
    int res = 0;
    res = magicnet_database_save_block(block);
    return res;
}

struct block *block_clone(struct block *block)
{
    struct block_data *block_data = block_data_new();
    for (int i = 0; i < block->data->total_transactions; i++)
    {
        block_data->transactions[i] = block_transaction_clone(block->data->transactions[i]);
    }
    block_data->total_transactions = block->data->total_transactions;
    return block_create_with_data(block->hash, block->prev_hash, block_data);
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
        block_buffer_write_transaction(data->transactions[i], tmp_buf);
    }
    sha256_data(buffer_ptr(tmp_buf), hash_out, buffer_len(tmp_buf));
    buffer_free(tmp_buf);
    return hash_out;
}

bool block_prev_hash_exists(struct block *block)
{
    char empty_hash[SHA256_STRING_LENGTH];
    bzero(empty_hash, sizeof(empty_hash));
    return memcmp(block->prev_hash, empty_hash, sizeof(empty_hash)) != 0;
}

int block_hash_sign_verify(struct block* block)
{
    int res = 0;
    block_hash_create(block->data, block->prev_hash, block->hash);
    res = block_verify(block);
    return res;
}
int block_verify(struct block *block)
{
    int res = 0;
    char block_hash[SHA256_STRING_LENGTH];
    block_hash_create(block->data, block->prev_hash, block_hash);
    if (memcmp(block->hash, block_hash, sizeof(block_hash)) != 0)
    {
        magicnet_log("%s the hash in the block does not match the hash it should be\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    for (int i = 0; i < block->data->total_transactions; i++)
    {
        struct block_transaction *transaction = block->data->transactions[i];
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
struct block *block_create_with_data(const char *hash, const char *prev_hash, struct block_data *data)
{
    struct block *block = calloc(1, sizeof(struct block));
    memcpy(block->hash, hash, sizeof(block->hash));
    if (prev_hash)
    {
        memcpy(block->prev_hash, prev_hash, sizeof(block->prev_hash));
    }
    block->data = data;
    return block;
}

struct block *block_create(struct block_data* data)
{
    char last_hash[SHA256_STRING_LENGTH] = {0};
    struct block* block = calloc(1, sizeof(struct block));
    block->data = data;
    // Consider instead cacheing it..
    if(magicnet_database_load_last_block(last_hash, NULL) >= 0)
    {
        memcpy(block->prev_hash, last_hash, sizeof(block->prev_hash));
    }

    return block;
}

void block_free(struct block *block)
{
    if (!block)
    {
        return;
    }

    if (block->data)
    {
       // block_data_free(block->data);
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

struct block *block_load(const char *hash)
{
    int res = 0;
    struct block* block = NULL;
    FILE *block_fp = NULL;
    char block_path[PATH_MAX];
    char prev_hash[SHA256_STRING_LENGTH];
    res = magicnet_database_load_block(hash, prev_hash);
    if (res < 0)
    {
        goto out;
    }

out:
    if (res < 0)
    {   
        if (block)
        {
            block_free(block);
            block = NULL;
        }
    }

    return block;
}   