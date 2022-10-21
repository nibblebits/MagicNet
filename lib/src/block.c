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
#include <pthread.h>

pthread_mutex_t blockchain_lock;

int blockchain_init()
{
    if (pthread_mutex_init(&blockchain_lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the blockchain lock\n");
        return -1;
    }

    return 0;
}

struct blockchain* blockchain_new()
{
    return calloc(1, sizeof(struct blockchain));
}

void blockchain_free(struct blockchain* blockchain)
{
    free(blockchain);
}


struct block_transaction_group* block_transaction_group_new()
{
    return calloc(1, sizeof(struct block_transaction_group));
}

void block_transaction_group_free(struct block_transaction_group *transaction_group)
{
    for (int i = 0; i < transaction_group->total_transactions; i++)
    {
        if (!transaction_group->transactions[i])
        {
            continue;
        }

        if (transaction_group->transactions[i]->data.ptr)
        {
            free(transaction_group->transactions[i]->data.ptr);
        }
        free(transaction_group->transactions[i]);
    }
    free(transaction_group);
}

struct block_transaction *block_transaction_new()
{
    struct block_transaction *transaction = calloc(1, sizeof(struct block_transaction));
    return transaction;
}

void block_transaction_free(struct block_transaction *transaction)
{
    free(transaction);
}

struct block_transaction *block_transaction_build(const char *program_name, char *data, size_t data_len)
{
    struct block_transaction *transaction = block_transaction_new();
    strncpy(transaction->data.program_name, program_name, sizeof(transaction->data.program_name));
    transaction->data.size = data_len;
    transaction->data.ptr = calloc(1, data_len);
    memcpy(transaction->data.ptr, data, data_len);
    transaction->data.time = time(NULL);
    return transaction;
}

void block_buffer_write_transaction_data(struct block_transaction_data *data, struct buffer *buffer)
{
    buffer_write_bytes(buffer, data->program_name, sizeof(data->program_name));
    buffer_write_long(buffer, data->size);
    buffer_write_long(buffer, data->time);

    if (data->ptr)
    {
        buffer_write_bytes(buffer, data->ptr, data->size);
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
    struct buffer *buffer = buffer_create();
    block_buffer_write_transaction_data(&transaction->data, buffer);
    sha256_data(buffer_ptr(buffer), transaction_hash, buffer_len(buffer));
    buffer_free(buffer);

    int res = 0;
    res = private_sign(transaction_hash, sizeof(transaction_hash), &transaction->signature);
    if (res < 0)
    {
        return res;
    }

    transaction->key = *MAGICNET_public_key();
    memcpy(transaction->hash, transaction_hash, sizeof(transaction->hash));

    return 0;
}



int block_transaction_add(struct block_transaction_group *transaction_group, struct block_transaction *transaction)
{
    int res = 0;
    if (transaction_group->total_transactions >= MAGICNET_MAX_TOTAL_TRANSACTIONS_IN_BLOCK)
    {
        res = -1;
        goto out;
    }
    int index = transaction_group->total_transactions;
    transaction_group->transactions[index] = transaction;
    transaction_group->total_transactions++;
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
    struct buffer *buffer = buffer_create();
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

BLOCKCHAIN_TYPE blockchain_should_create_new(struct block *block)
{
    char empty_hash[SHA256_STRING_LENGTH] = {0};
    if (memcmp(block->prev_hash, empty_hash, sizeof(block->prev_hash)) == 0)
    {
        // Previous hash is NULL, then this means a new blockchain has been created. We should ensure that we create this chain
        return MAGICNET_BLOCKCHAIN_TYPE_UNIQUE_CHAIN;
    }

    struct blockchain blockchain = {0};
    int res = magicnet_database_blockchain_load_from_last_hash(block->prev_hash, &blockchain);
    if (res < 0)
    {
        // We don't actually have a blockchain that links to our blocks previous hash
        // This essentially means that we dont have this full block chain .
        // We should create a new chain that is incomplete. When the chain is completed we will resolve the conflict.
        return MAGICNET_BLOCKCHAIN_TYPE_INCOMPLETE;
    }

    char hash[SHA256_STRING_LENGTH] = {0};
    res = magicnet_database_load_block_with_previous_hash(block->prev_hash, hash);
    if (res >= 0 && strncmp(block->hash, hash, sizeof(block->hash) != 0))
    {
        // We already have a block in one of our blockchains that has the previous hash equal to ours
        // this means this is a chain split. With two different histories.
        return MAGICNET_BLOCKCHAIN_TYPE_SPLIT_CHAIN;
    }

    return MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN;
}

int blockchain_create_new(struct block *block, BLOCKCHAIN_TYPE type)
{
    int res = 0;
    struct blockchain blockchain = {0};
    res = magicnet_database_blockchain_create(type, block->hash, &blockchain);
    if (res < 0)
    {
        res = -1;
        goto out;
    }

    res = blockchain.id;
out:
    return res;
}

int blockchain_create_new_if_required(struct block *block)
{
    int res = -1;
    BLOCKCHAIN_TYPE blockchain_type = blockchain_should_create_new(block);
    if (blockchain_type != MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN)
    {
        res = blockchain_create_new(block, blockchain_type);
    }
    return res;
}

int blockchain_block_prepare(struct block *block)
{
    int res = 0;
    res = blockchain_create_new_if_required(block);
    if (res > 0)
    {
        block->blockchain_id = res;
        return res;
    }

    // We did not have to create a blockchain? Then we need to get the last chain and set that to our ID
    struct blockchain blockchain = {0};
    res = magicnet_database_blockchain_load_from_last_hash(block->prev_hash, &blockchain);
    if (res < 0)
    {
        return res;
    }

    block->blockchain_id = blockchain.id;
    return res;
}

int block_save(struct block *block)
{
    int res = 0;
    pthread_mutex_lock(&blockchain_lock);
    res = block_verify(block);
    if (res < 0)
    {
        magicnet_log("%s block verification failed\n", __FUNCTION__);
        goto out;
    }
    
    res = magicnet_database_load_block(block->hash, NULL);
    if (res >= 0)
    {
        magicnet_log("%s the same block was sent to us twice, we will ignore this one\n", __FUNCTION__);
        goto out;
    }

    res = blockchain_block_prepare(block);
    if (res < 0)
    {
        goto out;
    }
    res = magicnet_database_save_block(block);
    if (res < 0)
    {
        goto out;
    }

    res = magincet_database_save_transaction_group(block->transaction_group);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_database_blockchain_update_last_hash(block->blockchain_id, block->hash);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_database_blockchain_increment_proven_verified_blocks(block->blockchain_id);
    if (res < 0)
    {
        goto out;
    }
    
out:
    pthread_mutex_unlock(&blockchain_lock);
    return res;
}

struct block *block_clone(struct block *block)
{
    struct block_transaction_group *transaction_group = block_transaction_group_new();
    for (int i = 0; i < block->transaction_group->total_transactions; i++)
    {
        transaction_group->transactions[i] = block_transaction_clone(block->transaction_group->transactions[i]);
    }
    transaction_group->total_transactions = block->transaction_group->total_transactions;
    memcpy(transaction_group->hash, block->transaction_group->hash, sizeof(transaction_group->hash));
    return block_create_with_group(block->hash, block->prev_hash, transaction_group);
}


const char *block_transaction_group_hash_create(struct block_transaction_group *group, char* hash_out)
{
    struct buffer *tmp_buf = buffer_create();
    buffer_write_long(tmp_buf, group->total_transactions);
    for (int i = 0; i < group->total_transactions; i++)
    {
        block_buffer_write_transaction(group->transactions[i], tmp_buf);
    }

    if (buffer_len(tmp_buf) == 0)
    {
        // No hash today....
        memset(hash_out, 0, SHA256_STRING_LENGTH);
        hash_out =NULL;
        goto out;
    }
    sha256_data(buffer_ptr(tmp_buf), hash_out, buffer_len(tmp_buf));
    buffer_free(tmp_buf);
out:
    return hash_out;
}

const char *block_hash_create(struct block *block, const char* prev_hash, char* hash_out)
{
    struct buffer *tmp_buf = buffer_create();
    if (block->prev_hash)
    {
        buffer_write_bytes(tmp_buf, (void *)prev_hash, SHA256_STRING_LENGTH);
    }

    char transaction_group_hash[SHA256_STRING_LENGTH];
    block_transaction_group_hash_create(block->transaction_group, transaction_group_hash);
    buffer_write_bytes(tmp_buf, transaction_group_hash, sizeof(block->transaction_group->hash));
    sha256_data(buffer_ptr(tmp_buf), hash_out, buffer_len(tmp_buf));
    buffer_free(tmp_buf);
    return block->hash;
}


bool block_prev_hash_exists(struct block *block)
{
    char empty_hash[SHA256_STRING_LENGTH];
    bzero(empty_hash, sizeof(empty_hash));
    return memcmp(block->prev_hash, empty_hash, sizeof(empty_hash)) != 0;
}

int block_hash_sign_verify(struct block *block)
{
    int res = 0;
    block_hash_create(block, block->prev_hash, block->hash);
    block_transaction_group_hash_create(block->transaction_group, block->transaction_group->hash);
    res = block_verify(block);
    return res;
}

int block_verify(struct block *block)
{
    int res = 0;
    char block_hash[SHA256_STRING_LENGTH];
    block_hash_create(block, block->prev_hash, block_hash);
    if (memcmp(block->hash, block_hash, sizeof(block_hash)) != 0)
    {
        magicnet_log("%s the hash in the block does not match the hash it should be\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    char transaction_group_hash[SHA256_STRING_LENGTH];
    block_transaction_group_hash_create(block->transaction_group, transaction_group_hash);
    if (memcmp(transaction_group_hash, block->transaction_group->hash, sizeof(transaction_group_hash)) != 0)
    {
        magicnet_log("%s the transaction group hash is not what it should be\n",__FUNCTION__);
        res = -1;
        goto out;
    }

    // Validate every transaction to ensure they are correct.
    for (int i = 0; i < block->transaction_group->total_transactions; i++)
    {
        struct block_transaction *transaction = block->transaction_group->transactions[i];
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
struct block *block_create_with_group(const char *hash, const char *prev_hash, struct block_transaction_group *group)
{
    struct block *block = calloc(1, sizeof(struct block));
    memcpy(block->hash, hash, sizeof(block->hash));
    if (prev_hash)
    {
        memcpy(block->prev_hash, prev_hash, sizeof(block->prev_hash));
    }
    block->transaction_group = group;
    return block;
}

struct block *block_create(struct block_transaction_group *transaction_group, const char* prev_hash)
{
    char last_hash[SHA256_STRING_LENGTH] = {0};
    struct block *block = calloc(1, sizeof(struct block));
    block->transaction_group = transaction_group;

    if (!prev_hash)
    {
        if(magicnet_database_load_last_block(last_hash, NULL) >= 0)
        {
            memcpy(block->prev_hash, last_hash, sizeof(block->prev_hash));
            prev_hash = last_hash;
        }
    }

    if (prev_hash)
    {
        memcpy(block->prev_hash, prev_hash, sizeof(block->prev_hash));
    }
    return block;
}

void block_free(struct block *block)
{
    if (!block)
    {
        return;
    }

    if (block->transaction_group)
    {
        
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
    struct block *block = NULL;
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
