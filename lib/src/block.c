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

struct blockchain *blockchain_new()
{
    return calloc(1, sizeof(struct blockchain));
}

void blockchain_free(struct blockchain *blockchain)
{
    free(blockchain);
}

struct block_transaction_group *block_transaction_group_new()
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
struct block_transaction_group *block_transaction_group_clone(struct block_transaction_group *transaction_group_in)
{
    struct block_transaction_group *cloned_transaction_group = block_transaction_group_new();
    for (int i = 0; i < transaction_group_in->total_transactions; i++)
    {
        cloned_transaction_group->transactions[i] = block_transaction_clone(transaction_group_in->transactions[i]);
    }
    cloned_transaction_group->total_transactions = transaction_group_in->total_transactions;
    memcpy(cloned_transaction_group->hash, transaction_group_in->hash, sizeof(cloned_transaction_group->hash));
    return cloned_transaction_group;
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

BLOCKCHAIN_TYPE blockchain_should_create_new(struct block *block, int *blockchain_id_out)
{
    char empty_hash[SHA256_STRING_LENGTH] = {0};
    if (memcmp(block->prev_hash, empty_hash, sizeof(block->prev_hash)) == 0)
    {
        // Previous hash is NULL, then this means a new blockchain has been created. We should ensure that we create this chain
        return MAGICNET_BLOCKCHAIN_TYPE_UNIQUE_CHAIN;
    }

    int blockchain_id = -1;
    int res = magicnet_database_load_block(block->prev_hash, NULL, &blockchain_id, NULL, NULL, NULL);
    if (res >= 0)
    {
        // We should use the chain of the previous hash here..
        *blockchain_id_out = blockchain_id;
        return MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN;
    }

    res = magicnet_database_load_block_from_previous_hash(block->hash, NULL, &blockchain_id, NULL);
    if (res >= 0)
    {
        // We should use the chain of the previous hash here..
        *blockchain_id_out = blockchain_id;
        return MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN;
    }

    res = magicnet_database_load_block_from_previous_hash(block->prev_hash, NULL, &blockchain_id, NULL);
    if (res >= 0)
    {
        // We should use the chain of the previous hash here..
        *blockchain_id_out = blockchain_id;
        return MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN;
    }

    return MAGICNET_BLOCKCHAIN_TYPE_INCOMPLETE;
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
    BLOCKCHAIN_TYPE blockchain_type = blockchain_should_create_new(block, &res);
    if (blockchain_type != MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN)
    {
        res = blockchain_create_new(block, blockchain_type);
    }
    return res;
}

void block_free_vector(struct vector* block_vec)
{
    vector_set_peek_pointer(block_vec, 0);
    struct block* block = vector_peek_ptr(block_vec);
    while(block)
    {
        block_free(block);
        block = vector_peek_ptr(block_vec);
    }
    vector_free(block_vec);
}

/**
 * Reformats the blockchain based on the given block. This function is responsible for moving blocks into new blockchains
 * if it is clear that a blockchain is obsolete.
 *
 * A blockchain becomes obsolete when it becomes fully resolved. For example this can happen if we have a block sent to us but we dont know
 * the block before it. This results in a blockchain of type INCOMPLETE. If we then resolve this chain then all the blocks are moved
 * to the correct blockchain and the old chain is deleted. In some cases the chain state is changed deletion is not always the case.
 * [DEPRECATED] FOR NOW.
 */
int blockchain_reformat(struct block *block)
{

    int res = 0;
    struct vector* block_vec = vector_create(sizeof(struct block*));
    while(magicnet_database_load_blocks(block_vec, 10) >= 0)
    {
    }

    magicnet_log("%s total blocks %i\n", __FUNCTION__, vector_count(block_vec));
    block_free_vector(block_vec);
out:
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
    if (!block)
    {
        // Null block? Could this be someone trying to exploit or a mistake of some kind..
        return MAGICNET_ERROR_SECURITY_RISK;
    }

    pthread_mutex_lock(&blockchain_lock);
    res = block_verify(block);
    if (res < 0)
    {
        magicnet_log("%s block verification failed\n", __FUNCTION__);
        goto out;
    }

    res = blockchain_block_prepare(block);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_database_load_block(block->hash, NULL, NULL, NULL, NULL, NULL);
    if (res >= 0)
    {
        blockchain_reformat(block);
        magicnet_log("%s the same block was sent to us twice, we will ignore this one\n", __FUNCTION__);
        res = MAGICNET_BLOCK_SENT_BEFORE;
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

    res = blockchain_reformat(block);
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

    struct block *block_cloned = block_create_with_group(block->hash, block->prev_hash, block->transaction_group);
    block_cloned->key = block->key;
    block_cloned->signature = block->signature;
    return block_cloned;
}

const char *block_transaction_group_hash_create(struct block_transaction_group *group, char *hash_out)
{
    if (group->total_transactions == 0)
    {
        // No hash today....
        memset(hash_out, 0, SHA256_STRING_LENGTH);
        return NULL;
    }

    struct buffer *tmp_buf = buffer_create();
    buffer_write_long(tmp_buf, group->total_transactions);
    for (int i = 0; i < group->total_transactions; i++)
    {
        block_buffer_write_transaction(group->transactions[i], tmp_buf);
    }

    sha256_data(buffer_ptr(tmp_buf), hash_out, buffer_len(tmp_buf));
    buffer_free(tmp_buf);
    return hash_out;
}

const char *block_hash_create(struct block *block, char *hash_out)
{
    struct buffer *tmp_buf = buffer_create();

    buffer_write_bytes(tmp_buf, &block->key, sizeof(block->key));
    buffer_write_bytes(tmp_buf, block->prev_hash, strlen(block->prev_hash));
    char transaction_group_hash[SHA256_STRING_LENGTH];
    if (block_transaction_group_hash_create(block->transaction_group, transaction_group_hash))
    {
        buffer_write_bytes(tmp_buf, transaction_group_hash, sizeof(block->transaction_group->hash));
    }
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
    block->key = *MAGICNET_public_key();

    block_hash_create(block, block->hash);

    res = block_sign(block);
    if (res < 0)
    {
        magicnet_log("%s failed to sign block\n", __FUNCTION__);
        return res;
    }
    res = block_verify(block);
    return res;
}

int block_sign(struct block *block)
{
    int res = 0;
    struct key blank_key = {0};
    if (memcmp(&block->key, &blank_key, sizeof(block->key)) == 0)
    {
        magicnet_log("%s no key attached to the block to sign with\n", __FUNCTION__);
        return -1;
    }
    res = private_sign(block->hash, sizeof(block->hash), &block->signature);
    if (res < 0)
    {
        magicnet_log("%s Failed to sign data with signature\n", __FUNCTION__);
        return -1;
    }

    return res;
}
int block_verify(struct block *block)
{
    int res = 0;
    char block_hash[SHA256_STRING_LENGTH];
    block_hash_create(block, block_hash);
    if (memcmp(block->hash, block_hash, sizeof(block_hash)) != 0)
    {
        magicnet_log("%s the hash in the block does not match the hash it should be\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Okay the hashes are correct but was this block signed by the key in the block?

    if (public_verify(&block->key, block->hash, sizeof(block->hash), &block->signature) < 0)
    {
        magicnet_log("%s block is invalid, signature did not sign this data\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // We only deal deal with transaction groups when transactions exist.
    if (block->transaction_group->total_transactions > 0)
    {
        char transaction_group_hash[SHA256_STRING_LENGTH];
        block_transaction_group_hash_create(block->transaction_group, transaction_group_hash);

        if (memcmp(transaction_group_hash, block->transaction_group->hash, sizeof(transaction_group_hash)) != 0)
        {
            magicnet_log("%s the transaction group hash is not what it should be\n", __FUNCTION__);
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
    if (group)
    {
        block->transaction_group = block_transaction_group_clone(group);
    }
    else
    {
        block->transaction_group = block_transaction_group_new();
    }
    return block;
}

struct block *block_create(struct block_transaction_group *transaction_group, const char *prev_hash)
{
    char last_hash[SHA256_STRING_LENGTH] = {0};
    struct block *block = calloc(1, sizeof(struct block));
    if (transaction_group)
    {
        block->transaction_group = block_transaction_group_clone(transaction_group);
    }
    else
    {
        block->transaction_group = block_transaction_group_new();
    }
    if (!prev_hash)
    {
        if (magicnet_database_load_last_block(last_hash, NULL) >= 0)
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
        block_transaction_group_free(block->transaction_group);
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
    char prev_hash[SHA256_STRING_LENGTH];
    int blockchain_id = -1;
    char transaction_group_hash[SHA256_STRING_LENGTH];
    struct key key;
    struct signature signature;
    res = magicnet_database_load_block(hash, prev_hash, &blockchain_id, transaction_group_hash, &key, &signature);
    if (res < 0)
    {
        goto out;
    }

    struct block_transaction_group *group = block_transaction_group_new();
    block = block_create_with_group(hash, prev_hash, group);
    block->blockchain_id = blockchain_id;
    block->key = key;
    block->signature = signature;

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
