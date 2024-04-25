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
#include <stdbool.h>

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

/**
 * This function creates a new struct self_block_transaction. It is not saved into the database at this time
 */
struct self_block_transaction *block_self_transaction_new(struct block_transaction *transaction)
{
    struct self_block_transaction *self_block_transaction = calloc(1, sizeof(struct self_block_transaction));
    self_block_transaction->state = BLOCK_TRANSACTION_STATE_PENDING_SIGN_AND_SEND;
    strncpy(self_block_transaction->status_message, "Pending", sizeof(self_block_transaction->status_message));
    self_block_transaction->transaction = block_transaction_clone(transaction);
    return self_block_transaction;
}

/**
 * This function checks if the block transaction has been signed yet
 */
bool block_transaction_is_signed(struct block_transaction *transaction)
{
    struct signature blank_sig = {0};
    return memcmp(&transaction->signature, &blank_sig, sizeof(transaction->signature)) != 0;
}

/**
 * Create function that gets active blockchain
 */
struct blockchain *magicnet_blockchain_get_active()
{
    struct blockchain *blockchain = blockchain_new();
    int ret = magicnet_database_blockchain_get_active(&blockchain);
    if (ret != 0)
    {
        magicnet_log("Failed to get active blockchain\n");
        blockchain_free(blockchain);
        return NULL;
    }
    return blockchain;
}
/**
 * Returns the current active blockchain id
 */
int magicnet_blockchain_get_active_id()
{
    return magicnet_database_get_active_blockchain_id();
}

void block_transaction_vector_free(struct vector *vector)
{
    vector_set_peek_pointer(vector, 0);
    struct block_transaction *transaction = vector_peek_ptr(vector);
    while (transaction)
    {
        block_transaction_free(transaction);
        transaction = vector_peek_ptr(vector);
    }

    vector_free(vector);
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
    if (!transaction_group_in)
    {
        return NULL;
    }

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
    // Write the previous block hash, by doing this we BIND this transaction to only one blockchain
    // Preventing it from being added to other chains. And ensuring a UNIQUE hash for a transaction that guarantees
    // it is only valid on the chain it was signed on.
    buffer_write_bytes(buffer, data->prev_block_hash, sizeof(data->prev_block_hash));
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

int block_transaction_coin_transfer_valid(struct block_transaction *transaction)
{
    int res = 0;
    struct block_transaction_money_transfer money_transfer;
    res = magicnet_money_transfer_data(transaction, &money_transfer);
    if (res < 0)
    {
        goto out;
    }

    if (money_transfer.amount <= 0)
    {
        // Show error message
        magicnet_log("%s the amount is not valid\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Check that the recipient key is valid
    if (!MAGICNET_key_valid(&money_transfer.recipient_key))
    {
        magicnet_log("%s the recipient key is invalid\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Check that the recipient key is equal to the target key on the main transaction
    if (memcmp(&money_transfer.recipient_key, &transaction->target_key, sizeof(money_transfer.recipient_key)) != 0)
    {
        magicnet_log("%s the recipient key is not equal to the target key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    double sender_balance_after_send = 0;
    magicnet_wallet_calculate_balance_from_block(&transaction->key, &sender_balance_after_send, transaction->data.prev_block_hash);
    sender_balance_after_send -= money_transfer.amount;

    // Check the balances are the same
    if (sender_balance_after_send != money_transfer.new_balances.sender_balance)
    {
        magicnet_log("%s the coin transaction contains an incorrect sender balance\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    double recipient_balance_after_send = 0;
    magicnet_wallet_calculate_balance_from_block(&money_transfer.recipient_key, &recipient_balance_after_send, transaction->data.prev_block_hash);
    recipient_balance_after_send += money_transfer.amount;

    // Check the balances match
    if (recipient_balance_after_send != money_transfer.new_balances.recipient_balance)
    {
        magicnet_log("%s the coin transaction contains an incorrect recipient balance\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // TODO check the funding sources to ensure that the sender has enough funds
    // TODO check the funding sources to ensure that the sender has not already spent the funds

out:
    return res;
}

int block_transaction_valid_specified(struct block_transaction *transaction, int flags)
{
    if (transaction->data.size > MAGICNET_MAX_SIZE_FOR_TRANSACTION_DATA)
    {
        // Show error message
        magicnet_log("%s the transaction data is too large\n", __FUNCTION__);
        return -1;
    }

    // Let's see if the key is valid
    if (!MAGICNET_key_valid(&transaction->key))
    {
        magicnet_log("%s the public key is invalid\n", __FUNCTION__);
        return -1;
    }

    // Lets check to see if the target key is valid
    if (key_loaded(&transaction->target_key) && !MAGICNET_key_valid(&transaction->target_key))
    {
        magicnet_log("%s the target key is invalid\n", __FUNCTION__);
        return -1;
    }

    if (flags & MAGICNET_BLOCK_VERIFICATION_VERIFY_TRANSACTION_DATA)
    {
        if (transaction->type == MAGICNET_TRANSACTION_TYPE_COIN_SEND)
        {
            int res = block_transaction_coin_transfer_valid(transaction);
            if (res < 0)
            {
                return res;
            }
        }
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

int block_transaction_valid(struct block_transaction *transaction)
{
    return block_transaction_valid_specified(transaction, MAGICNET_BLOCK_VERIFICATION_VERIFY_ALL);
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
    bool block_has_chain = block->blockchain_id != 0;

    if (!block_has_chain && memcmp(block->prev_hash, empty_hash, sizeof(block->prev_hash)) == 0)
    {
        magicnet_log("%s new block %p adding new chain\n", __FUNCTION__, block);
        return MAGICNET_BLOCKCHAIN_TYPE_UNIQUE_CHAIN;
    }

    int res = 0;

    res = magicnet_database_count_blocks_with_previous_hash(block->prev_hash);
    if (res > 1)
    {
        // We have more than one block with the previous hash of our block.
        // This count includes the block here in this function.
        // This means we need to split the chain and our block be on the split chain
        return MAGICNET_BLOCKCHAIN_TYPE_SPLIT_CHAIN;
    }

    // Lets get the block with the previous hash
    struct block *pervious_block = block_load(block->prev_hash);
    if (pervious_block)
    {
        *blockchain_id_out = pervious_block->blockchain_id;
        block_free(pervious_block);
        return MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN;
    }

    int bco = 0;
    if (magicnet_database_load_block_from_previous_hash(block->hash, NULL, &bco, NULL, NULL, NULL) >= 0)
    {
        *blockchain_id_out = bco;
        return MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN;
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
    BLOCKCHAIN_TYPE blockchain_type = blockchain_should_create_new(block, &res);

    if (blockchain_type != MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN)
    {
        res = blockchain_create_new(block, blockchain_type);
    }
    return res;
}

void block_free_vector(struct vector *block_vec)
{
    vector_set_peek_pointer(block_vec, 0);
    struct block *block = vector_peek_ptr(block_vec);
    while (block)
    {
        block_free(block);
        block = vector_peek_ptr(block_vec);
    }
    vector_free(block_vec);
}

int blockchain_block_prepare(struct block *block)
{
    return 0;
}

void blockchain_reformat_individual_block(struct block *block)
{
    int blockchain_id = blockchain_create_new_if_required(block);
    if (blockchain_id > 0)
    {
        block->blockchain_id = blockchain_id;
    }

    magicnet_database_update_block(block);
}

int blockchain_reformat(struct block *block)
{
    int res = 0;
    blockchain_reformat_individual_block(block);

    // Reformat all the other blocks that have no chain.
    struct vector *block_vec = vector_create(sizeof(struct block *));
    while (magicnet_database_load_blocks_with_no_chain(block_vec, 10) >= 0)
    {
    }

    for (int i = 0; i < vector_count(block_vec) * 2; i++)
    {
        vector_set_peek_pointer(block_vec, 0);
        struct block *current_block = vector_peek_ptr(block_vec);
        while (current_block)
        {
            blockchain_reformat_individual_block(current_block);
            current_block = vector_peek_ptr(block_vec);
        }
    }
    block_free_vector(block_vec);
    return res;
}

int block_save_with_rules(struct block *block, int flags)
{
    int res = 0;
    if (!block)
    {
        // Null block? Could this be someone trying to exploit or a mistake of some kind..
        return MAGICNET_ERROR_SECURITY_RISK;
    }

    pthread_mutex_lock(&blockchain_lock);

    res = block_verify_specified(block, flags);
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

    res = magicnet_database_load_block(block->hash, NULL, &block->blockchain_id, NULL, NULL, NULL, NULL);
    if (res >= 0)
    {
        magicnet_log("%s the same block was sent to us twice, we will ignore this one\n", __FUNCTION__);
        blockchain_reformat(block);
        res = MAGICNET_DATA_SENT_BEFORE;
        goto out;
    }

    magicnet_council_certificate_save(block->certificate);


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

    res = blockchain_reformat(block);
    if (res < 0)
    {
        goto out;
    }

out:
    pthread_mutex_unlock(&blockchain_lock);
    return res;
}

int block_save(struct block *block)
{
    return block_save_with_rules(block, MAGICNET_BLOCK_VERIFICATION_VERIFY_ALL);
}

struct block *block_clone(struct block *block)
{

    struct block *block_cloned = block_create_with_group(block->hash, block->prev_hash, block_transaction_group_clone(block->transaction_group));
    block_cloned->certificate = magicnet_council_certificate_clone(block->certificate);
    block_cloned->blockchain_id = block->blockchain_id;
    block_cloned->time = block->time;
    return block_cloned;
}

const char *block_transaction_group_hash_create(struct block_transaction_group *group, char *hash_out)
{
    if (!group || group->total_transactions == 0)
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

    char certificate_hash[SHA256_STRING_LENGTH];
    magicnet_council_certificate_hash(block->certificate, certificate_hash);
    buffer_write_bytes(tmp_buf, certificate_hash, sizeof(certificate_hash));
    buffer_write_long(tmp_buf, block->time);
    char transaction_group_hash[SHA256_STRING_LENGTH];
    if (block_transaction_group_hash_create(block->transaction_group, transaction_group_hash))
    {
        buffer_write_bytes(tmp_buf, transaction_group_hash, sizeof(transaction_group_hash));
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

int block_hash_sign_verify(struct block *block)
{
    int res = 0;
    block_hash_create(block, block->hash);
    block_transaction_group_hash_create(block->transaction_group, block->transaction_group->hash);

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

    res = private_sign(block->hash, sizeof(block->hash), &block->signature);
    if (res < 0)
    {
        magicnet_log("%s Failed to sign data with signature\n", __FUNCTION__);
        return -1;
    }

    return res;
}

int block_verify_timestamp(struct block *block)
{
    int res = 0;
    // TODO Verify the block time is fair.
    return res;
}

int block_verify_specified(struct block *block, int flags)
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

    if (flags & MAGICNET_BLOCK_VERIFICATION_VERIFY_TIMESTAMP)
    {
        res = block_verify_timestamp(block);
        if (res < 0)
        {
            magicnet_log("%s the timestamp for the block cannot be real. The block is rejected.\n", __FUNCTION__);
            res = -1;
            goto out;
        }
    }

    // Okay the hashes are correct but was this block signed by the key in the block?
    if (flags & MAGICNET_BLOCK_VERIFICATION_VERIFY_SIGNATURE)
    {
        // Verify the certificate is apart of the central council and is valid.
        if (magicnet_central_council_certificate_verify(block->certificate) < 0)
        {
            magicnet_log("%s the council certificate could not be verified for the given block\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        if (public_verify(&block->certificate->owner_key, block->hash, sizeof(block->hash), &block->signature) < 0)
        {
            magicnet_log("%s block is invalid, signature did not sign this data\n", __FUNCTION__);
            res = -1;
            goto out;
        }
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
        if (flags & MAGICNET_BLOCK_VERIFICATION_VERIFY_TRANSACTIONS)
        {
            for (int i = 0; i < block->transaction_group->total_transactions; i++)
            {
                struct block_transaction *transaction = block->transaction_group->transactions[i];
                res = block_transaction_valid_specified(transaction, flags);
                if (res < 0)
                {
                    goto out;
                }

                // Though the transaction may be valid its also essential that all the transactions have a prev block hash
                // that point to our previous hash
                if (memcmp(transaction->data.prev_block_hash, block->prev_hash, sizeof(block->prev_hash)) != 0)
                {
                    magicnet_log("%s A transaction within this block was not made for this block\n", __FUNCTION__);
                    res = -1;
                    goto out;
                }
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

int block_verify(struct block *block)
{
    return block_verify_specified(block, MAGICNET_BLOCK_VERIFICATION_VERIFY_ALL);
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
    if (!group)
    {
        block->transaction_group = block_transaction_group_new();
    }
    return block;
}

struct block *block_create(struct block_transaction_group *transaction_group, const char *prev_hash)
{
    char last_hash[SHA256_STRING_LENGTH] = {0};
    struct block *block = calloc(1, sizeof(struct block));
    block->time = time(NULL);
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

    if (block->certificate)
    {
        magicnet_council_certificate_free(block->certificate);
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

struct block_transaction *block_transaction_load(const char *transaction_hash)
{
    struct block_transaction *transaction = NULL;
    magicnet_database_load_block_transaction(transaction_hash, &transaction);
    return transaction;
}

bool block_transactions_empty(struct block *block)
{
    return block->transaction_group->total_transactions == 0;
}

// This function loads transactions from a struct magicnet_transactions_request into a struct block_transaction_group
int block_transactions_load(struct magicnet_transactions_request *request, struct block_transaction_group *transaction_group)
{
    int res = 0;
    struct blockchain *active_chain = NULL;
    struct block *last_block = NULL;
    struct block *current_block = NULL;
    struct block *tmp_block = NULL;

    // If we have the transaction group hash set and the block hash set then this is an error
    if (!sha256_empty(request->transaction_group_hash) && !sha256_empty(request->block_hash))
    {
        // We cant have the block hash set and the transaction group hash set because if the transaction group hash is set
        // then we must only load the transactions for that group hash.
        return MAGICNET_ERROR_INVALID_PARAMETERS;
    }

    // Do we have a transaction group hash in the filter request? If not then we will follow the chain downwards to ensure that the chain
    // is maintained. If we do have a transaction group hash then we will load the transactions from that group hash.
    if (!sha256_empty(request->transaction_group_hash))
    {
        // Not empty? Great! We will load the transactions from that group hash.
        res = magicnet_database_load_transactions(request, transaction_group);
        return res;
    }

    // No block hash? then we should load the last block hash.
    if (sha256_empty(request->block_hash))
    {
        // We have no transaction group hash. We will load the transactions from the block hash.
        // Get last blockchain
        active_chain = magicnet_blockchain_get_active();
        if (!active_chain)
        {
            magicnet_log("%s cannot load transactions when no active blockchain exists\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        // Lets load the last block from the active chain
        last_block = block_load(active_chain->last_hash);
        if (!last_block)
        {
            magicnet_log("%s cannot load transactions when no last block exists\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        current_block = last_block;
    }
    else
    {
        current_block = block_load(request->block_hash);
    }

    if (!current_block)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    block_load_fully(current_block);
    // Do we have a transaction group hash in this block?
    if (block_transactions_empty(current_block))
    {
        goto out;
    }

    // We have transactions in this block. Lets load them.
    magicnet_transactions_request_remove_block_hash(request);
    magicnet_transactions_request_set_transaction_group_hash(request, current_block->transaction_group->hash);
    res = magicnet_database_load_transactions(request, transaction_group);
    if (res < 0 && res != MAGICNET_ERROR_NOT_FOUND)
    {
        magicnet_log("%s failed to load transactions from block %s\n", __FUNCTION__, current_block->hash);
        goto out;
    }
out:
    magicnet_transactions_request_remove_transaction_group_hash(request);
    magicnet_transactions_request_remove_block_hash(request);
    if (current_block)
    {
        if (sha256_empty(current_block->prev_hash))
        {
            res = MAGICNET_ERROR_END_OF_STREAM;
        }
        else
        {
            magicnet_transactions_request_set_block_hash(request, current_block->prev_hash);
        }
        block_free(current_block);
    }

    if (active_chain)
    {
        blockchain_free(active_chain);
    }
    return res;
}

int block_load_transactions(struct block *block)
{
    int res = 0;
    if (!block->transaction_group)
    {
        magicnet_log("%s cannot load block transactions when a transaction group does not exist\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (block->transaction_group->total_transactions > 0)
    {
        magicnet_log("%s cannot load block transactions when a transaction group already has transactions. Likely already loaded or modified. Must load transactions FIRST!\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    res = magicnet_database_load_block_transactions(block);
out:
    return res;
}

int block_load_fully(struct block *block)
{
    int res = 0;

    res = block_load_transactions(block);
    if (res == MAGICNET_ERROR_NOT_FOUND)
    {
        // This isnt a critical error.. Res is okay. This block just has no transactions
        res = 0;
    }

    return res;
}

struct block *block_load(const char *hash)
{
    int res = 0;
    struct block *block = NULL;
    FILE *block_fp = NULL;
    char prev_hash[SHA256_STRING_LENGTH];
    int blockchain_id = -1;
    char transaction_group_hash[SHA256_STRING_LENGTH];
    char signing_certificate_hash[SHA256_STRING_LENGTH];
    struct signature signature;
    time_t created_time;
    res = magicnet_database_load_block(hash, prev_hash, &blockchain_id, transaction_group_hash, signing_certificate_hash, &signature, &created_time);
    if (res < 0)
    {
        goto out;
    }

    struct block_transaction_group *group = block_transaction_group_new();
    memcpy(group->hash, transaction_group_hash, sizeof(group->hash));
    block = block_create_with_group(hash, prev_hash, group);
    block->blockchain_id = blockchain_id;
    block->certificate = magicnet_council_certificate_load(signing_certificate_hash);
    if (!block->certificate)
    {
        magicnet_log("%s failed to load certificate for block %s\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }
    block->signature = signature;
    block->time = created_time;

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
