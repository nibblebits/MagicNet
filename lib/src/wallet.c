#include "magicnet/magicnet.h"
#include "key.h"
#include <memory.h>
#include <stdlib.h>

int magicnet_wallet_calculate_balance_for_request(struct magicnet_transactions_request* transactions_request, struct key* key, double* balance_out)
{
    int res = 0;
    struct block_transaction_group *group = block_transaction_group_new();
    bool done = false;
    double balance = 0;
    while (!done && (res = block_transactions_load(transactions_request, group)) >= 0)
    {
        // Lets go through the transactions and
        for (int i = 0; i < group->total_transactions; i++)
        {
            struct block_transaction_money_transfer money_transfer;
            res = magicnet_money_transfer_data(group->transactions[i], &money_transfer);
            if (res < 0)
            {
                goto out;
            }

            // Is the recipient key our key?
            if (key_cmp(key, &money_transfer.recipient_key))
            {
                balance = money_transfer.new_balances.recipient_balance;
                done = true;
            }

            // Is the transaction key our key?
            if (key_cmp(key, &group->transactions[i]->key))
            {
                balance = money_transfer.new_balances.sender_balance;
                done = true;
            }

            if (done)
            {
                break;
            }
        }
        block_transaction_group_free(group);
        group = block_transaction_group_new();
    }

    // There arent serious problems for this function.
    if (res == MAGICNET_ERROR_END_OF_STREAM || res == MAGICNET_ERROR_NOT_FOUND)
    {
        res = 0;
    }
    block_transaction_group_free(group);
    group = NULL;

out:
    *balance_out = balance;
    return res;

}
int magicnet_wallet_calculate_balance_from_block(struct key *key, double *balance_out, const char *block_hash)
{
    int res = 0;
    double balance = 0;
    size_t blocks_allowed = MAGICNET_BALANCE_CALCULATION_BLOCK_LIMIT;
    struct magicnet_transactions_request transactions_request = {};
    magicnet_transactions_request_init(&transactions_request);
    magicnet_transactions_request_set_type(&transactions_request, MAGICNET_TRANSACTION_TYPE_COIN_SEND);
    magicnet_transactions_request_set_key(&transactions_request, key);
    magicnet_transactions_request_set_flag(&transactions_request, MAGICNET_TRANSACTIONS_REQUEST_FLAG_KEY_OR_TARGET_KEY);
    magicnet_transactions_request_set_target_key(&transactions_request, key);
    magicnet_transactions_request_set_block_hash(&transactions_request, block_hash);
    return magicnet_wallet_calculate_balance_for_request(&transactions_request, key, balance_out);
   
}
int magicnet_wallet_calculate_balance(struct key *key, double *balance_out)
{
    int res = 0;
    double balance = 0;
    size_t blocks_allowed = MAGICNET_BALANCE_CALCULATION_BLOCK_LIMIT;
    struct magicnet_transactions_request transactions_request = {};
    magicnet_transactions_request_init(&transactions_request);
    magicnet_transactions_request_set_type(&transactions_request, MAGICNET_TRANSACTION_TYPE_COIN_SEND);
    magicnet_transactions_request_set_key(&transactions_request, key);
    magicnet_transactions_request_set_flag(&transactions_request, MAGICNET_TRANSACTIONS_REQUEST_FLAG_KEY_OR_TARGET_KEY);
    magicnet_transactions_request_set_target_key(&transactions_request, key);
    return magicnet_wallet_calculate_balance_for_request(&transactions_request, key, balance_out);
}

struct magicnet_wallet *magicnet_wallet_find(struct key *key)
{
    int res = 0;
    struct magicnet_wallet *wallet = NULL;
    wallet = calloc(1, sizeof(struct magicnet_wallet));
    wallet->key = *key;
    res = magicnet_wallet_calculate_balance(key, &wallet->balance);
    if (res < 0)
    {
        free(wallet);
        return NULL;
    }
    return wallet;
}

void magicnet_wallet_free(struct magicnet_wallet *wallet)
{
    free(wallet);
}