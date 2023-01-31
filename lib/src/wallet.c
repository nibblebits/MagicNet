#include "magicnet.h"
#include "key.h"
#include <memory.h>
#include <stdlib.h>

double magicnet_wallet_calculate_balance(struct key* key)
{
    struct blockchain* active_chain = magicnet_blockchain_get_active();
    if (!active_chain)
    {
        // No active chain then how can we have a wallet balance.
        return 0;
    }
    
    
    // Alright lets calculate the balance based on the previous transaction history
    // we must look back through all the blocks on the active blockchain
    // we cant rely on a transaction database search as we cant be sure of the correct chain that way

    struct block* current_block = block_load(active_chain->last_hash);
    while(current_block)
    {
        // Let's load all transactions in the block that have interactions
        // for the given keys.
        char prev_hash[SHA256_STRING_LENGTH];
        memcpy(prev_hash, active_chain->prev_hash, sizeof(prev_hash));
        // Free the block
        block_free(current_block);
        current_block = block_load(prev_hash);
    }

}

struct magicnet_wallet* magicnet_wallet_find(struct key* key)
{
    struct magicnet_wallet* wallet = NULL;
    wallet = calloc(1, sizeof(struct magicnet_wallet));
    wallet->key = *key;
    wallet->balance = magicnet_wallet_calculate_balance(key);
}

void magicnet_wallet_free(struct magicnet_wallet* wallet)
{
    free(wallet);
}