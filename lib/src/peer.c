#include "magicnet.h"
#include "database.h"
/**
 * Function that returns the money a peer has
*/
int magicnet_peer_get_money_for_chain(struct magicnet_peer_information* peer, int blockchain_id)
{

    struct magicnet_peer_blockchain_info info;
    int ret = magicnet_database_magicnet_peer_blockchain_info_get(&peer->key, blockchain_id, &info);
    if(ret != 0)
    {
        return -1;
    }
    return info.money;

}


/**
 * This function calculates the startup money for a peer. 
 * All peers will start with nothing except the genesis key which will start with around 1 million coins.
 * 
*/
double magicnet_peer_startup_money(struct magicnet_peer_information *info)
{
    double money = 0;

    // Is the key the genesis key? If so the startup money will be the genesis money
    if (MAGICNET_is_genesis_key(&info->key))
    {
        money = MAGICNET_GENESIS_STARTING_MONEY;
    }

    return money;
}

int magicnet_peer_blockchain_info_create(struct magicnet_peer_information *info)
{
    int res = 0;
    // We need to first check if theirs a key in the info. If theres not then we know too little information to make blockchain information
    // right now
    if (info->key.key == NULL)
    {
        res = -1;
        goto out;
    }

    // We need to check if the peer has a blockchain info for the active blockchain
    struct magicnet_peer_blockchain_info blockchain_info;
    res = magicnet_database_magicnet_peer_blockchain_info_get(&info->key, magicnet_database_get_active_blockchain_id(), &blockchain_info);
    if (res < 0 && res != MAGICNET_ERROR_NOT_FOUND)
    {
        goto out;
    }
    
    if (res == MAGICNET_ERROR_NOT_FOUND)
    {
        // Calculate the money to create for the new peer
        int money = magicnet_peer_startup_money(info);

        // If the peer does not have a blockchain info for the active blockchain then we need to create one
        res = magicnet_database_magicnet_peer_blockchain_info_add(&info->key, magicnet_database_get_active_blockchain_id(),  money);
        if (res < 0)
        {
            goto out;
        }
    }

out:
    return res;
}

int magicnet_save_peer_info(struct magicnet_peer_information *peer_info)
{
    int res = 0;
    res = magicnet_database_peer_update_or_create(peer_info);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_peer_blockchain_info_create(peer_info);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}


/**
 * Function that returns the money a peer has uses the default current active blockchain 
*/
int magicnet_peer_get_money(struct magicnet_peer_information* peer)
{
    return magicnet_peer_get_money_for_chain(peer, magicnet_database_get_active_blockchain_id());
}