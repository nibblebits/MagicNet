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
 * Function that returns the money a peer has uses the default current active blockchain 
*/
int magicnet_peer_get_money(struct magicnet_peer_information* peer)
{
    return magicnet_peer_get_money_for_chain(peer, magicnet_database_get_active_blockchain_id());
}