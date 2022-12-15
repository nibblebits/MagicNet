/*
 * This file holds functions that are used to determine if a peer or ip address is banned from this server/peer
*/

#include "magicnet.h"
#include "database.h"

/**
 * This function checks if the ip address is banned 
 * It uses the database functions as specified in database.h to check if the ip address is banned. 
 * @param ip_address The ip address to check
 * @return bool
*/
bool magicnet_peer_ip_is_banned(const char *ip_address)
{
    struct magicnet_banned_peer_information peer_info;
    if (magicnet_database_banned_peer_load_by_ip(ip_address, &peer_info) == 0)
    {
        return true;
    }
    return false;
}