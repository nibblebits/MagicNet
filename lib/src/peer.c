#include "magicnet.h"
#include "database.h"




int magicnet_save_peer_info(struct magicnet_peer_information *peer_info)
{
    int res = 0;
    res = magicnet_database_peer_update_or_create(peer_info);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}
