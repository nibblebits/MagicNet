#include "magicnet/log.h"
#include "magicnet/magicnet.h"
#include "magicnet/database.h"
#include "magicnet/init.h"
#include <time.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    int res = 0;
    printf("Starting MagicNet server\n");
    res = magicnet_server_init();
    if (res < 0)
    {
        printf("could not initialize the magicnet server\n");
        return res;
    }

    struct magicnet_server* server = magicnet_server_start(MAGICNET_SERVER_PORT);
    if (!server)
    {
        printf("The  magic net server could not be started\n");
        return -1;
    }
    res = magicnet_network_thread_start(server);
    if (res < 0)
    {
        printf("failed to start magic server thread\n");
        return -1;
    }
    
    res = magicnet_chain_downloaders_setup_and_poll(server);
    if (res < 0)
    {
        printf("There was a problem setting up the chain downloaders\n");
        return -1;
    }



    // Accept the clients
    while(1)
    {
        struct magicnet_client* client = magicnet_accept(server);
        if (client)
        {
            // Start the client thread.
            magicnet_client_thread_start(client);
        }

    }    
}