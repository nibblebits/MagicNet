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
    magicnet_log("test");


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
    
    struct magicnet_chain_downloader* downloader = magincnet_chain_downloader_download(server, "17f3830135685dacf2c9589331bfa905618c89ac13764a2638028c1bd3bf990c");


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