#include "magicnet/log.h"
#include "magicnet/magicnet.h"
#include <time.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    printf("Starting MagicNet server\n");
    magicnet_log_initialize();
    int res = magicnet_database_load();
    if (res < 0)
    {
        return -1;
    }

    struct magicnet_server* server = magicnet_server_start();
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