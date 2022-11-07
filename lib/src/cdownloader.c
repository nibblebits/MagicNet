#include "magicnet.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

size_t magicnet_chain_downloader_connected_clients_count(struct magicnet_chain_downloader* downloader)
{
    size_t count = 0;
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (magicnet_connected(downloader->clients[i]))
        {
            count++;
        }
    }

    return count;
}

int magicnet_chain_downloader_client_add(struct magicnet_chain_downloader* downloader, struct magicnet_client* client)
{
    int res = -1;
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (!magicnet_connected(downloader->clients[i]))
        {
            if (downloader->clients[i] != NULL)
            {
                magicnet_client_free(downloader->clients[i]);
            }

            downloader->clients[i] = client;
            res = 0;
        }
    }   
    return res;
}
void magicnet_chain_downloader_thread_connect_to_next_client(struct magicnet_chain_downloader* downloader)
{
    struct magicnet_server* server = downloader->server;
    struct vector* ip_vec = vector_create(sizeof(struct sockaddr_in));
    magicnet_server_lock(server);
    magicnet_server_push_outgoing_connected_ips(server, ip_vec);
    magicnet_server_unlock(server);

    if (vector_empty(ip_vec))
    {
        // Nothing we can do... The server instance has not managed to connect to anybody yet.
        // We only make new connections to clients we know are online. The server is responsible for figuring that out.
        vector_free(ip_vec);
        return;
    }

    int random_index = rand() % vector_count(ip_vec);
    struct sockaddr_in* addr = vector_peek_at(ip_vec, random_index);
    size_t count = 0;
    while(count <= magicnet_chain_downloader_connected_clients_count(downloader))
    {
        struct magicnet_client* client = magicnet_tcp_network_connect(*addr, 0, "chain-downloader");
        if (client)
        {
            if(magicnet_chain_downloader_client_add(downloader, client) == 0)
            {
                magicnet_log("%s added a new client to the chain downloader\n", __FUNCTION__);
            }
        }
        count++;
    }

    vector_free(ip_vec);
}
/**
 * This file is responsible for downloading blockchains when people lag behind.
*/
void *magicnet_chain_downloader_thread(void *_downloader)
{
    struct magicnet_chain_downloader* downloader = _downloader;
    bool running = true;
    while(running)
    {
        pthread_mutex_lock(&downloader->lock);

        if (downloader->finished)
        {
            running = false;
        }
        magicnet_chain_downloader_thread_connect_to_next_client(downloader);
        pthread_mutex_unlock(&downloader->lock);
        sleep(5);

    }
}

/**
 * Queues a download for the block with the given previous hash. Downloads the entire chain until NULL is found.
*/
struct magicnet_chain_downloader* magincnet_chain_downloader_download(struct magicnet_server* server, const char* prev_hash)
{
    struct magicnet_chain_downloader* downloader = calloc(1, sizeof(struct magicnet_chain_downloader));
    strncpy(downloader->starting_hash, prev_hash, strlen(prev_hash));
    downloader->total_blocks_downloaded = 0;
    downloader->finished = false;
    downloader->server = server;
     if (pthread_mutex_init(&downloader->lock, NULL) != 0)
    {
        magicnet_log("%s Failed to initialize the downloder lock\n", __FUNCTION__);
        return NULL;
    }

    // Let's start the thread
    pthread_t thread_id;
    pthread_mutex_lock(&downloader->lock);
    if (pthread_create(&thread_id, NULL, &magicnet_chain_downloader_thread, downloader))
    {
        magicnet_log("%s failed to start the downloader thread\n", __FUNCTION__);
        goto out;
    }
    downloader->downloader_thread_id = thread_id;

out:
    pthread_mutex_unlock(&downloader->lock);
    return downloader;
}

void magicnet_chain_downloader_finish(struct magicnet_chain_downloader* downloader)
{
    pthread_mutex_lock(&downloader->lock);
    downloader->finished = true;
    pthread_mutex_unlock(&downloader->lock);

    pthread_join(downloader->downloader_thread_id, NULL);
    free(downloader);
}