#include "magicnet.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

struct magicnet_chain_downloader_peer_thread* magicnet_chain_downloader_peer_thread_for_client(struct magicnet_chain_downloader* downloader, struct magicnet_client* client)
{
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (downloader->peer_threads[i] && downloader->peer_threads[i]->client == client)
        {
            return downloader->peer_threads[i];
        }
    }
    return NULL;
}

void magicnet_chain_downloader_client_free(struct magicnet_chain_downloader* downloader, struct magicnet_client* client)
{
    struct magicnet_chain_downloader_peer_thread* thread = magicnet_chain_downloader_peer_thread_for_client(downloader, client);
    // If we have a running thread it is responsible for cleaning up the client memory not us.
    if (thread)
    {
        thread->finished = true;
        return;
    }

    magicnet_close_and_free(client);
}

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
                magicnet_chain_downloader_client_free(downloader->clients[i]);
            }

            downloader->clients[i] = client;
            res = 0;
            break;
        }
    }   
    return res;
}

int magicnet_chain_downloader_peer_thread_add(struct magicnet_chain_downloader* downloader, struct magicnet_chain_downloader_peer_thread* peer_thread)
{
    int res = -1;
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if(downloader->peer_threads[i] == NULL)
        {
            downloader->peer_threads[i] = peer_thread;
            res = 0;
            break;
        }
    }   
    return res;
}



void *magicnet_chain_downloader_peer_thread_loop(void *_peer_thread)
{
    struct magicnet_chain_downloader_peer_thread* peer_thread = _peer_thread;
    bool running = true;
    while(running)
    {
        magicnet_log("%s peer thread loop test\n", __FUNCTION__);
        sleep(1);
    }
}

int magicnet_chain_downloader_peer_create_thread(struct magicnet_chain_downloader* downloader, struct magicnet_client* client)
{
    int res = 0;
    struct magicnet_chain_downloader_peer_thread* peer_thread = calloc(1, sizeof(struct magicnet_chain_downloader_peer_thread));
    peer_thread->client = client;
    peer_thread->downloader = downloader;
    
    if (pthread_create(&peer_thread->thread_id, NULL, &magicnet_chain_downloader_peer_thread_loop, peer_thread))
    {
        magicnet_log("%s failed to start the peer download thread\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_chain_downloader_peer_thread_add(downloader, peer_thread);
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

    size_t tries = 0;
    while(magicnet_chain_downloader_connected_clients_count(downloader) < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS && tries < 10)
    {
        tries++;
         int random_index = rand() % vector_count(ip_vec);
        struct sockaddr_in* addr = vector_peek_at(ip_vec, random_index);
        struct magicnet_client* client = magicnet_tcp_network_connect(*addr, 0, "chain-downloader");
        if (client)
        {
            if(magicnet_chain_downloader_client_add(downloader, client) < 0)
            {
                magicnet_log("%s failed to add client\n", __FUNCTION__);
                magicnet_close_and_free(client);
                continue;
            }

            if(magicnet_chain_downloader_peer_create_thread(client) < 0)
            {
                magicnet_log("%s failed to start peer thread\n", __FUNCTION__);
                magicnet_close_and_free(client);
                continue;
            }

            magicnet_log("%s added a new client to the chain downloader\n", __FUNCTION__);
        }
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
        sleep(1);

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