#include "magicnet.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

struct magicnet_chain_downloader_peer_thread *magicnet_chain_downloader_peer_thread_for_client(struct magicnet_chain_downloader *downloader, struct magicnet_client *client)
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

/**
 * Removes the peer thread from the downloader. Does not free memory. Removed thread can still be used.
 */
void magicnet_chain_downloader_peer_thread_remove(struct magicnet_chain_downloader *downloader, struct magicnet_chain_downloader_peer_thread *thread)
{
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (downloader->peer_threads[i] == thread)
        {
            downloader->peer_threads[i] = NULL;
        }
    }

}

void magicnet_chain_downloader_client_free(struct magicnet_chain_downloader *downloader, struct magicnet_client *client)
{
    struct magicnet_chain_downloader_peer_thread *thread = magicnet_chain_downloader_peer_thread_for_client(downloader, client);
    // If we have a running thread it is responsible for cleaning up the client memory not us.
    if (thread)
    {
        thread->finished = true;
        return;
    }

    magicnet_close_and_free(client);
}

size_t magicnet_chain_downloader_connected_clients_count(struct magicnet_chain_downloader *downloader)
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

int magicnet_chain_downloader_client_add(struct magicnet_chain_downloader *downloader, struct magicnet_client *client)
{
    int res = -1;
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (!magicnet_connected(downloader->clients[i]))
        {
            if (downloader->clients[i] != NULL)
            {
                magicnet_chain_downloader_client_free(downloader, downloader->clients[i]);
            }

            downloader->clients[i] = client;
            res = 0;
            break;
        }
    }
    return res;
}

int magicnet_chain_downloader_peer_thread_add(struct magicnet_chain_downloader *downloader, struct magicnet_chain_downloader_peer_thread *peer_thread)
{
    int res = -1;
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (downloader->peer_threads[i] == NULL)
        {
            downloader->peer_threads[i] = peer_thread;
            res = 0;
            break;
        }
    }
    return res;
}

bool magicnet_chain_downloader_accepted_packet(struct magicnet_packet* packet)
{
    return packet && (magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_BLOCK_SEND ||
         magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND);
}

int magicnet_chain_downloader_peer_thread_loop_packet_exchange_protocol(struct magicnet_chain_downloader_peer_thread *peer_thread, struct magicnet_packet *send_packet, struct magicnet_packet *recv_packet)
{
    int res = 0;
    magicnet_signed_data(send_packet)->flags = MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    strncpy(magicnet_signed_data(send_packet)->payload.request_block.prev_hash, peer_thread->downloader->request_hash, sizeof(magicnet_signed_data(send_packet)->payload.request_block.prev_hash));
    res = magicnet_client_write_packet(peer_thread->client, send_packet, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        magicnet_log("%s failed to write request block packet\n", __FUNCTION__);
        goto out;
    }

    // Lets get a response packet
    res = magicnet_client_read_packet(peer_thread->client, recv_packet);
    if (res < 0)
    {
        magicnet_log("%s failed to read response packet\n", __FUNCTION__);
        goto out;
    }

    if (!magicnet_chain_downloader_accepted_packet(recv_packet))
    {
        magicnet_log("%s we was sent a packet we did not expect..\n", __FUNCTION__);
        res = -1;
        goto out;
    }

out:
    return res;
}

int magicnet_chain_downloader_peer_thread_loop_packet_exchange(struct magicnet_chain_downloader_peer_thread *thread, struct magicnet_packet *send_packet, struct magicnet_packet *recv_packet)
{
    int res = 0;
    res = magicnet_chain_downloader_peer_thread_loop_packet_exchange(thread, send_packet, recv_packet);
    if (res < 0)
    {
        magicnet_log("%s issue exchanging the packet\n", __FUNCTION__);
        goto out;
    }

    // Okay we have the received packet.. It should be a not found or a block send
    if (magicnet_signed_data(recv_packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND)
    {
        magicnet_log("%s this peer isnt aware of the hash we are looking for..\n", __FUNCTION__);
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    // This must be a block packet
    if (magicnet_signed_data(recv_packet)->type != MAGICNET_PACKET_TYPE_BLOCK_SEND)
    {
        magicnet_log("%s we was not expecting the packet provided we want a block send packet\n", __FUNCTION__);
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    magicnet_log("%s downloaded block\n", __FUNCTION__);

out:
    return res;
}
void *magicnet_chain_downloader_peer_thread_loop(void *_peer_thread)
{
    struct magicnet_chain_downloader_peer_thread *peer_thread = _peer_thread;
    bool running = true;
    while (running)
    {
        struct magicnet_packet *send_packet = magicnet_packet_new();
        struct magicnet_packet *recv_packet = magicnet_packet_new();
        pthread_mutex_lock(&peer_thread->downloader->lock);
        magicnet_chain_downloader_peer_thread_loop_packet_exchange(peer_thread, send_packet, recv_packet);
        // Check the thread has not been terminated.
        // We should have a seperate lock for the peer.. Hesitant as i dont want to make a deadlock but neccessary.
        running = !peer_thread->finished;
        pthread_mutex_unlock(&peer_thread->downloader->lock);

        magicnet_free_packet(send_packet);
        magicnet_free_packet(recv_packet);
    }

    magicnet_close_and_free(peer_thread->client);
    magicnet_chain_downloader_peer_thread_remove(peer_thread->downloader, peer_thread);
    free(peer_thread);
}

void magicnet_chain_downloader_peer_thread_stop(struct magicnet_chain_downloader_peer_thread *peer_thread)
{
    // Local variable as the peer thread will free its own memory when it leaves scope.
    pthread_t thread_id = -1;
    pthread_mutex_lock(&peer_thread->downloader->lock);
    peer_thread->finished = true;
    thread_id = peer_thread->thread_id;
    pthread_mutex_unlock(&peer_thread->downloader->lock);

    pthread_join(thread_id, NULL);
}

int magicnet_chain_downloader_peer_create_thread(struct magicnet_chain_downloader *downloader, struct magicnet_client *client)
{
    int res = 0;
    struct magicnet_chain_downloader_peer_thread *peer_thread = calloc(1, sizeof(struct magicnet_chain_downloader_peer_thread));
    peer_thread->client = client;
    peer_thread->downloader = downloader;

    if (pthread_create(&peer_thread->thread_id, NULL, &magicnet_chain_downloader_peer_thread_loop, peer_thread))
    {
        magicnet_log("%s failed to start the peer download thread\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    res = magicnet_chain_downloader_peer_thread_add(downloader, peer_thread);
    while(1)
    {
        sleep(1);
    }
out:
    if (res < 0)
    {
        magicnet_log("%s problem adding thread freeing\n", __FUNCTION__);
        free(peer_thread);
    }
    return res;
}
void magicnet_chain_downloader_thread_connect_to_next_client(struct magicnet_chain_downloader *downloader)
{
    struct magicnet_server *server = downloader->server;
    struct vector *ip_vec = vector_create(sizeof(struct sockaddr_in));
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
    while (magicnet_chain_downloader_connected_clients_count(downloader) < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS && tries < 10)
    {
        tries++;
        int random_index = rand() % vector_count(ip_vec);
        struct sockaddr_in *addr = vector_peek_at(ip_vec, random_index);
        // Our new client will not accept relayed packets as we just want to ask and then get. No relayed stuff..
        struct magicnet_client *client = magicnet_tcp_network_connect(*addr, 0, MAGICNET_COMMUNICATION_FLAG_NO_RELAYED_PACKETS, "chain-downloader");
        if (client)
        {
            if (magicnet_chain_downloader_client_add(downloader, client) < 0)
            {
                magicnet_log("%s failed to add client\n", __FUNCTION__);
                magicnet_close_and_free(client);
                continue;
            }

            if (magicnet_chain_downloader_peer_create_thread(downloader, client) < 0)
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
    struct magicnet_chain_downloader *downloader = _downloader;
    bool running = true;
    while (running)
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
struct magicnet_chain_downloader *magincnet_chain_downloader_download(struct magicnet_server *server, const char *prev_hash)
{
    struct magicnet_chain_downloader *downloader = calloc(1, sizeof(struct magicnet_chain_downloader));
    strncpy(downloader->starting_hash, prev_hash, sizeof(downloader->starting_hash));
    strncpy(downloader->request_hash, prev_hash, sizeof(downloader->request_hash));

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

void magicnet_chain_downloader_finish(struct magicnet_chain_downloader *downloader)
{
    pthread_mutex_lock(&downloader->lock);
    downloader->finished = true;
    pthread_mutex_unlock(&downloader->lock);

    pthread_join(downloader->downloader_thread_id, NULL);
    free(downloader);
}