#include "magicnet.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include "database.h"

void magicnet_downloads_remove(struct magicnet_chain_downloader *downloader);

static struct magicnet_active_chain_downloads downloads;
int magicnet_chain_downloaders_setup_and_poll(struct magicnet_server *server)
{
    int res = 0;
    bzero(&downloads, sizeof(downloads));
    if (pthread_mutex_init(&downloads.lock, NULL) != 0)
    {
        magicnet_log("%s Failed to initialize the downloder lock\n", __FUNCTION__);
        goto out;
    }

    downloads.chain_downloads = vector_create(sizeof(struct magicnet_chain_downloader *));

    struct vector* blocks_to_download = vector_create(sizeof(struct block*));
    while(magicnet_database_load_blocks_with_no_chain(blocks_to_download, 1) >= 0)
    {
        struct block* prev_block = vector_back_ptr(blocks_to_download);
        if (prev_block)
        {
            magicnet_chain_downloader_download(server, prev_block->prev_hash);
        }
    }

    block_free_vector(blocks_to_download);
out:
    return res;
}

void magicnet_chain_downloader_peer_thread_free(struct magicnet_chain_downloader_peer_thread *thread)
{
    free(thread);
}

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
    magicnet_close_and_free(client);
}

void magicnet_chain_downloader_peer_thread_finish(struct magicnet_chain_downloader_peer_thread *thread)
{
    thread->finished = true;
}
void magicnet_chain_downloader_free(struct magicnet_chain_downloader *downloader)
{
    free(downloader);
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

/**
 * Removes a client from the downloader. Does not close or free the client.. Just removes its association with the downloader.
 */
int magicnet_chain_downloader_client_remove(struct magicnet_chain_downloader *downloader, struct magicnet_client *client)
{
    if (!client)
    {
        return -1;
    }

    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (downloader->clients[i] == client)
        {
            downloader->clients[i] = NULL;
        }
    }

    return 0;
}
int magicnet_chain_downloader_client_add(struct magicnet_chain_downloader *downloader, struct magicnet_client *client)
{
    int res = -1;
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        if (!downloader->clients[i])
        {
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

bool magicnet_chain_downloader_accepted_packet(struct magicnet_packet *packet)
{
    return packet && (magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_BLOCK_SEND ||
                      magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND);
}

int magicnet_chain_downloader_peer_thread_loop_packet_exchange_protocol(struct magicnet_chain_downloader_peer_thread *peer_thread, struct magicnet_packet *send_packet, struct magicnet_packet *recv_packet)
{
    int res = 0;
    magicnet_signed_data(send_packet)->flags = MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(send_packet)->type = MAGICNET_PACKET_TYPE_REQUEST_BLOCK;
    strncpy(magicnet_signed_data(send_packet)->payload.request_block.request_hash, peer_thread->downloader->request_hash, sizeof(magicnet_signed_data(send_packet)->payload.request_block.request_hash));
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
    res = magicnet_chain_downloader_peer_thread_loop_packet_exchange_protocol(thread, send_packet, recv_packet);
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

out:
    return res;
}

int magicnet_chain_downloader_peer_thread_loop_save_block_from_packet(struct magicnet_chain_downloader_peer_thread *peer_thread, struct magicnet_packet *recv_packet)
{
    int res = 0;
    bool download_completed = false;
    pthread_mutex_lock(&peer_thread->downloader->lock);
    // We have a packet
    if (vector_count(magicnet_signed_data(recv_packet)->payload.block_send.blocks) != 1)
    {
        magicnet_log("%s we was expecting just one block invalid amount of blocks sent\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    struct block *block = vector_back_ptr(magicnet_signed_data(recv_packet)->payload.block_send.blocks);
    if (strncmp(block->hash, peer_thread->downloader->request_hash, sizeof(block->hash)) != 0)
    {
        magicnet_log("%s The block sent was not the one we was expecting\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Alright we got the block lets save it
    res = block_save(block);
    if (res < 0)
    {
        goto out;
    }

    if (res == MAGICNET_BLOCK_SENT_BEFORE)
    {
        magicnet_log("%s we actually finished downloading the chain as we have a block that we already own\n", __FUNCTION__);
        download_completed = true;
    }
    magicnet_log("%s saved block %s\n", __FUNCTION__, block->hash);

    // Now the request hash must change
    strncpy(peer_thread->downloader->request_hash, block->prev_hash, sizeof(peer_thread->downloader->request_hash));
    peer_thread->downloader->total_blocks_downloaded++;

    if (sha256_empty(block->prev_hash))
    {
        download_completed = true;
    }

    if (download_completed)
    {
        // Finished downloading?
        res = MAGICNET_TASK_COMPLETE;
        peer_thread->downloader->download_completed = true;
    }
out:
    pthread_mutex_unlock(&peer_thread->downloader->lock);
    return res;
}
void *magicnet_chain_downloader_peer_thread_loop(void *_peer_thread)
{
    struct magicnet_chain_downloader_peer_thread *peer_thread = _peer_thread;
    struct magicnet_chain_downloader *downloader = peer_thread->downloader;
    bool running = true;
    while (running)
    {
        struct magicnet_packet *send_packet = magicnet_packet_new();
        struct magicnet_packet *recv_packet = magicnet_packet_new();
        int res = magicnet_chain_downloader_peer_thread_loop_packet_exchange(peer_thread, send_packet, recv_packet);
        if (res < 0)
        {
            magicnet_log("%s failed packet exchange we will terminate the client\n", __FUNCTION__);
            goto loop_end;
        }

        res = magicnet_chain_downloader_peer_thread_loop_save_block_from_packet(peer_thread, recv_packet);
        if (res == MAGICNET_TASK_COMPLETE)
        {
            // We are done downloading the chain.
            running = false;
        }
    loop_end:
        if (res < 0 || !running)
        {
            pthread_mutex_lock(&downloader->lock);
            running = false;
            peer_thread->finished = true;
            pthread_mutex_unlock(&downloader->lock);
        }
        else
        {
            pthread_mutex_lock(&downloader->lock);
            // Check the thread has not been terminated.
            // We should have a seperate lock for the peer.. Hesitant as i dont want to make a deadlock but neccessary.
            running = !peer_thread->finished;
            if (downloader->finished)
            {
                // Downloader finished? Then we are also done
                peer_thread->finished = true;
                running = false;
            }
            pthread_mutex_unlock(&downloader->lock);
        }

        magicnet_free_packet(send_packet);
        magicnet_free_packet(recv_packet);
    }

    pthread_mutex_lock(&downloads.lock);
    magicnet_downloads_remove(downloader);
    pthread_mutex_unlock(&downloads.lock);

    pthread_mutex_lock(&downloader->lock);
    magicnet_chain_downloader_client_remove(downloader, peer_thread->client);
    magicnet_close_and_free(peer_thread->client);
    magicnet_chain_downloader_peer_thread_remove(downloader, peer_thread);
    magicnet_chain_downloader_peer_thread_free(peer_thread);
    pthread_mutex_unlock(&downloader->lock);
    return NULL;
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
out:
    if (res < 0)
    {
        magicnet_log("%s problem adding thread freeing\n", __FUNCTION__);
        magicnet_chain_downloader_peer_thread_free(peer_thread);
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

        if (downloader->finished || downloader->download_completed)
        {
            downloader->finished = true;
            running = false;
            goto loop_out;
        }
        magicnet_chain_downloader_thread_connect_to_next_client(downloader);

    loop_out:
        pthread_mutex_unlock(&downloader->lock);
        sleep(1);
    }

    magicnet_log("%s ended downloader thread\n", __FUNCTION__);
}

void magicnet_downloads_add(struct magicnet_chain_downloader *downloader)
{
    vector_push(downloads.chain_downloads, &downloader);
}

void magicnet_downloads_remove(struct magicnet_chain_downloader *downloader)
{
    vector_set_peek_pointer(downloads.chain_downloads, 0);
    struct magicnet_chain_downloader *current_downloader = vector_peek_ptr(downloads.chain_downloads);
    while (current_downloader)
    {
        if (current_downloader == downloader)
        {
            vector_pop_last_peek(downloads.chain_downloads);
            break;
        }
        current_downloader = vector_peek_ptr(downloads.chain_downloads);
    }
}
/**
 * Queues a download for the block with the given previous hash. Downloads the entire chain until NULL is found.
 */
struct magicnet_chain_downloader *magicnet_chain_downloader_download(struct magicnet_server *server, const char *request_hash, pthread_t *thread_id_out)
{
    struct magicnet_chain_downloader *downloader = calloc(1, sizeof(struct magicnet_chain_downloader));
    strncpy(downloader->starting_hash, request_hash, sizeof(downloader->starting_hash));
    strncpy(downloader->request_hash, request_hash, sizeof(downloader->request_hash));

    downloader->total_blocks_downloaded = 0;
    downloader->finished = false;
    downloader->server = server;
    if (pthread_mutex_init(&downloader->lock, NULL) != 0)
    {
        magicnet_log("%s Failed to initialize the downloder lock\n", __FUNCTION__);
        return NULL;
    }
    pthread_mutex_lock(&downloads.lock);
    magicnet_downloads_add(downloader);
    pthread_mutex_unlock(&downloads.lock);

    // Let's start the thread
    pthread_t thread_id = 0;
    pthread_mutex_lock(&downloader->lock);
    if (pthread_create(&thread_id, NULL, &magicnet_chain_downloader_thread, downloader))
    {
        magicnet_log("%s failed to start the downloader thread\n", __FUNCTION__);
        goto out;
    }

    downloader->downloader_thread_id = thread_id;
    if (thread_id_out)
    {
        *thread_id_out = thread_id;
    }
out:
    pthread_mutex_unlock(&downloader->lock);
    return downloader;
}

void magicnet_chain_downloader_finish(struct magicnet_chain_downloader *downloader)
{
    pthread_mutex_lock(&downloader->lock);
    downloader->finished = true;
    pthread_mutex_unlock(&downloader->lock);

    // Wait for all the peers to end..
    for (int i = 0; i < MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS; i++)
    {
        pthread_t peer_thread_id = -1;
        pthread_mutex_lock(&downloader->lock);
        if (downloader->peer_threads[i])
        {
            peer_thread_id = downloader->peer_threads[i]->thread_id;
        }
        pthread_mutex_unlock(&downloader->lock);

        if (peer_thread_id == -1)
        {
            continue;
        }

        pthread_join(peer_thread_id, NULL);
    }

    // Wait for the downloader thread to end.
    pthread_join(downloader->downloader_thread_id, NULL);
    pthread_mutex_destroy(&downloader->lock);
    free(downloader);
    magicnet_log("%s downloaded freed\n", __FUNCTION__);
}

int magicnet_chain_downloader_download_and_wait(struct magicnet_server *server, const char *request_hash)
{
    int res = 0;
    pthread_t thread_id = -1;
    struct magicnet_chain_downloader *downloader = magicnet_chain_downloader_download(server, request_hash, &thread_id);
    if (!downloader)
    {
        return -1;
    }

    // Let's wait until the thread is done.
    pthread_join(thread_id, NULL);
    magicnet_chain_downloader_finish(downloader);

    return res;
}