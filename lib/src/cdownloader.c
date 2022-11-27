#include "magicnet.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include "database.h"

void magicnet_downloads_remove(struct magicnet_chain_downloader *downloader);
void magicnet_chain_downloader_free_general_data(struct magicnet_chain_downloader *downloader);

static struct magicnet_active_chain_downloads downloads;
static struct magicnet_chain_downloader *default_downloader = NULL;

void magicnet_chain_downloader_finish(struct magicnet_chain_downloader *downloader)
{
    pthread_t thread_id = -1;
    pthread_mutex_lock(&downloads.lock);
    downloader->finished = true;
    thread_id = downloader->thread_id;
    pthread_mutex_unlock(&downloads.lock);

    pthread_join(thread_id, NULL);

    pthread_mutex_lock(&downloads.lock);
    magicnet_downloads_remove(downloader);
    if (downloader == default_downloader)
    {
        default_downloader = NULL;
    }
    magicnet_chain_downloader_free_general_data(downloader);
    free(downloader);
    pthread_mutex_unlock(&downloads.lock);
}

int magicnet_chain_downloader_shutdown_last()
{
    pthread_t thread_id;
    struct magicnet_chain_downloader *downloader = NULL;
    pthread_mutex_lock(&downloads.lock);
    downloader = vector_back_ptr_or_null(downloads.chain_downloads);
    if (!downloader)
    {
        return -1;
        pthread_mutex_unlock(&downloads.lock);
    }
    pthread_mutex_unlock(&downloads.lock);

    magicnet_chain_downloader_finish(downloader);

    return 0;
}
void magicnet_chain_downloaders_shutdown()
{
    magicnet_log("%s terminating downloaders please wait..\n", __FUNCTION__);

    size_t count = 0;
    while (magicnet_chain_downloader_shutdown_last() >= 0)
    {
        magicnet_log("%s ended a chain downloader\n", __FUNCTION__);
        count++;
    }

    vector_free(downloads.chain_downloads);
    magicnet_log("%s ended %i chain downloader threads\n", __FUNCTION__, count);

    magicnet_log("%s downloaders terminated\n", __FUNCTION__);
}

bool magicnet_default_downloader_is_hash_queued_no_locks(const char *hash)
{
    // No default downloader instance right now.
    if (!default_downloader)
    {
        return false;
    }

    vector_set_peek_pointer(default_downloader->hashes_to_download, 0);
    struct magicnet_chain_downloader_hash_to_download *hash_to_download = vector_peek_ptr(default_downloader->hashes_to_download);
    while (hash_to_download)
    {
        if (memcmp(hash_to_download->hash, hash, sizeof(hash_to_download->hash)) == 0)
        {
            return true;
        }
        hash_to_download = vector_peek_ptr(default_downloader->hashes_to_download);
    }

    return false;
}
bool magicnet_default_downloader_is_hash_queued(const char *hash)
{
    bool res = false;
    pthread_mutex_lock(&downloads.lock);
    if (!default_downloader)
    {
        pthread_mutex_unlock(&downloads.lock);
        return NULL;
    }
    res = magicnet_default_downloader_is_hash_queued_no_locks(hash);
    pthread_mutex_unlock(&downloads.lock);
    return res;
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

void magicnet_chain_downloader_remove_hash(struct magicnet_chain_downloader *downloader, struct block *block)
{
    vector_set_peek_pointer(downloader->hashes_to_download, 0);
    struct magicnet_chain_downloader_hash_to_download *hash = vector_peek_ptr(downloader->hashes_to_download);
    while (hash)
    {
        if (memcmp(hash->hash, block->hash, sizeof(hash->hash)) == 0)
        {
            vector_pop_last_peek(downloader->hashes_to_download);
            free(hash);
            break;
        }
    }
}

void magicnet_chain_downloaders_remove_hash_no_locks(struct block *block)
{
    vector_set_peek_pointer(downloads.chain_downloads, 0);
    struct magicnet_chain_downloader *downloader = vector_peek_ptr(downloads.chain_downloads);
    while (downloader)
    {
        magicnet_chain_downloader_remove_hash(downloader, block);
        downloader = vector_peek_ptr(downloads.chain_downloads);
    }
}

void magicnet_chain_downloaders_remove_hash(struct block *block)
{
    pthread_mutex_lock(&downloads.lock);
    magicnet_chain_downloaders_remove_hash_no_locks(block);
    pthread_mutex_unlock(&downloads.lock);
}
void magicnet_chain_downloader_blocks_catchup(struct magicnet_server *server)
{

    struct vector *blocks_to_download = vector_create(sizeof(struct block *));
    while (magicnet_database_load_blocks_with_no_chain(blocks_to_download, 1) >= 0)
    {
        struct block *prev_block = vector_back_ptr(blocks_to_download);
        if (prev_block && !sha256_empty(prev_block->prev_hash))
        {
            magicnet_chain_downloader_queue_for_block_download(prev_block->prev_hash);
        }
    }

    block_free_vector(blocks_to_download);
}
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

    // The default downloader will always be running, we can push hashes we want at any time and it will resolve them.
    default_downloader = magicnet_chain_downloader_download(server);
    if (!default_downloader)
    {
        magicnet_log("%s could not create downloader instance\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    magicnet_chain_downloader_blocks_catchup(server);

    magicnet_chain_downloader_start(default_downloader);
out:
    return res;
}

void magicnet_chain_downloader_free_general_data(struct magicnet_chain_downloader *downloader)
{
    vector_set_peek_pointer(downloader->hashes_to_download, 0);
    struct magicnet_chain_downloader_hash_to_download *hash = vector_peek_ptr(downloader->hashes_to_download);
    while (hash)
    {
        free(hash);
        hash = vector_peek_ptr(downloader->hashes_to_download);
    }

    vector_free(downloader->hashes_to_download);
}

bool magicnet_chain_downloader_accepted_packet(struct magicnet_packet *packet)
{
    return packet && (magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_BLOCK_SEND ||
                      magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND);
}

struct magicnet_chain_downloader *magicnet_chain_downloader_download(struct magicnet_server *server)
{
    struct magicnet_chain_downloader *downloader = calloc(1, sizeof(struct magicnet_chain_downloader));
    downloader->server = server;
    downloader->hashes_to_download = vector_create(sizeof(const char *));

    return downloader;
}

int magicnet_chain_downloader_hash_find(struct magicnet_chain_downloader *downloader, const char *hash, struct magicnet_chain_downloader_hash_to_download *hash_to_download_out)
{
    int res = MAGICNET_ERROR_NOT_FOUND;
    vector_set_peek_pointer(downloader->hashes_to_download, 0);
    struct magicnet_chain_downloader_hash_to_download *hash_to_download = vector_peek_ptr(downloader->hashes_to_download);
    while (hash_to_download)
    {
        if (memcmp(hash_to_download->hash, hash, sizeof(hash_to_download->hash)) == 0)
        {
            res = 0;
            if (hash_to_download_out)
            {
                *hash_to_download_out = *hash_to_download;
            }
            break;
        }
        hash_to_download = vector_peek_ptr(downloader->hashes_to_download);
    }

    return res;
}

void magicnet_chain_downloader_hash_add(struct magicnet_chain_downloader *downloader, const char *hash)
{
    if (sha256_empty(hash))
    {
        return;
    }

    // Already added..
    if (magicnet_chain_downloader_hash_find(downloader, hash, NULL) == 0)
    {
        return;
    }

    // Already have the block? Then dont do anything..
    struct block *block = block_load(hash);
    if (block)
    {
        block_free(block);
        return;
    }

    struct magicnet_chain_downloader_hash_to_download *hash_to_download = calloc(1, sizeof(struct magicnet_chain_downloader_hash_to_download));
    strncpy(hash_to_download->hash, hash, sizeof(hash_to_download->hash));
    vector_push(downloader->hashes_to_download, &hash_to_download);
}

int magicnet_chain_downloader_queue_for_block_download(const char *block_hash)
{
    pthread_mutex_lock(&downloads.lock);
    if (!default_downloader)
    {
        pthread_mutex_unlock(&downloads.lock);
        return -1;
    }
    magicnet_chain_downloader_hash_add(default_downloader, block_hash);
    pthread_mutex_unlock(&downloads.lock);
    return 0;
}

int magicnet_chain_downloader_thread_ask_for_blocks(struct magicnet_chain_downloader *downloader)
{
    int res = 0;
    struct magicnet_chain_downloader_hash_to_download hash_to_find;
    struct magicnet_chain_downloader_hash_to_download *hash = NULL;
    struct magicnet_packet *req_packet = magicnet_packet_new();
    pthread_mutex_lock(&downloads.lock);
    vector_set_peek_pointer(downloader->hashes_to_download, 0);

    // Lets find the next hash to request, It will be the first hash we encounter whose had its request delay.
    hash = vector_peek_ptr(downloader->hashes_to_download);
    while (hash && !(time(NULL) - hash->last_request > MAGICNET_CHAIN_DOWNLOADER_BLOCK_REQUEST_DELAY_SECONDS))
    {
        hash = vector_peek_ptr(downloader->hashes_to_download);
    }
    // We have a hash that is ready to be requested again.
    if (hash)
    {
        hash->last_request = time(NULL);
        hash_to_find = *hash;
    }
    pthread_mutex_unlock(&downloads.lock);

    if (!hash)
    {
        goto out;
    }

    magicnet_signed_data(req_packet)->type = MAGICNET_PACKET_TYPE_REQUEST_BLOCK;
    magicnet_signed_data(req_packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    strncpy(magicnet_signed_data(req_packet)->payload.request_block.request_hash, hash_to_find.hash, sizeof(magicnet_signed_data(req_packet)->payload.request_block.request_hash));
    struct magicnet_client *client_we_asked = NULL;
    magicnet_server_lock(downloader->server);
    res = magicnet_server_add_packet_to_relay(downloader->server, req_packet);
    magicnet_server_unlock(downloader->server);

out:
    magicnet_free_packet(req_packet);
    return 0;
}

void magicnet_chain_downloader_check_blocks_received(struct magicnet_chain_downloader *downloader)
{
    vector_set_peek_pointer(downloader->hashes_to_download, 0);
    struct magicnet_chain_downloader_hash_to_download *hash_to_download = vector_peek_ptr(downloader->hashes_to_download);
    while (hash_to_download)
    {
        struct block *block = block_load(hash_to_download->hash);
        if (block)
        {
            // Oh we have the block now thats great... Let us delete the request hash
            free(hash_to_download);
            vector_pop_last_peek(downloader->hashes_to_download);
        }
        block_free(block);
        hash_to_download = vector_peek_ptr(downloader->hashes_to_download);
    }
}
void *magicnet_chain_downloader_thread_loop(void *_downloader)
{
    struct magicnet_chain_downloader *downloader = _downloader;

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    bool running = true;
    bool do_sleep = false;
    while (running)
    {
        do_sleep = false;
        magicnet_chain_downloader_thread_ask_for_blocks(downloader);
        pthread_mutex_lock(&downloads.lock);

        // Let's check if we received the blocks we asked for. This is non-blocking we will come around a couple times most likely
        // when the block is there the request hash is removed from the downloader.
        magicnet_chain_downloader_check_blocks_received(downloader);
        // No hashes to downloadthen we should just sleep for a bit so we can save some CPU cycles..
        if (vector_empty(downloader->hashes_to_download))
        {
            do_sleep = true;
        }
        if (downloader->finished)
        {
            running = false;
        }
        pthread_mutex_unlock(&downloads.lock);

        if (do_sleep)
        {
            usleep(1000);
        }
    }

    return downloader;
}
int magicnet_chain_downloader_start(struct magicnet_chain_downloader *downloader)
{
    int res = 0;

    pthread_mutex_lock(&downloads.lock);
    magicnet_downloads_add(downloader);
    pthread_mutex_unlock(&downloads.lock);

    if (pthread_create(&downloader->thread_id, NULL, &magicnet_chain_downloader_thread_loop, downloader))
    {
        magicnet_log("%s failed to start the peer download thread\n", __FUNCTION__);
        res = -1;
        goto out;
    }

out:
    return res;
}
