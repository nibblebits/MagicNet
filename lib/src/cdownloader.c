#include "magicnet.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include "database.h"
#include "signaling.h"

void magicnet_downloads_remove(struct magicnet_chain_downloader *downloader);
void magicnet_chain_downloader_free_general_data(struct magicnet_chain_downloader *downloader);
struct magicnet_client *magicnet_chain_downloader_wait_for_client_with_block(struct magicnet_chain_downloader *downloader);

static struct magicnet_active_chain_downloads downloads;
static struct magicnet_chain_downloader *default_downloader = NULL;
bool downloaders_shut_down = false;

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
        pthread_mutex_unlock(&downloads.lock);
        return -1;
    }
    pthread_mutex_unlock(&downloads.lock);

    magicnet_chain_downloader_finish(downloader);

    return 0;
}
void magicnet_chain_downloaders_shutdown()
{
    magicnet_important("%s terminating downloaders please wait..\n", __FUNCTION__);

    size_t count = 0;
    while (magicnet_chain_downloader_shutdown_last() >= 0)
    {
        magicnet_important("%s ended a chain downloader\n", __FUNCTION__);
        count++;
    }
    magicnet_important("%s ended %i chain downloader threads\n", __FUNCTION__, count);

    magicnet_important("%s downloaders terminated\n", __FUNCTION__);
}

void magicnet_chain_downloaders_cleanup()
{
    magicnet_important("%s cleaning up downloaders memory\n", __FUNCTION__);
    pthread_mutex_destroy(&downloads.lock);
    vector_free(downloads.chain_downloads);
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
    int res = 0;
    struct magicnet_chain_downloader *downloader = calloc(1, sizeof(struct magicnet_chain_downloader));
    downloader->server = server;
    downloader->hashes_to_download = vector_create(sizeof(const char *));
out:
    if (res < 0)
    {
        magicnet_chain_downloader_free_general_data(downloader);
        free(downloader);
        downloader = NULL;
    }
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

    if (!downloader)
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
    struct magicnet_signal *signal = NULL;
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

    signal = magicnet_signal_find_free("downloader-req-block-signal");
    if (!signal)
    {
        magicnet_log("%s we are out of signals for now\n", __FUNCTION__);
        goto out;
    }

    magicnet_log("%s asking network for key\n", __FUNCTION__);
    magicnet_signed_data(req_packet)->type = MAGICNET_PACKET_TYPE_REQUEST_BLOCK;
    magicnet_signed_data(req_packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    strncpy(magicnet_signed_data(req_packet)->payload.request_block.request_hash, hash_to_find.hash, sizeof(magicnet_signed_data(req_packet)->payload.request_block.request_hash));
    magicnet_signed_data(req_packet)->payload.request_block.signal_id = signal->id;
    magicnet_server_lock(downloader->server);
    res = magicnet_server_add_packet_to_relay(downloader->server, req_packet);
    magicnet_server_unlock(downloader->server);

    struct key *key = NULL;
    res = magicnet_signal_wait_timed(signal, 30, (void **)&key);
    if (res < 0 || !key)
    {
        magicnet_log("%s failed to get response\n", __FUNCTION__);
        goto out;
    }

    magicnet_log("%s key=%s\n", __FUNCTION__, key->key);

    magicnet_log("%s attempting to connect to key\n", __FUNCTION__);
    struct magicnet_client *new_client = magicnet_connect_for_key(downloader->server, key, "chain-downloader");
    if (!new_client)
    {
        magicnet_log("%s FAILED\n", __FUNCTION__);
        goto out;
    }

    magicnet_log("%s connected to key\n", __FUNCTION__);

    // We have a client now, lets download as many blocks as we can
    struct magicnet_packet *super_download_packet = magicnet_packet_new();
    magicnet_signed_data(super_download_packet)->type = MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_REQUEST;
    magicnet_signed_data(super_download_packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    strncpy(magicnet_signed_data(super_download_packet)->payload.block_super_download.begin_hash, hash_to_find.hash, sizeof(magicnet_signed_data(super_download_packet)->payload.block_super_download.begin_hash));
    magicnet_signed_data(super_download_packet)->payload.block_super_download.total_blocks_to_request = MAGICNET_MAX_BLOCK_SUPER_DOWNLOAD_REQUEST_BLOCK_COUNT;
    res = magicnet_client_write_packet(new_client, super_download_packet, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        magicnet_log("%s failed to write super download request\n", __FUNCTION__);
        goto out;
    }


    // Now we expect right away a response with the blocks
    // Loop through all the blocks sent to us and download them
    char last_prev_hash[SHA256_STRING_LENGTH] = {0};
    for (int i = 0; i < MAGICNET_MAX_BLOCK_SUPER_DOWNLOAD_REQUEST_BLOCK_COUNT; i++)
    {
        struct magicnet_packet *super_download_response = magicnet_packet_new();

        // Read the response packet from the client
        res = magicnet_client_read_packet(new_client, super_download_response);
        if (res < 0)
        {
            magicnet_log("%s failed to read super download response\n", __FUNCTION__);
            goto out;
        }

        // Check if we are done  and for incorrect packets being sent to us.
        if (magicnet_signed_data(super_download_response)->type == MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_DONE)
        {
            magicnet_log("%s super download done\n", __FUNCTION__);
            goto out;
        }
        else if (magicnet_signed_data(super_download_response)->type != MAGICNET_PACKET_TYPE_BLOCK_SEND)
        {
            magicnet_log("%s super download response was not a block send packet or a done packet\n", __FUNCTION__);
            goto out;
        }

        struct block *block = vector_back_ptr(magicnet_signed_data(super_download_response)->payload.block_send.blocks);
        if (block)
        {
            magicnet_log("%s saving block %s\n", __FUNCTION__, block->hash);
            block_save(block);
            // Remove the block from the downloader hashes
            magicnet_chain_downloaders_remove_hash(block);

            strncpy(last_prev_hash, block->prev_hash, sizeof(last_prev_hash));
        }
        
        magicnet_free_packet(super_download_response);
    }

    if (!sha256_empty(last_prev_hash))
    {
       // Add the previous hash back to the download queue so we can download the next block later
       magicnet_log("%s still more to go adding prev hash %s to download queue", __FUNCTION__, last_prev_hash);
       magicnet_chain_downloader_hash_add(downloader, last_prev_hash);
    }

out:
    if (signal)
    {
        magicnet_signal_release(signal);
    }
    magicnet_free_packet(req_packet);
    return 0;
}



struct magicnet_chain_downloader *magicnet_chain_downloader_get_with_thread_id_no_locks(pthread_t thread_id)
{
    vector_set_peek_pointer(downloads.chain_downloads, 0);
    struct magicnet_chain_downloader *downloader = vector_peek_ptr(downloads.chain_downloads);
    while (downloader)
    {
        if (downloader->thread_id == thread_id)
        {
            return downloader;
        }
        downloader = vector_peek_ptr(downloads.chain_downloads);
    }

    return NULL;
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
