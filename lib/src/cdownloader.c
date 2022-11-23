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

void magicnet_chain_downloader_blocks_catchup(struct magicnet_server* server)
{
    return;
    
    struct magicnet_chain_downloader* downloader = magicnet_chain_downloader_download(server);
    if (!downloader)
    {
        magicnet_log("%s could not create downloader instance\n", __FUNCTION__);
        return;
    }

    struct vector* blocks_to_download = vector_create(sizeof(struct block*));
    while(magicnet_database_load_blocks_with_no_chain(blocks_to_download, 1) >= 0)
    {
        struct block* prev_block = vector_back_ptr(blocks_to_download);
        if (prev_block)
        {
            magicnet_chain_downloader_hash_add(downloader, prev_block->hash);
        }
    }

    magicnet_chain_downloader_start(downloader);
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
    magicnet_chain_downloader_blocks_catchup(server);
out:
    return res;
}

void magicnet_chain_downloader_free(struct magicnet_chain_downloader *downloader)
{
    vector_set_peek_pointer(downloader->hashes_to_download, 0);
    struct magicnet_chain_downloader_hash_to_download*  hash = vector_peek_ptr(downloader->hashes_to_download);
    while(hash)
    {
        free(hash);
        hash = vector_peek_ptr(downloader->hashes_to_download);
    }
    free(downloader);
}


bool magicnet_chain_downloader_accepted_packet(struct magicnet_packet *packet)
{
    return packet && (magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_BLOCK_SEND ||
                      magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND);
}

struct magicnet_chain_downloader* magicnet_chain_downloader_download(struct magicnet_server* server)
{
    struct magicnet_chain_downloader* downloader = calloc(1, sizeof(struct magicnet_chain_downloader));
    downloader->server = server;
    downloader->hashes_to_download = vector_create(sizeof(const char*));

    if (pthread_mutex_init(&downloader->lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the downloader lock\n");
        return NULL;
    }


    return downloader;
}

void magicnet_chain_downloader_hash_add(struct magicnet_chain_downloader* downloader, const char* hash)
{
    if (sha256_empty(hash))
    {
        return;
    }

    struct magicnet_chain_downloader_hash_to_download* hash_to_download = calloc(1, sizeof(struct magicnet_chain_downloader_hash_to_download));
    strncpy(hash_to_download->hash, hash, sizeof(hash));
    vector_push(downloader->hashes_to_download, &hash_to_download);
}

int magicnet_chain_downloader_thread_ask_for_blocks(struct magicnet_chain_downloader* downloader)
{
    return 0;
}
void *magicnet_chain_downloader_thread_loop(void *_downloader)
{
    struct magicnet_chain_downloader* downloader = _downloader;
    bool running = true;
    while(running)
    {
        magicnet_chain_downloader_thread_ask_for_blocks(downloader);
        pthread_mutex_lock(&downloader->lock);
        if (downloader->finished)
        {
            running = false;
        }
        pthread_mutex_unlock(&downloader->lock);
    }

}
int magicnet_chain_downloader_start(struct magicnet_chain_downloader* downloader)
{
    int res = 0;
    if (pthread_create(&downloader->thread_id, NULL, &magicnet_chain_downloader_thread_loop, downloader))
    {
        magicnet_log("%s failed to start the peer download thread\n", __FUNCTION__);
        res = -1;
        goto out;
    }

out:
    return res;
}
