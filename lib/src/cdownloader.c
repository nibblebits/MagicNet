#include "magicnet.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

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
        sleep(5);
        if (downloader->finished)
        {
            running = false;
        }
        pthread_mutex_unlock(&downloader->lock);

    }
}

/**
 * Queues a download for the block with the given previous hash. Downloads the entire chain until NULL is found.
*/
struct magicnet_chain_downloader* magincnet_chain_downloader_download(const char* prev_hash)
{
    struct magicnet_chain_downloader* downloader = calloc(1, sizeof(struct magicnet_chain_downloader));
    strncpy(downloader->starting_hash, prev_hash, strlen(prev_hash));
    downloader->total_blocks_downloaded = 0;
    downloader->finished = false;
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