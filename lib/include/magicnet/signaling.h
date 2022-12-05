#ifndef MAGICNET_SIGNALING
#define MAGICNET_SIGNALING
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>

#include "config.h"

struct magicnet_signal
{
    int id;
    int index;
    // Signal type is requried for security precautions. In case someone in the network asks us to invoke a signal
    // of a different type that was expected. We need to keep track of this so we always know the type of data and signal we are dealing with.
    char signal_type[MAGICNET_MAX_SIGNAL_TYPE_NAME];
    void *data;
    // Vector of void* multiple pushes can fill this data_vec while others are waiting.
    struct vector* data_vec;
    pthread_rwlock_t signal_lock;
    sem_t sem;
    bool free;
};

int magicnet_signals_init();
void magicnet_signals_free();
struct magicnet_signal *magicnet_signal_find_free(const char* signal_type);
struct magicnet_signal* magicnet_signal_get_by_id_and_type(const char* signal_type, int id);
int magicnet_signal_wait_timed(struct magicnet_signal *signal, int seconds, void** data_out);
int magicnet_signal_post(struct magicnet_signal *signal, void *data, size_t size);
int magicnet_signal_post_for_signal(int signal_id, const char* signal_type, void* data, size_t size);
void magicnet_signal_release(struct magicnet_signal* signal);
void magicnet_signals_release_all();
#endif