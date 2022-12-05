#include <semaphore.h>
#include <signal.h>
#include <errno.h>
#include <memory.h>

#include "magicnet.h"
#include "signaling.h"
#include "log.h"

struct magicnet_signal signals[MAGICNET_MAX_SIGNALING_SIGNALS] = {0};
pthread_rwlock_t signal_lock;

int magicnet_signals_init()
{
    int res = 0;
    for (int i = 0; i < MAGICNET_MAX_SIGNALING_SIGNALS; i++)
    {
        memset(&signals[i], 0, sizeof(signals[i]));
        signals[i].data_vec = vector_create(sizeof(void *));
        if (pthread_rwlock_init(&signals[i].signal_lock, NULL) != 0)
        {
            magicnet_error("%s failed to initialize signal lock\n", __FUNCTION__);
            res = -1;
            goto out;
        }
        if (sem_init(&signals[i].sem, 0, 0) != 0)
        {
            magicnet_error("%s failed to initialize wait for response client semaphore\n", __FUNCTION__);
            res = -1;
            goto out;
        }
        if (i == 0)
        {
            signals[i].id = rand() % 999;
        }
        else
        {
            signals[i].id = rand() % (i * 1000) + (i * 1000) + 999;
        }
        signals[i].index = i;
        signals[i].free = true;
    }

out:
    return res;
}

void magicnet_signal_free(struct magicnet_signal *signal)
{
    sem_destroy(&signal->sem);
    pthread_rwlock_destroy(&signal->signal_lock);
    for (int i = 0; i < vector_count(signal->data_vec); i++)
    {
        free(&signal->data_vec[i]);
    }

    vector_free(signal->data_vec);
}

void magicnet_signals_release_all()
{
    for (int i = 0; i < MAGICNET_MAX_SIGNALING_SIGNALS; i++)
    {
        magicnet_signal_release(&signals[i]);
    }
}

void magicnet_signals_free()
{
    for (int i = 0; i < MAGICNET_MAX_SIGNALING_SIGNALS; i++)
    {
        magicnet_signal_free(&signals[i]);
    }
}

struct magicnet_signal *magicnet_signal_find_free(const char *signal_type)
{
    for (int i = 0; i < MAGICNET_MAX_SIGNALING_SIGNALS; i++)
    {
        pthread_rwlock_wrlock(&signals[i].signal_lock);
        if (signals[i].free)
        {
            strncpy(signals[i].signal_type, signal_type, sizeof(signals[i].signal_type));
            signals[i].free = false;
            pthread_rwlock_unlock(&signals[i].signal_lock);
            return &signals[i];
        }
        pthread_rwlock_unlock(&signals[i].signal_lock);
    }

    return NULL;
}

int magicnet_signal_wait_timed(struct magicnet_signal *signal, int seconds, void **data_out)
{
    int res = -1;
    char signal_type[MAGICNET_MAX_SIGNAL_TYPE_NAME];
    int signal_id = -1;

    // There is a possibility the signal would be recycled even though we are waiting, for this reason
    // we will store the current signal type and ID. If they differ when returning from the semaphore we know
    // that theirs been a problem
    strncpy(signal_type, signal->signal_type, sizeof(signal_type));
    signal_id = signal->id;

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
    {
        /* handle error */
        goto out;
    }

    ts.tv_sec += seconds;
    int s = 0;
    while ((s = sem_timedwait(&signal->sem, &ts)) == -1 && errno == EINTR)
        continue;

    pthread_rwlock_rdlock(&signal->signal_lock);
    if (signal_id != signal->id || strncmp(signal_type, signal->signal_type, sizeof(signal_type)) != 0)
    {
        res = -1;
        pthread_rwlock_unlock(&signal->signal_lock);
        goto out;
    }
    *data_out = vector_back_ptr_or_null(signal->data_vec);
    pthread_rwlock_unlock(&signal->signal_lock);

    if (s != -1)
    {
        res = 0;
        goto out;
    }

out:
    return res;
}

struct magicnet_signal *magicnet_signal_get_by_id_and_type(const char *signal_type, int id)
{
    struct magicnet_signal *signal = NULL;
    for (int i = 0; i < MAGICNET_MAX_SIGNALING_SIGNALS; i++)
    {
        pthread_rwlock_rdlock(&signals[i].signal_lock);
        if (!signals[i].free && signals[i].id == id &&
            strncmp(signals[i].signal_type, signal_type, sizeof(signals[i].signal_type)) == 0)
        {
            // Match found.
            signal = &signals[i];
        }
        pthread_rwlock_unlock(&signals[i].signal_lock);
    }

    return signal;
}

int magicnet_signal_post(struct magicnet_signal *signal, void *data, size_t size)
{
    void *data_clone = malloc(size);
    memcpy(data_clone, data, size);
    pthread_rwlock_wrlock(&signal->signal_lock);
    vector_push(signal->data_vec, &data_clone);

    if (sem_post(&signal->sem) == -1)
    {
        magicnet_error("%s post problem\n", __FUNCTION__);
        pthread_rwlock_unlock(&signal->signal_lock);
        return -1;
    }

    pthread_rwlock_unlock(&signal->signal_lock);
    return 0;
}

int magicnet_signal_post_for_signal(int signal_id, const char *signal_type, void *data, size_t size)
{
    int res = 0;

    struct magicnet_signal *signal = magicnet_signal_get_by_id_and_type(signal_type, signal_id);
    if (!signal)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    void *data_clone = malloc(size);
    memcpy(data_clone, data, size);

    pthread_rwlock_wrlock(&signal->signal_lock);
    // It is possible with the miliseconds that have passed the signal was reused...
    // Due to this being the case we will ensure it is the same signal type.. If it is then it is expecting the same data
    // therefore it is still valid
    if (strncmp(signal->signal_type, signal_type, sizeof(signal->sem)) != 0)
    {
        res = MAGICNET_ERROR_DATA_NO_LONGER_AVAILABLE;
        pthread_rwlock_unlock(&signal->signal_lock);
        goto out;
    }
    vector_push(signal->data_vec, &data_clone);

    if (sem_post(&signal->sem) == -1)
    {
        magicnet_error("%s post problem\n", __FUNCTION__);
        pthread_rwlock_unlock(&signal->signal_lock);
        res = -1;
        goto out;
    }

    pthread_rwlock_unlock(&signal->signal_lock);

out:
    return res;
}

void magicnet_signal_release(struct magicnet_signal *signal)
{
    pthread_rwlock_wrlock(&signal->signal_lock);
    signal->free = true;
    for (int i = 0; i < vector_count(signal->data_vec); i++)
    {
        free(&signal->data_vec[i]);
    }

    vector_free(signal->data_vec);
    signal->data_vec = vector_create(sizeof(void *));
    memset(signal->signal_type, 0, sizeof(signal->signal_type));
    if (signal->index == 0)
    {
        signal->id = rand() % 999;
    }
    else
    {
        signal->id = (rand() % (signal->index * 1000) + (signal->index * 1000)) + 999;
    }
    int sem_value = 0;
    sem_getvalue(&signal->sem, &sem_value);
    for (int i = 0; i < sem_value; i++)
    {
        sem_post(&signal->sem);
    }
    pthread_rwlock_unlock(&signal->signal_lock);
}