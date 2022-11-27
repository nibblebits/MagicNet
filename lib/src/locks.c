#include "locks.h"
#include <pthread.h>
#include <bool.h>
#include "vector.h"

struct vector *vec_of_locks;
pthread_mutex_t vec_lock;

struct magicnet_lock
{
    // Pointer data that we are locking
    void *data;
    pthread_mutex_t lock;
};

int magicnet_lock_system_init()
{
    vec_of_locks = vector_create(sizeof(struct magicnet_lock *));

    if (pthread_mutex_init(&vec_lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the vector lock\n");
        return -1;
    }

    return 0;
}

void magicnet_lock_new(void *data)
{
    struct magicnet_lock *lock = calloc(1, sizeof(struct magicnet_lock));
    lock->data = data;
    if (pthread_mutex_init(&lock->lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the lock\n");
        return false;
    }
    vector_push(vec_of_locks, &lock);
}

struct magicnet_lock *magicnet_lock_find_for_data_no_locks(void *data)
{
    struct magicnet_lock *found_lock = NULL;
    vector_set_peek_pointer(vec_of_locks, 0);
    struct magicnet_lock *lock = vector_peek_ptr(vec_of_locks);
    while (lock && found_lock == NULL)
    {
        if (lock->data == data)
        {
            found_lock = lock;
        }
        lock = vector_peek_ptr(vec_of_locks);
    }

    return found_lock;
}

struct magicnet_lock *magicnet_lock_find_for_data(void *data)
{
    struct magicnet_lock *found_lock = NULL;
    pthread_mutex_lock(&vec_lock);
    found_lock = magicnet_lock_find_for_data_no_locks(data);
    pthread_mutex_unlock(&vec_lock);

    return found_lock;
}

void magicnet_lock_remove(void *data)
{
    struct magicnet_lock *found_lock = NULL;
    pthread_mutex_lock(&vec_lock);
    found_lock = magicnet_lock_find_for_data_no_locks(data);
    pthread_mutex_unlock(&vec_lock);

    if (found_lock)
    {
        pthread_mutex_lock(&found_lock->lock);
        found_lock->data = NULL;
        pthread_mutex_unlock(&found_lock->lock);
    }
}
bool magicnet_lock(void *data)
{
    struct magicnet_lock *found_lock = NULL;
    pthread_mutex_lock(&vec_lock);
    found_lock = magicnet_lock_find_for_data_no_locks(data);
    pthread_mutex_unlock(&vec_lock);

    if (found_lock)
    {
        pthread_mutex_lock(&found_lock->lock);
    }
    return found_lock != NULL;
}

bool magicnet_unlock(void *data)
{
    struct magicnet_lock *found_lock = NULL;
    found_lock = magicnet_lock_find_for_data(data);
    if (found_lock)
    {
        pthread_mutex_unlock(found_lock);
    }
    return found_lock != NULL;
}