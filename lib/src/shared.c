
#include "shared.h"
#include <memory.h>
#include <stdlib.h>
struct magicnet_shared_ptr *magicnet_shared_ptr_new(void *data, MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data_func)
{
    int res = 0;
    struct magicnet_shared_ptr *shared_ptr = calloc(1, sizeof(struct magicnet_shared_ptr));
    if (!shared_ptr)
    {
        res = -1;
        goto out;
    }

    shared_ptr->mutex = calloc(1, sizeof(pthread_mutex_t));
    if (!shared_ptr->mutex)
    {
        res = -1;
        goto out;
    }
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(shared_ptr->mutex, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);

    shared_ptr->ptr = data;
    //keep at zero, the person who made the pointer should hold it
    shared_ptr->ref_count = 0;
    shared_ptr->functions.free_data = free_data_func;
out:
    if (res < 0)
    {
        free(shared_ptr->mutex);
        free(shared_ptr);
        shared_ptr = NULL;
    }

    return shared_ptr;
}

void magicnet_shared_ptr_free_data(struct magicnet_shared_ptr *ptr)
{
    if (ptr->functions.free_data)
    {
        ptr->functions.free_data(ptr, ptr->ptr);
    }
}

void *magicnet_shared_ptr_hold(struct magicnet_shared_ptr *ptr)
{
    void *_ptr = ptr->ptr;
    pthread_mutex_t *mutex = ptr->mutex;
    pthread_mutex_lock(mutex);
    ptr->ref_count++;

    pthread_mutex_unlock(mutex);

    return _ptr;
}

void magicnet_shared_ptr_release(struct magicnet_shared_ptr *ptr)
{
    pthread_mutex_t *mutex = ptr->mutex;
    pthread_mutex_lock(mutex);
    ptr->ref_count--;
    if (ptr->ref_count <= 0)
    {
        magicnet_shared_ptr_free_data(ptr);
        free(ptr);
        pthread_mutex_unlock(mutex);
        pthread_mutex_destroy(mutex);
        free(mutex);
        return;
    }

    pthread_mutex_unlock(mutex);

}
