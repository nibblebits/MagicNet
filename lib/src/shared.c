
#include "shared.h"
#include <memory.h>
#include <stdlib.h>

/**
 * NOTE THE DESIGN HAS BEEN SIMPLIFIED WE NOW ONLY USE ONE MUTEX FOR THE WHOEL SHRED PTR SYSTEM
 * IT NEEDS IMPROVING WE CAN DO BETTER.
 */
pthread_mutex_t *shared_ptr_mutex = NULL;

int magicnet_shared_ptr_system_init()
{
    if (!shared_ptr_mutex)
    {
        shared_ptr_mutex = calloc(1, sizeof(pthread_mutex_t));
        pthread_mutexattr_t mutex_attr;
        pthread_mutexattr_init(&mutex_attr);
        pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(shared_ptr_mutex, &mutex_attr);
        pthread_mutexattr_destroy(&mutex_attr);
    }
    return 0;
}
struct magicnet_shared_ptr *magicnet_shared_ptr_new(void *data, MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data_func)
{
    int res = 0;
    struct magicnet_shared_ptr *shared_ptr = calloc(1, sizeof(struct magicnet_shared_ptr));
    if (!shared_ptr)
    {
        res = -1;
        goto out;
    }

    shared_ptr->mutex = shared_ptr_mutex;
    if (!shared_ptr->mutex)
    {
        res = -1;
        goto out;
    }

    shared_ptr->ptr = data;
    // keep at zero, the person who made the pointer should hold it
    shared_ptr->ref_count = 0;
    shared_ptr->functions.free_data = free_data_func;
    shared_ptr->thread_vec = vector_create(sizeof(pthread_t));
    if (!shared_ptr->thread_vec)
    {
        res = -1;
        goto out;
    }

out:
    if (res < 0)
    {

        vector_free(shared_ptr->thread_vec);
        if (shared_ptr)
        {
            free(shared_ptr);
        }

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

/**
 * change to a map slow as hell..
 *
 * I THINK THIS IDEA WAS BAD, WE WILL KEEP IT FOR NOW PROBABLY WILL SCRAP THOSE FUNCTIONS
 */
bool magicnet_shared_ptr_thread_noted(struct magicnet_shared_ptr *ptr, pthread_t thread_id)
{
    vector_set_peek_pointer(ptr->thread_vec, 0);
    pthread_t cur_thread_id = 0;
    size_t thread_count = vector_count(ptr->thread_vec);
    for (size_t i = 0; i < thread_count; i++)
    {
        cur_thread_id = (pthread_t)(uintptr_t)vector_peek(ptr->thread_vec);
        if (cur_thread_id == thread_id)
        {
            return true;
        }
    }

    return false;
}

void magicnet_shared_ptr_thread_note(struct magicnet_shared_ptr *ptr, pthread_t thread_id)
{
    // This could get slow we should improve this
    // maybe better idea is to push duplicates and deal with them when joining threads later.
    if (magicnet_shared_ptr_thread_noted(ptr, thread_id))
        return;

    vector_push(ptr->thread_vec, &thread_id);
}

void *magicnet_shared_ptr_hold(struct magicnet_shared_ptr *ptr)
{
    void *_ptr = ptr->ptr;
    pthread_mutex_lock(shared_ptr_mutex);
    ptr->ref_count++;
    pthread_mutex_unlock(shared_ptr_mutex);

    return _ptr;
}

void magicnet_shared_ptr_release(struct magicnet_shared_ptr *ptr)
{
    pthread_mutex_lock(shared_ptr_mutex);
    ptr->ref_count--;
    if (ptr->ref_count == 0)
    {
        // BUG HERE I THINK ITS MUTLI-THREADED RELATED AS WHEN USING GDB
        // THE SEG FAULT DOES NOT OCCUR.
        magicnet_shared_ptr_free_data(ptr);
        // free(ptr);
        pthread_mutex_unlock(shared_ptr_mutex);
        return;
    }

    if (ptr->ref_count < 0)
    {
        magicnet_log("%s bug found release while not held\n", __FUNCTION__);
    }

    pthread_mutex_unlock(shared_ptr_mutex);
}
