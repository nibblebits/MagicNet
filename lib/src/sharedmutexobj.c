#include "sharedmutexobj.h"

struct magicnet_shared_mutex_obj *magicnet_shared_mutex_obj_create_hold_as_owner(void *data, MAGICNET_SHARED_MUTEX_OBJ_FREE_DATA_FUNCTION free_data_func)
{
    int res = 0;
    struct magicnet_shared_mutex_obj *obj = calloc(1, sizeof(struct magicnet_shared_mutex_obj));
    if (!obj)
    {
        res = -1;
        goto out;
    }

    obj->mutex = calloc(1, sizeof(pthread_mutex_t));
    if (!obj->mutex)
    {
        res = -1;
        goto out;
    }
    obj->owner_refcount = 1;
    obj->viewer_refcount = 0;
    obj->functions.free_data = free_data_func;
    obj->data = data;

    // thread action, recursive could be a bad idea
    // but for now we will keep it, maybe change it later.
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(obj->mutex, &mutex_attr);

out:
    if (res < 0 && obj)
    {
        if (obj->mutex)
        {
            // destory mutex
            pthread_mutex_destroy(obj->mutex);
            free(obj->mutex);
            obj->mutex = NULL;
        }

        free(obj);
    }
    return obj;
}

void *magicnet_shared_mutex_obj_owner_hold(struct magicnet_shared_mutex_obj *mutex_obj)
{
    // lock it, better deisgn might be an atomic integer
    // then when its zero, lock the lock to wait until someone is done with it
    // then finally free and destory, we will see. decide later..
    pthread_mutex_lock(mutex_obj->mutex);
    mutex_obj->owner_refcount++;
    pthread_mutex_unlock(mutex_obj->mutex);

    return mutex_obj->data;
}

bool magicnet_shared_mutex_obj_is_stale(struct magicnet_shared_mutex_obj* mutex_obj)
{
    // We dont need a long for this operation
    return mutex_obj->flags & MAGICNET_SHARED_MUTEX_OBJ_FLAG_STALE;
}

void _magicnet_shared_mutex_obj_free_data(struct magicnet_shared_mutex_obj *mutex_obj)
{
    if (mutex_obj->functions.free_data)
    {
        mutex_obj->functions.free_data(mutex_obj->data);
        // the data payload is freed.
        mutex_obj->data = NULL;
        mutex_obj->flags |= MAGICNET_SHARED_MUTEX_OBJ_FLAG_STALE;
    }
}

void magicnet_shared_mutex_obj_handle_release_refcounts(struct magicnet_shared_mutex_obj *mutex_obj, bool *mutex_deleted)
{
    *mutex_deleted = false;
    if (mutex_obj->owner_refcount <= 0 && mutex_obj->data)
    {
        _magicnet_shared_mutex_obj_free_data(mutex_obj);
        mutex_obj->data = NULL;
    }

    if (mutex_obj->viewer_refcount <= 0)
    {
        // Are we also out of viewers, then free the entire structure
        pthread_mutex_unlock(mutex_obj->mutex);
        pthread_mutex_destroy(mutex_obj->mutex);
        free(mutex_obj->mutex);
        free(mutex_obj);
        *mutex_deleted = true;
    }
}
void magicnet_shared_mutex_obj_owner_release(struct magicnet_shared_mutex_obj *mutex_obj)
{
    bool mutex_deleted = false;
    pthread_mutex_lock(mutex_obj->mutex);
    mutex_obj->owner_refcount--;

    magicnet_shared_mutex_obj_handle_release_refcounts(mutex_obj, &mutex_deleted);
    if (!mutex_deleted)
    {
        pthread_mutex_unlock(mutex_obj->mutex);
    }
}

void *magicnet_shared_mutex_obj_viewer_hold(struct magicnet_shared_mutex_obj *mutex_obj)
{
    pthread_mutex_lock(mutex_obj->mutex);
    mutex_obj->viewer_refcount++;
    pthread_mutex_unlock(mutex_obj->mutex);
    return mutex_obj->data;
}

void magicnet_shared_mutex_obj_viewer_release(struct magicnet_shared_mutex_obj *mutex_obj)
{
    bool mutex_deleted = false;
    pthread_mutex_lock(mutex_obj->mutex);
    mutex_obj->viewer_refcount--;

    magicnet_shared_mutex_obj_handle_release_refcounts(mutex_obj, &mutex_deleted);
    if (!mutex_deleted)
    {
        pthread_mutex_unlock(mutex_obj->mutex);
    }
}

void magicnet_shared_mutex_obj_lock(struct magicnet_shared_mutex_obj *mutex_obj)
{
    pthread_mutex_lock(mutex_obj->mutex);
}

void magicnet_shared_mutex_obj_unlock(struct magicnet_shared_mutex_obj *mutex_obj)
{
    pthread_mutex_unlock(mutex_obj->mutex);
}
