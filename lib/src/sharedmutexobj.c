#include "sharedmutexobj.h"
#include "log.h"

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
    
    obj->refcount_mutex = calloc(1, sizeof(pthread_mutex_t));
    if (!obj->refcount_mutex)
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


    // non-recursive for this one.
    pthread_mutex_init(obj->owner_refcount, NULL);

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
        if (obj->refcount_mutex)
        {
            pthread_mutex_destory(obj->refcount_mutex);
            free(obj->refcount_mutex);
            obj->refcount_mutex = NULL;
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
    pthread_mutex_lock(mutex_obj->refcount_mutex);
    mutex_obj->owner_refcount++;
    pthread_mutex_unlock(mutex_obj->refcount_mutex);

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
void magicnet_shared_mutex_obj_owner_release(struct magicnet_shared_mutex_obj *mutex_obj)
{
    bool unlock_mutex = true;
    pthread_mutex_lock(mutex_obj->refcount_mutex);
    mutex_obj->owner_refcount--;

    if (mutex_obj->owner_refcount < 0)
    {
        magicnet_bug("%s releasing a owner that was never held\n", __FUNCTION__);
        return;
    }

    // Has the owner_refcount dropped to zero
    if (mutex_obj->owner_refcount == 0)
    {
        // great we need to free the data, theirs no more owners
        // of this object.
        // technically should be safe if someone locks the lock for the data
        // during free, because we have seperate mutexes now
        // but if the lock is held after free is done we are in trouble.
        mutex_obj->functions.free_data(mutex_obj->data);

        // try to think of a way to capture a lock thats still held
        // and flag a warning
        // for now we assume the user of this functionality has done it correctly
        pthread_mutex_destroy(mutex_obj->mutex);
        free(mutex_obj->mutex);
        free(mutex_obj->data);
        // finally null it, the slot is still available to the observers
        // the slot is stale now.
        mutex_obj->data = NULL;
        mutex_obj->flags |= MAGICNET_SHARED_MUTEX_OBJ_FLAG_STALE;

        // what about the visitor refcount is this zero too, if so we can get rid
        // of this memory
        if (mutex_obj->viewer_refcount == 0)
        {
            // owner_refcount == 0 && viewer_refcount == 0
            // therefore we are the last thread to be here, so we dont 
            // have to worry about concurrency anymore
            pthread_mutex_unlock(mutex_obj->refcount_mutex);
            pthread_mutex_destroy(mutex_obj->refcount_mutex);
            free(mutex_obj->refcount_mutex);
            free(mutex_obj);

            // with that all the data is gone.
            unlock_mutex = false;
        }
    }
   
    if (unlock_mutex)
    {
        pthread_mutex_unlock(mutex_obj->refcount_mutex);
    }
}

void *magicnet_shared_mutex_obj_viewer_hold(struct magicnet_shared_mutex_obj *mutex_obj)
{
    pthread_mutex_lock(mutex_obj->refcount_mutex);
    mutex_obj->viewer_refcount++;
    pthread_mutex_unlock(mutex_obj->refcount_mutex);
    return mutex_obj->data;
}

void magicnet_shared_mutex_obj_viewer_release(struct magicnet_shared_mutex_obj *mutex_obj)
{
    bool unlock_mutex = true;
    pthread_mutex_lock(mutex_obj->refcount_mutex);
    mutex_obj->viewer_refcount--;

    if (mutex_obj->viewer_refcount < 0)
    {
        magicnet_bug("%s releasing a viewer that never held\n", __FUNCTION__);
        return;
    }

    if (mutex_obj->viewer_refcount == 0)
    {
        // The viewer refcount has dropped to zero
        // theirs no more observers, we can delete the mutex and the shared object
        // but only if theres also no owners
        if (mutex_obj->owner_refcount == 0)
        {
            if (mutex_obj->data)
            {
                magicnet_bug("%s owner_refcount == 0 yet the data still exists it should've been deleted in the owner release\n", __FUNCTION__);
                return;
            }
            // no owners means the memory for the mutex data was already cleaned up
            // so we just have to deal with the mutex object its self
            pthread_mutex_unlock(mutex_obj->refcount_mutex);

            // We unlocked ourseleves but since we are the last viewer among all threads
            // data-race shouldnt happen
            pthread_mutex_destroy(mutex_obj->refcount_mutex);
            free(mutex_obj->refcount_mutex);
            free(mutex_obj);

            // and thats it the object is gone.
            unlock_mutex = false;
        }
    }

    if (unlock_mutex)
    {
        pthread_mutex_unlock(mutex_obj->refcount_mutex);
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
