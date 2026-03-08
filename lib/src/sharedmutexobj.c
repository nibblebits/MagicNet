#include "sharedmutexobj.h"
#include "log.h"
#include <stdlib.h>
#include <stdio.h>
bool _magicnet_shared_mutex_obj_is_stale(struct magicnet_shared_mutex_obj *mutex_obj);

int magicnet_shared_mutex_obj_fill_hold(struct magicnet_shared_mutex_obj *obj, void *data, MAGICNET_SHARED_MUTEX_OBJ_FREE_DATA_FUNCTION free_data_func)
{
    int res = 0;
    if (!obj || !obj->refcount_mutex)
    {
        return -1;
    }

    pthread_mutex_lock(obj->refcount_mutex);

    if (obj->owner_refcount > 0)
    {
        magicnet_important("%s You are attempting to fill an existing object that has not been freed yet\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    obj->flags = 0;
    obj->owner_refcount = 1;
    obj->functions.free_data = free_data_func;
    obj->data = data;

    obj->mutex = calloc(1, sizeof(pthread_mutex_t));
    if (!obj->mutex)
    {
        res = -1;
        goto out;
    }

    // thread action, recursive could be a bad idea
    // but for now we will keep it, maybe change it later.
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(obj->mutex, &mutex_attr);

out:
    pthread_mutex_unlock(obj->refcount_mutex);

    return res;
}
struct magicnet_shared_mutex_obj *magicnet_shared_mutex_obj_create_hold_as_owner(void *data, MAGICNET_SHARED_MUTEX_OBJ_FREE_DATA_FUNCTION free_data_func, struct magicnet_shared_mutex_obj *recycle_obj)
{
    int res = 0;
    bool is_fresh = false;
    struct magicnet_shared_mutex_obj *obj = recycle_obj;
    if (!obj)
    {
        is_fresh = true;
        obj = calloc(1, sizeof(struct magicnet_shared_mutex_obj));
        if (!obj)
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

        // non-recursive for this one.
        pthread_mutex_init(obj->refcount_mutex, NULL);

        obj->viewer_refcount = 0;
    }

    res = magicnet_shared_mutex_obj_fill_hold(obj, data, free_data_func);

out:
    if (res < 0 && obj)
    {
        if (is_fresh)
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
                pthread_mutex_destroy(obj->refcount_mutex);
                free(obj->refcount_mutex);
                obj->refcount_mutex = NULL;
            }

            free(obj);
            obj = NULL;
        }
    }
    return obj;
}

void *magicnet_shared_mutex_obj_owner_hold(struct magicnet_shared_mutex_obj *mutex_obj)
{
    // Is the mutex obj null, then return null
    if (!mutex_obj)
    {
        return NULL;
    }
    pthread_mutex_lock(mutex_obj->refcount_mutex);
    // Is the obj stale, if so no ref count
    if (!_magicnet_shared_mutex_obj_is_stale(mutex_obj))
    {
        mutex_obj->owner_refcount++;
    }
    pthread_mutex_unlock(mutex_obj->refcount_mutex);

    // returns NULL if nothing to hold.
    return mutex_obj->data;
}

bool _magicnet_shared_mutex_obj_is_stale(struct magicnet_shared_mutex_obj *mutex_obj)
{
    // We dont need a long for this operation
    return mutex_obj->flags & MAGICNET_SHARED_MUTEX_OBJ_FLAG_STALE;
}

bool magicnet_shared_mutex_obj_is_stale(struct magicnet_shared_mutex_obj *mutex_obj)
{
    bool stale = false;
    pthread_mutex_lock(mutex_obj->refcount_mutex);
    stale = _magicnet_shared_mutex_obj_is_stale(mutex_obj);
    pthread_mutex_unlock(mutex_obj->refcount_mutex);
    return stale;
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
    if (!mutex_obj)
    {
        // for simplicty we will allows nulls in hold and release
        // the default action will be to ignore the requst, this is to simplify the code
        // when working with large arrays where nulls may be present ect.
        // hold shall return a null data result if hold is called
       return;
    }
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
        if (mutex_obj->functions.free_data)
        {
            mutex_obj->functions.free_data(mutex_obj->data);
        }

        // try to think of a way to capture a lock thats still held
        // and flag a warning
        // for now we assume the user of this functionality has done it correctly
        pthread_mutex_destroy(mutex_obj->mutex);
        free(mutex_obj->mutex);
        mutex_obj->mutex = NULL;
        // DON'T FREE THE MUTEX_OBJ->DATA ITS HANDLED IN THE FREE FUNCTION.
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

void magicnet_shared_mutex_obj_viewer_hold(struct magicnet_shared_mutex_obj *mutex_obj)
{
    if (!mutex_obj)
    {
        magicnet_bug("%s null object provided\n", __FUNCTION__);
    }
    pthread_mutex_lock(mutex_obj->refcount_mutex);
    mutex_obj->viewer_refcount++;
    pthread_mutex_unlock(mutex_obj->refcount_mutex);

    // WARNING: VIEWER SHALL NEVER RECEIVE THE DATA AS THERIS NOT A GUARANTEE
    // THE DATA WILL EXIST WHEN HE HAS IT.
}

void magicnet_shared_mutex_obj_viewer_release(struct magicnet_shared_mutex_obj *mutex_obj)
{
    if (!mutex_obj)
    {
        magicnet_bug("%s null object provided\n", __FUNCTION__);
    }
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
    if (!mutex_obj || !mutex_obj->mutex)
    {
        magicnet_bug("%s the mutex does not exist, owner ref hit zero viewer ref > 0\n", __FUNCTION__);
        return;
    }

    pthread_mutex_lock(mutex_obj->mutex);
}

void magicnet_shared_mutex_obj_unlock(struct magicnet_shared_mutex_obj *mutex_obj)
{
    if (!mutex_obj || !mutex_obj->mutex)
    {
        magicnet_bug("%s the mutex does not exist, owner ref hit zero viewer ref > 0\n", __FUNCTION__);
        return;
    }

    pthread_mutex_unlock(mutex_obj->mutex);
}
