#ifndef MAGICNET_MUTEX_OBJECT_H
#define MAGICNET_MUTEX_OBJECT_H

#include <pthread.h>
struct mutex_obj
{
    void* ptr;
    pthread_mutex_t mutex;
};

/**
 * \param ptr The data you want to protect
 */
struct mutex_obj* mutex_obj_init(void* ptr);

/**
 * Locks the mutex and returns the data payload
 */
void* mutex_obj_lock(struct mutex_obj* obj);

/**
 * Unlocks the mutex 
 */
void mutex_obj_unlock(struct mutex_obj* obj);

#endif