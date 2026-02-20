#ifndef MAGICNET_SHARED_H
#define MAGICNET_SHARED_H

/**
 * naming might make issues if c++ compiler used, consider this later..
 * 
 */
#include <stddef.h>
#include <pthread.h>
#include "vector.h"

struct magicnet_shared_ptr;
typedef void(*MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION)(struct magicnet_shared_ptr* ptr, void* data_ptr);

struct magicnet_shared_ptr
{
    void* ptr;
    int ref_count;

    // CHANGE OF DESIGN ONE MUTEX FOR ALL SHAREDPTR TO SIMPLIFY FOR NOW
    // dont delete the mutex!
    pthread_mutex_t* mutex;

    struct
    {
        MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data;
    } functions;

    // We will store the thread ids of everyone holding it
    // so we can join the threads reducing concurrency issues.
    // pthread_t vector.
    struct vector* thread_vec;
};

struct magicnet_shared_ptr* magicnet_shared_ptr_new(void* data, MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data_func);
void* magicnet_shared_ptr_hold(struct magicnet_shared_ptr* ptr);
void magicnet_shared_ptr_release(struct magicnet_shared_ptr* ptr);
int magicnet_shared_ptr_system_init();

#endif