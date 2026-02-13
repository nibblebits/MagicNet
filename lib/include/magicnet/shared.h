#ifndef MAGICNET_SHARED_H
#define MAGICNET_SHARED_H

/**
 * naming might make issues if c++ compiler used, consider this later..
 * 
 */
#include <stddef.h>
#include <pthread.h>

typedef void(*MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION)(struct magicnet_shared_ptr* ptr, void* data_ptr);

struct magicnet_shared_ptr
{
    void* ptr;
    size_t ref_count;
    pthread_mutex_t* mutex;

    struct
    {
        MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data;
    } functions;
};

struct magicnet_shared_ptr* magicnet_shared_ptr_new(void* data, MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data_func);
void* magicnet_shared_ptr_hold(struct magicnet_shared_ptr* ptr);
void magicnet_shared_ptr_release(struct magicnet_shared_ptr* ptr);

#endif