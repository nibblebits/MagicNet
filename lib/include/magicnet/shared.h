#ifndef MAGICNET_SHARED_H
#define MAGICNET_SHARED_H

/**
 * naming might make issues if c++ compiler used, consider this later..
 * 
 */
#include <stddef.h>
#include <pthread.h>
#include <stdatomic.h>
#include "vector.h"

/**
 * Shared pointer implementation, you must call magicnet_shared_ptr_hold after creating the
 * shared pointer, otherwise the memory will stay alive forever.
 */
struct magicnet_shared_ptr;
typedef void(*MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION)(struct magicnet_shared_ptr* ptr, void* data_ptr);
typedef int SHARED_POINTER_STATE;
enum
{
    SHARED_POINTER_STATE_ALIVE,
    SHARED_POINTER_STATE_DESTROYED
};

struct magicnet_shared_ptr
{
    void* ptr;
    _Atomic int ref_count;
    struct
    {
        MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data;
    } functions;
};

struct magicnet_shared_ptr* magicnet_shared_ptr_new(void* data, MAGICNET_SHARED_PTR_FREE_DATA_FUNCTION free_data_func);
void* magicnet_shared_ptr_hold(struct magicnet_shared_ptr* ptr);
void magicnet_shared_ptr_release(struct magicnet_shared_ptr* ptr, SHARED_POINTER_STATE* state_out);
int magicnet_shared_ptr_system_init();

#endif