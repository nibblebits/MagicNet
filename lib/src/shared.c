
#include "shared.h"
#include <memory.h>
#include <stdlib.h>


int magicnet_shared_ptr_system_init()
{
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


    atomic_init(&shared_ptr->ref_count, 0);
    shared_ptr->ptr = data;
    // keep at zero, the person who made the pointer should hold it
    shared_ptr->ref_count = 0;
    shared_ptr->functions.free_data = free_data_func;
 

out:
    if (res < 0)
    {

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

void *magicnet_shared_ptr_hold(struct magicnet_shared_ptr *ptr)
{
    void *_ptr = ptr->ptr;
    atomic_fetch_add(&ptr->ref_count, 1);
    return _ptr;
}

void magicnet_shared_ptr_release(struct magicnet_shared_ptr *ptr)
{
    atomic_fetch_sub(&ptr->ref_count, 1);
    if (atomic_load(&ptr->ref_count) == 0)
    {
        magicnet_shared_ptr_free_data(ptr);
        free(ptr);
        return;
    }
}
