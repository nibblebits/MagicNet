
/**
 * Think of a better name soon..
 * 
 * THis attempts to solve a problem where a mutex is owned by the object
 * that is being deleted, we will abstract it out.
 */
#ifndef MAGICNET_SHARED_MUTEX_OBJ
#define MAGICNET_SHARED_MUTEX_OBJ

// allows it to look like your defining a type
// for code cleanliness not compiler correctness.
#define MAGICNET_SHARED_MUTEX_OBJECT(x) struct magicnet_shared_mutex_obj

typedef void (*MAGICNET_SHARED_MUTEX_OBJ_FREE_DATA_FUNCTION)(void* data);
#include <pthread.h>
#include <stdbool.h>

enum
{
    MAGICNET_SHARED_MUTEX_OBJ_FLAG_STALE = 0b00000001,
};
struct magicnet_shared_mutex_obj
{
    int flags;
    // Pointer to the data of the object
    void* data;

    // refcount for this shared pointer data, data will not be freed until its zero
    int owner_refcount;

    // refcount for the viewer of this data they aren't owners
    // when viewer_refcount == 0 and owner_refcount == 0 the mutex is freed
    // along with the whole object.
    int viewer_refcount;

    // Used by the internal system to prevent data-races
    // more powerful than atomic for what we need.
    pthread_mutex_t* refcount_mutex;

    // Mutex for the data only, not used by the shared mutex functionality
    // only by the programmer whome wishes to lock the object inside in data.
    pthread_mutex_t* mutex;

    struct
    {
        MAGICNET_SHARED_MUTEX_OBJ_FREE_DATA_FUNCTION free_data;
    } functions;
};
struct magicnet_shared_mutex_obj *magicnet_shared_mutex_obj_create_hold_as_owner(void *data, MAGICNET_SHARED_MUTEX_OBJ_FREE_DATA_FUNCTION free_data_func, struct magicnet_shared_mutex_obj *recycle_obj);

void *magicnet_shared_mutex_obj_owner_hold(struct magicnet_shared_mutex_obj *mutex_obj);
bool magicnet_shared_mutex_obj_is_stale(struct magicnet_shared_mutex_obj* mutex_obj);
void magicnet_shared_mutex_obj_owner_release(struct magicnet_shared_mutex_obj *mutex_obj);
void magicnet_shared_mutex_obj_viewer_hold(struct magicnet_shared_mutex_obj *mutex_obj);
void magicnet_shared_mutex_obj_viewer_release(struct magicnet_shared_mutex_obj *mutex_obj);
void magicnet_shared_mutex_obj_lock(struct magicnet_shared_mutex_obj *mutex_obj);
void magicnet_shared_mutex_obj_unlock(struct magicnet_shared_mutex_obj *mutex_obj);
int magicnet_shared_mutex_obj_fill(struct magicnet_shared_mutex_obj *obj, void *data, MAGICNET_SHARED_MUTEX_OBJ_FREE_DATA_FUNCTION free_data_func);
#endif