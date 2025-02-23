#ifndef MAGICNET_NTHREAD_H
#define MAGICNET_NTHREAD_H
#include <pthread.h>
#include <unistd.h>

#include "vector.h"

enum
{
    MAGICNET_ACTION_POLL_CONTINUE,
    MAGICNET_ACTION_POLL_END
};

//fwd declare..
struct magicnet_nthread_action;

// Poll function will be called on every cycle
// return -1 if your done with the thread action or return MAGICNET_POLL_END
// and want to no longer be polled
typedef int (*MAGICNET_NTHREAD_POLL_FUNCTION)(struct magicnet_nthread_action* action);

/**
 * Implementor must only free his private data
 * do not touch the memory of the nthread action.
 */
typedef void (*MAGICNET_NTHREAD_FREE_PRIVATE_FUNCTION)(struct magicnet_nthread_action* action, void* private_data);
struct magicnet_nthread_action
{

    // Called every cycle, return -1 to remove this action
    MAGICNET_NTHREAD_POLL_FUNCTION poll;
    // Every action must have this pointer to handle its private data 
    // freeing...
    MAGICNET_NTHREAD_FREE_PRIVATE_FUNCTION free_private;

    // Private data belogning to the action
    void* private;
};

enum
{
    MAGICNET_NTHREAD_FLAG_RUNNING = 0b00000001
};

struct magicnet_nthread_thread
{

    // vector of magicnet_nthread_action*
    // every action will poll
    // return -1 to remove the action.
    // || return MAGICNET_POLL_END
    struct vector* actions;
    struct
    {
        pthread_t id;
        // for locking operations involving the actions vector.
        // or any other part of the thread that needs to be synced.
        // Becareful for dead locks, if magicnet_nthread has aquired a lock.
        pthread_mutex_t mutex;
    } thread;

    int flags;
};


struct magicnet_nthread
{
    // Vector of threads
    struct vector* threads;

    // We will have a round robin type of setup here for pushing
    // Equal to the index in the vector of the therad
    // we should next push actions too.
    size_t next_thread_index_push;
    

    //  Lock, for pushes to the threads vector
    pthread_mutex_t mutex;
};

/**
 * Pushes an action that needs to be dealt with to the thread pool
 * return zero if you want to keep being called every cycle, otherwise
 * return negative or enum definition to end...
 * 
 */
int magicnet_threads_push_action(struct magicnet_nthread_action* action);
int magicnet_threads_push_action_to_thread(struct magicnet_nthread_thread* thread, struct magicnet_nthread_action* action);
struct magicnet_nthread_action *magicnet_threads_action_new(MAGICNET_NTHREAD_POLL_FUNCTION poll_function, void *private_data, MAGICNET_NTHREAD_FREE_PRIVATE_FUNCTION free_private);
int magicnet_nthread_thread_start(struct magicnet_nthread_thread* thread);
int magicnet_threads_init(int t_threads);

#endif