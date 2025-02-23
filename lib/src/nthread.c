#include "nthread.h"
#include "vector.h"
#include <stdio.h>
#include <stdlib.h>
struct magicnet_nthread *nthread = NULL;

//fwd declared..
void magicnet_threads_action_free(struct magicnet_nthread_action *action);

int magicnet_threads_nthread_init()
{
    int res = 0;
    nthread = calloc(1, sizeof(struct magicnet_nthread));
    if (!nthread)
    {
        res = -1;
        goto out;
    }

    nthread->threads = vector_create(sizeof(struct magicnet_nthread_thread *));
    if (!nthread->threads)
    {
        res = -1;
        goto out;
    }

    // initialize the mutex
    pthread_mutex_init(&nthread->mutex, NULL);

out:
    if (res < 0)
    {
        if (nthread && nthread->threads)
        {
            vector_free(nthread->threads);
            nthread->threads = NULL;
        }

        if (nthread)
        {
            free(nthread);
            nthread = NULL;
        }
    }
    return res;
}

int magicnet_thread_new(struct magicnet_nthread_thread **thread_out)
{
    int res = 0;
    struct magicnet_nthread_thread *thread =
        calloc(1, sizeof(struct magicnet_nthread_thread));
    if (!thread)
    {
        res = -1;
        goto out;
    }

    thread->actions = vector_create(sizeof(struct magicnet_nthread_action *));
    if (!thread->actions)
    {
        goto out;
    }
    // Initialize the mutex
    pthread_mutex_init(&thread->thread.mutex, NULL);

    // Push to the threads vector.
    pthread_mutex_lock(&nthread->mutex);
    vector_push(nthread->threads, &thread);
    pthread_mutex_unlock(&nthread->mutex);

    if (thread_out)
    {
        *thread_out = thread;
    }
out:
    if (res < 0)
    {
        if (thread && thread->actions)
        {
            vector_free(thread->actions);
            thread->actions = NULL;
        }

        if (thread)
        {
            free(thread);
            thread = NULL;
        }
    }
    return res;
}

int magicnet_threads_begin(int t_threads)
{
    int res = 0;
    for (int i = 0; i < t_threads; i++)
    {
        struct magicnet_nthread_thread *thread = NULL;
        res = magicnet_thread_new(&thread);
        if (res < 0)
        {
            break;
        }

        // let's start the thread
        res = magicnet_nthread_thread_start(thread);
        if (res < 0)
        {
            break;
        }
    }
    return res;
}
int magicnet_threads_init(int t_threads)
{
    int res = 0;

    // initialize the root structure
    res = magicnet_threads_nthread_init();
    if (res < 0)
    {
        goto out;
    }

    // We have a thread vector , lets start the threads
    res = magicnet_threads_begin(t_threads);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

void *magicnet_nthread_thread_pthread_function(void *nthread_ptr)
{
    struct magicnet_nthread_thread *thread = (struct magicnet_nthread_thread *)nthread_ptr;

    while (1)
    {
        // Infinite loop for these threads, with a little sleeping
        // come back later to add ability to shut them down

        // Lets loop through all the actions
        vector_set_peek_pointer(thread->actions, 0);
        struct magicnet_nthread_action *action = vector_peek_ptr(thread->actions);
        while (action)
        {
            // now let's call the poll function of the action
            int res = action->poll(action);
            if (res < 0 || res == MAGICNET_ACTION_POLL_END)
            {
                // This action has completed whatever it wanted to do
                // or an error occured, we are done with it
                vector_pop_last_peek(thread->actions);
                // Free the action
                magicnet_threads_action_free(action);
            }
            action = vector_peek_ptr(thread->actions);
        }
        usleep(100);
    }
    return NULL;
}
int magicnet_nthread_thread_start(struct magicnet_nthread_thread *thread)
{
    int res = 0;
    pthread_mutex_lock(&thread->thread.mutex);
    // Are we already running?
    if (thread->flags & MAGICNET_NTHREAD_FLAG_RUNNING)
    {
        // then no need to start again
        res = -1;
        goto out;
    }

    res = pthread_create(&thread->thread.id, NULL,
                         magicnet_nthread_thread_pthread_function, thread);

    if (res < 0)
    {
        goto out;
    }
    thread->flags |= MAGICNET_NTHREAD_FLAG_RUNNING;
out:
    pthread_mutex_unlock(&thread->thread.mutex);
    return res;
}
struct magicnet_nthread_action *magicnet_threads_action_new(MAGICNET_NTHREAD_POLL_FUNCTION poll_function, void *private_data, MAGICNET_NTHREAD_FREE_PRIVATE_FUNCTION free_private)
{
    struct magicnet_nthread_action *action = calloc(1, sizeof(struct magicnet_nthread_action));
    if (!action)
    {
        return NULL;
    }

    action->poll = poll_function;
    action->private = private_data;
    action->free_private = free_private;

    return action;
}

void magicnet_threads_action_free(struct magicnet_nthread_action *action)
{
    // Let's free the action data
    if (action->free_private)
    {
        action->free_private(action, action->private);
    }

    // now ourselves
    free(action);
}

int magicnet_threads_push_action_to_thread(struct magicnet_nthread_thread *thread, struct magicnet_nthread_action *action)
{
    int res = 0;
    pthread_mutex_lock(&thread->thread.mutex);
    vector_push(thread->actions, &action);
    pthread_mutex_unlock(&thread->thread.mutex);
    return res;
}

struct magicnet_nthread_thread *magicnet_threads_next_thread_for_push()
{
    struct magicnet_nthread_thread *thread = NULL;

    thread = (struct magicnet_nthread_thread *)vector_peek_ptr_at(nthread->threads, nthread->next_thread_index_push);
    if (!thread)
    {
        // Not found? alright lets just get index zero
        thread = vector_peek_ptr_at(nthread->threads, 0);
        // reset the next pointer too, to index 1 since we just took zero.
        nthread->next_thread_index_push = 1;
    }

    return thread;
}

int magicnet_threads_push_action(struct magicnet_nthread_action *action)
{
    struct magicnet_nthread_thread *nthread = magicnet_threads_next_thread_for_push();
    if (!nthread)
    {
        return -1;
    }

    return magicnet_threads_push_action_to_thread(nthread, action);
}