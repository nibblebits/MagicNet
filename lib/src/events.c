#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "magicnet/magicnet.h"
#include "magicnet/vector.h"
#include "magicnet/config.h"
#include "magicnet/log.h"


/** EVENT BUILDING FUNCTIONS START HERE **/
int magicnet_event_make_for_block(struct magicnet_event** event_out, struct block* block)
{
    int res = 0;
    struct magicnet_event* event = magicnet_event_new(&(struct magicnet_event){.type=MAGICNET_EVENT_TYPE_NEW_BLOCK,.data.new_block_event.block=block_clone(block)});
    if (!event)
    {
        res = MAGICNET_ERROR_INCOMPATIBLE;
        goto out;
    }

    *event_out = event;

out:
    return res;
}

/** EVENT BUILDING FUNCTIONS END HERE **/







void magicnet_event_release_data_for_event_type_new_block(struct magicnet_event *event)
{
    if (event->data.new_block_event.block)
    {
        block_free(event->data.new_block_event.block);
    }
}

void magicnet_event_release_data(struct magicnet_event *event)
{
    switch (event->type)
    {
    case MAGICNET_EVENT_TYPE_NEW_BLOCK:
        magicnet_event_release_data_for_event_type_new_block(event);
        break;
    }
}
void magicnet_event_release(struct magicnet_event *event)
{
    magicnet_event_release_data(event);
    free(event);
}

struct magicnet_event *magicnet_event_new(struct magicnet_event *event)
{
    struct magicnet_event *new_event = calloc(1, sizeof(struct magicnet_event));
    if (event)
    {
        memcpy(new_event, event, sizeof(struct magicnet_event));
    }

    new_event->id = rand() % 999999999999;
    return new_event;
}

void magicnet_copy_event_data_new_block(struct magicnet_event *copy_to_event, struct magicnet_event *copy_from_event)
{
    copy_to_event->data.new_block_event.block = block_clone(copy_from_event->data.new_block_event.block);
}

void magicnet_copy_event_data(struct magicnet_event *copy_to_event, struct magicnet_event *copy_from_event)
{
    switch (copy_from_event->type)
    {
    case MAGICNET_EVENT_TYPE_NEW_BLOCK:
        magicnet_copy_event_data_new_block(copy_to_event, copy_from_event);
        break;
    }
}
struct magicnet_event *magicnet_copy_event(struct magicnet_event *original_event)
{
    struct magicnet_event *new_event = magicnet_event_new(original_event);
    if (!new_event)
    {
        return NULL;
    }

    magicnet_copy_event_data(new_event, original_event);
    return new_event;
}

struct vector *magicnet_copy_events(struct vector *events_vec_in)
{
    struct vector *new_events_vec = vector_create(sizeof(struct magicnet_event *));
    vector_set_peek_pointer(events_vec_in, 0);
    struct magicnet_event *event = vector_peek_ptr(events_vec_in);
    while (event)
    {
        struct magicnet_event *cloned_event = magicnet_copy_event(event);
        vector_push(new_events_vec, &cloned_event);
        event = vector_peek_ptr(events_vec_in);
    }

    return new_events_vec;
}

void magicnet_events_vector_clone_events_and_push(struct vector* events_from, struct vector* events_to)
{
    vector_set_peek_pointer(events_from, 0);
    struct magicnet_event* event_to_copy = vector_peek_ptr(events_from);
    while(event_to_copy)
    {
        struct magicnet_event* cloned_event = magicnet_copy_event(event_to_copy);
        vector_push(events_to, &cloned_event);
        event_to_copy = vector_peek_ptr(events_from);
    }
}

int _magicnet_events_poll(struct magicnet_program *program, bool reconnect_if_neccessary)
{
    int res = 0;
    struct magicnet_packet* res_packet = magicnet_packet_new();

    struct magicnet_packet *poll_packet = magicnet_packet_new();
    magicnet_signed_data(poll_packet)->type = MAGICNET_PACKET_TYPE_EVENTS_POLL;
    magicnet_signed_data(poll_packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    // We will ask for 10 events for now. replace with definition later..
    magicnet_signed_data(poll_packet)->payload.events_poll.total = MAGICNET_TOTAL_EVENTS_TO_REQUEST;
    res = magicnet_client_write_packet(program->client, poll_packet, 0);
    if (res < 0)
    {
        goto out;
    }

    // Alright lets read the next packet as they should send us one
    res = magicnet_client_read_packet(program->client, res_packet);
    if (res < 0)
    {
        goto out;
    }

    // Alrighty lets go through this packet so we can fill our local client with all the events
    if (magicnet_signed_data(res_packet)->type != MAGICNET_PACKET_TYPE_EVENTS_RES)
    {
        magicnet_error("The server returend a different packet than we was expecting, it returned %i. It is important when using events that no other packets are waiting to be read, ensure other requests are fullfilled before calling this function\n", magicnet_signed_data(res_packet)->type);
        res = MAGICNET_ERROR_INCOMPATIBLE;
        goto out;
    }

    // Feed the events into our program client vector and boom its done.
    magicnet_events_vector_clone_events_and_push(magicnet_signed_data(res_packet)->payload.events_poll_res.events, program->client->events);

out:
    magicnet_free_packet(res_packet);
    if (res < 0 && reconnect_if_neccessary)
    {
        magicnet_reconnect(program);
        // Lets try again..
        res = _magicnet_events_poll(program, false);
    }
    magicnet_free_packet(poll_packet);
    return res;
}


int magicnet_events_poll(struct magicnet_program *program)
{
    return _magicnet_events_poll(program, true);
}

size_t magicnet_client_total_known_events(struct magicnet_client* client)
{
    return vector_count(client->events);
}

bool magicnet_client_has_known_events(struct magicnet_client* client)
{
    return magicnet_client_total_known_events(client) > 0;
}

int magicnet_client_pop_event(struct magicnet_client* client, struct magicnet_event** event)
{
    int res = 0;
    if (!magicnet_client_has_known_events(client))
    {
        res =  MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }

    struct magicnet_event* client_event = vector_peek_ptr_at(client->events, 0);
    vector_pop_at(client->events, 0);
    *event = magicnet_copy_event(client_event);
    // Lets free the event in the vector now.
    magicnet_event_release(client_event);
out:
    return res;
}

int magicnet_client_push_event(struct magicnet_client* client, struct magicnet_event* event)
{
    int res = 0;
    // COnsider renaming this copy_event to event_copy... Bad naming..
    struct magicnet_event* cloned_event = magicnet_copy_event(event);
    vector_push(client->events, &cloned_event);
    return res;
}

bool magicnet_has_queued_events(struct magicnet_program *program)
{
    return magicnet_client_has_known_events(program->client);
}

struct magicnet_event *magicnet_next_event(struct magicnet_program *program)
{
    int res = 0;
    struct magicnet_event *event = NULL;

    // No queued events? Lets poll and find new ones.
    if (!magicnet_has_queued_events(program))
    {
        res = magicnet_events_poll(program);
        if (res < 0)
        {
            goto out;
        }
    }

    // Lets see if we have events now
    if (!magicnet_has_queued_events(program))
    {
        // Still nothing? Alright lets assume theirs no events, but this isnt a failure.
        goto out;
    }

    // Yeah we got queued events alright lets return one.
    event = vector_peek_ptr_at(program->client->events, 0);
    vector_pop_at(program->client->events, 0);

out:
    return event;
}

void magicnet_events_vector_free(struct vector *events_vec)
{
    vector_set_peek_pointer(events_vec, 0);
    struct magicnet_event *event = vector_peek_ptr(events_vec);
    while (event)
    {
        magicnet_event_release(event);
        event = vector_peek_ptr(events_vec);
    }

    vector_free(events_vec);
}

