#include "magicnet/magicnet.h"
#include "magicnet/config.h"
#include "magicnet/vector.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>

/**
 * @brief A vector of struct magicnet_registered_structure determines the registered
 * structures for this client.
 */
static struct vector *structure_vec;
/**
 * @brief Registered program vector with the possible programs struct magicnet_program
 *
 */
static struct vector *program_vec;

int magicnet_init()
{
    structure_vec = vector_create(sizeof(struct magicnet_registered_structure));
    program_vec = vector_create(sizeof(struct magicnet_program));
    srand(time(NULL));

    return 0;
}

int magicnet_get_structure(int type, struct magicnet_registered_structure *struct_out)
{
    vector_set_peek_pointer(structure_vec, 0);
    int res = -1;
    struct magicnet_registered_structure *current_struct = vector_peek(structure_vec);
    while (current_struct)
    {
        if (current_struct->type == type)
        {
            memcpy(struct_out, current_struct, sizeof(struct magicnet_registered_structure));
            res = 0;
            break;
        }
        current_struct = vector_peek(structure_vec);
    }

    return res;
}

/**
 * @brief Registers the structure on THIS client only, any network operations will be translated
 * based on the structures registered. Only APPLIES to this client only
 *
 * @param type
 * @param size
 * @return int
 */
int magicnet_register_structure(long type, size_t size)
{
    struct magicnet_registered_structure structure = {};
    if (magicnet_get_structure(type, &structure) >= 0)
    {
        return -1;
    }

    // Let's register this network structure so the application can manage it.
    structure.type = type;
    structure.size = size;
    vector_push(structure_vec, &structure);
    return 0;
}

void magicnet_block_send_packet_free(struct magicnet_packet* packet)
{
    struct magicnet_block_send* block_send_packet = &magicnet_signed_data(packet)->payload.block_send;
    vector_set_peek_pointer(block_send_packet->blocks, 0);
    struct block* block = vector_peek_ptr(block_send_packet->blocks);
    while(block)
    {
        // To be dealth with later.
        block->transaction_group = NULL;
        block_free(block);
        block = vector_peek_ptr(block_send_packet->blocks);
    }

    // Here we go we free transaction group here.
    block_transaction_group_free(block_send_packet->transaction_group);
}
void magicnet_free_packet_pointers(struct magicnet_packet* packet)
{   
    if (!packet)
    {
        return;
    }
    switch(magicnet_signed_data(packet)->type)
    {
        case MAGICNET_PACKET_TYPE_EMPTY_PACKET:

        break;
        
        case MAGICNET_PACKET_TYPE_NOT_FOUND:

        break;

        case MAGICNET_PACKET_TYPE_PING:

        break;

        case MAGICNET_PACKET_TYPE_POLL_PACKETS:

        break;

        case MAGICNET_PACKET_TYPE_PONG:

        break;

        case MAGICNET_PACKET_TYPE_USER_DEFINED:
            free(magicnet_signed_data(packet)->payload.user_defined.data);
        break;

        case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
            block_transaction_free(magicnet_signed_data(packet)->payload.transaction_send.transaction);
            break;

        case MAGICNET_PACKET_TYPE_BLOCK_SEND:
            magicnet_block_send_packet_free(packet);
            break;



        case MAGICNET_PACKET_TYPE_SERVER_SYNC:
            
            break;
    }

}

void magicnet_free_packet(struct magicnet_packet* packet)
{   
    magicnet_free_packet_pointers(packet);
    free(packet);
}
struct magicnet_program *magicnet_get_program(const char *name)
{
    vector_set_peek_pointer(program_vec, 0);
    struct magicnet_program *program = vector_peek(program_vec);
    while (program)
    {
        if (strncmp(program->name, name, sizeof(program->name)) == 0)
        {
            // A match?
            break;
        }
        program = vector_peek(program_vec);
    }

    return program;
}

void magicnet_reconnect(struct magicnet_program* program)
{
    struct magicnet_client *client = magicnet_tcp_network_connect(MAGICNET_LOCAL_SERVER_ADDRESS, MAGICNET_SERVER_PORT, MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE, program->name);
    if (!client)
    {
        return;
    }
    program->client = client;

}


int _magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet, bool reconnect_if_required)
{
    struct magicnet_registered_structure structure = {};
    struct magicnet_packet magicnet_packet= {};
    if (magicnet_get_structure(packet_type, &structure) < 0)
    {
        return -1;
    }

    magicnet_packet.signed_data.id = rand() % 999999999;
    magicnet_packet.signed_data.type = MAGICNET_PACKET_TYPE_USER_DEFINED;
    magicnet_packet.signed_data.payload.user_defined.type = packet_type;
    strncpy(magicnet_packet.signed_data.payload.user_defined.program_name, program->name, sizeof(magicnet_packet.signed_data.payload.user_defined.program_name));
    magicnet_packet.signed_data.payload.user_defined.data = calloc(1, structure.size);
    magicnet_packet.signed_data.payload.user_defined.data_len = structure.size;
    memcpy(magicnet_packet.signed_data.payload.user_defined.data, packet, structure.size);
    int res = magicnet_client_write_packet(program->client, &magicnet_packet, 0);
    if (res < 0)
    {
        goto out;
    }

out:
    // Now we have sent the packet we can free the data payload.
    if (magicnet_packet.signed_data.payload.user_defined.data)
    {
        free(magicnet_packet.signed_data.payload.user_defined.data);
    }
    if (res < 0)
    {
        if (reconnect_if_required)
        {
            res = _magicnet_send_packet(program, packet_type, packet, false);
        }
    }
    return res;
}

int _magicnet_make_transaction(struct magicnet_program* program, void* data, size_t size, bool reconnect_if_required)
{
    int res = 0;
    struct magicnet_packet* packet = magicnet_packet_new();
    struct block_transaction* transaction = block_transaction_build(program->name, data, size);

    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_TRANSACTION_SEND;
    magicnet_signed_data(packet)->payload.transaction_send.transaction = transaction;
    res = magicnet_client_write_packet(program->client, packet, 0);
    if (res < 0)
    {
        goto out;
    }

out:
    if (res < 0)
    {
        if (reconnect_if_required)
        {
            res = _magicnet_make_transaction(program, data, size, false);
        }
    }
    magicnet_free_packet(packet);
    return res;
}

int magicnet_make_transaction(struct magicnet_program* program, void* data, size_t size)
{
    return _magicnet_make_transaction(program, data, size, true);
}

int magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet)
{
   return _magicnet_send_packet(program, packet_type, packet, true);
}

int _magicnet_next_packet(struct magicnet_program *program, void** packet_out, bool reconnect_if_neccessary)
{
   int res = 0;
    struct magicnet_packet *packet = magicnet_packet_new();
    struct magicnet_client *client = program->client;
    struct magicnet_packet* packet_to_send = magicnet_packet_new();
    packet_to_send->signed_data.type = MAGICNET_PACKET_TYPE_POLL_PACKETS;
    // First we poll to see if thiers packets for us
    bool packet_found = false;
    while (!packet_found)
    {
        res = magicnet_client_write_packet(client, packet_to_send, 0);
        if (res < 0)
        {
            goto out;
        }
        if (magicnet_client_read_packet(client, packet) < 0)
        {
            res = -1;
            goto out;
        }
        packet_found = true;
        if (magicnet_signed_data(packet)->type != MAGICNET_PACKET_TYPE_USER_DEFINED)
        {
            // Someone sent as a dodgy packet. we only want user defined packets.
            // Do cleanup.
            packet_found = false;
        }
        if (magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND)
        {
            packet_found = false;
        }

        if (!packet_found)
        {
            // We've to wait a bit.. lets not do damage.
            usleep(5000000);
        }
    }

    int payload_packet_type = magicnet_signed_data(packet)->payload.user_defined.type;
    struct magicnet_registered_structure structure;
    res = magicnet_get_structure(payload_packet_type, &structure);
    if (res < 0)
    {
        // We aren't aware of this structure.
        goto out;
    }
    res = payload_packet_type;
    void* data = calloc(1, structure.size);
    memcpy(data, magicnet_signed_data(packet)->payload.user_defined.data, structure.size);
    *packet_out = data;
out:
    if (res < 0 && reconnect_if_neccessary)
    {
        magicnet_reconnect(program);
        res = _magicnet_next_packet(program, packet_out, false);
    }
    magicnet_free_packet(packet);
    magicnet_free_packet(packet_to_send);
    return res;
}

int magicnet_next_packet(struct magicnet_program *program, void** packet_out)
{
    return _magicnet_next_packet(program, packet_out, true);
}

struct magicnet_program *magicnet_program(const char *name)
{
    int res = 0;
    struct magicnet_program *program = magicnet_get_program(name);
    if (program)
    {
        // We already got the program
        return program;
    }

    // We must register the program

    program = calloc(1, sizeof(struct magicnet_program));
    strncpy(program->name, name, sizeof(program->name));
    vector_push(program_vec, program);

    struct magicnet_client *client = magicnet_tcp_network_connect(MAGICNET_LOCAL_SERVER_ADDRESS, MAGICNET_SERVER_PORT, MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE, name);
    if (!client)
    {
        res = -1;
        goto out;
    }
    program->client = client;
out:
    if (res < 0)
    {
        free(program);
        program = NULL;
    }
    return program;
}