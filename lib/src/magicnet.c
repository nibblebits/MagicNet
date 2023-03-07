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

struct magicnet_transactions *magicnet_transactions_new(struct vector *block_transactions_vec);


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

void magicnet_block_send_packet_free(struct magicnet_packet *packet)
{
    struct magicnet_block_send *block_send_packet = &magicnet_signed_data(packet)->payload.block_send;
    vector_set_peek_pointer(block_send_packet->blocks, 0);
    struct block *block = vector_peek_ptr(block_send_packet->blocks);
    while (block)
    {
        block_free(block);
        block = vector_peek_ptr(block_send_packet->blocks);
    }

    // Here we go we free transaction group here.
    block_transaction_group_free(block_send_packet->transaction_group);
    vector_free(block_send_packet->blocks);
}


void magicnet_transactions_list_response_packet_free(struct magicnet_packet* packet)
{
    block_transaction_vector_free(magicnet_signed_data(packet)->payload.transaction_list_response.transactions);
}

void magicnet_free_packet_pointers(struct magicnet_packet *packet)
{
    if (!packet)
    {
        return;
    }
    switch (magicnet_signed_data(packet)->type)
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


    case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_REQUEST:

        break;

    case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_RESPONSE:
        magicnet_transactions_list_response_packet_free(packet);
        break;
    case MAGICNET_PACKET_TYPE_SERVER_SYNC:

        break;
    }
}

void magicnet_free_packet(struct magicnet_packet *packet)
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

void magicnet_reconnect(struct magicnet_program *program)
{
    struct magicnet_client *client = magicnet_tcp_network_connect_for_ip(MAGICNET_LOCAL_SERVER_ADDRESS, MAGICNET_SERVER_PORT, MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE, program->name);
    if (!client)
    {
        return;
    }
    program->client = client;
}

int _magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet, bool reconnect_if_required)
{
    struct magicnet_registered_structure structure = {};
    struct magicnet_packet magicnet_packet = {};
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

int _magicnet_make_transaction(struct magicnet_program *program, int type, void *data, size_t size, bool reconnect_if_required)
{
    int res = 0;
    struct magicnet_packet *packet = magicnet_packet_new();
    struct block_transaction *transaction = block_transaction_build(program->name, data, size);
    transaction->type = type;
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
            res = _magicnet_make_transaction(program, type, data, size, false);
        }
    }
    magicnet_free_packet(packet);
    return res;
}

int magicnet_make_transaction(struct magicnet_program *program, int type, void *data, size_t size)
{
    return _magicnet_make_transaction(program, type, data, size, true);
}

int magicnet_make_transaction_using_buffer(struct magicnet_program *program, int type, struct buffer *buffer)
{
    return magicnet_make_transaction(program, type, buffer->data, buffer->len);
}

int magicnet_update_transaction_payload(struct block_transaction* transaction, void* ptr, size_t size)
{
    if (transaction->data.ptr)
    {
        free(transaction->data.ptr);
    }
    transaction->data.ptr = calloc(1, size);
    transaction->data.size = size;
    memcpy(transaction->data.ptr, ptr, size);
    return 0;
}

void magicnet_money_transfer_data_write_to_buffer(struct buffer* buffer, struct block_transaction_money_transfer *money_transfer)
{
    buffer_write_double(buffer, money_transfer->amount);
    buffer_write_bytes(buffer, &money_transfer->recipient_key, sizeof(money_transfer->recipient_key));
    buffer_write_double(buffer, money_transfer->new_balances.recipient_balance);
    buffer_write_double(buffer, money_transfer->new_balances.sender_balance);
}

int magicnet_money_transfer_data_write(struct block_transaction* transaction, struct block_transaction_money_transfer *money_transfer)
{
    struct buffer *buffer = buffer_create();
    magicnet_money_transfer_data_write_to_buffer(buffer, money_transfer);
    magicnet_update_transaction_payload(transaction, buffer->data, buffer->len);
    buffer_free(buffer);
    return 0;
}

/**
 * This function creates a money transfer transaction and sends money
 */
int magicnet_make_money_transfer(struct magicnet_program *program, const char *to, double amount)
{
    int res = 0;
    struct block_transaction_money_transfer money_transfer = {};
    money_transfer.recipient_key = MAGICNET_key_from_string(to);
    // With a null transfer funding the server will figure out how to send that amount.
    money_transfer.amount = amount;

    // OKay lets create a buffer and write the transfer data
    struct buffer *buffer = buffer_create();
    magicnet_money_transfer_data_write_to_buffer(buffer, &money_transfer);
    res = magicnet_make_transaction_using_buffer(program, MAGICNET_TRANSACTION_TYPE_COIN_SEND, buffer);
    buffer_free(buffer);
    return res;
}

int magicnet_money_transfer_data(struct block_transaction* transaction, struct block_transaction_money_transfer* money_transfer)
{
    int res = 0;
    struct buffer *buffer = buffer_wrap(transaction->data.ptr, transaction->data.size);
    res = buffer_read_double(buffer, &money_transfer->amount);
    if (res < 0)
    {
        goto out;
    }
    res = buffer_read_bytes(buffer, &money_transfer->recipient_key, sizeof(money_transfer->recipient_key));
    if (res < 0)
    {
        goto out;
    }
    res = buffer_read_double(buffer, &money_transfer->new_balances.recipient_balance);
    if (res < 0)
    {
        goto out;
    }
    res = buffer_read_double(buffer, &money_transfer->new_balances.sender_balance);
    if (res < 0)
    {
        goto out;
    }

out:
    buffer_free(buffer);
    return res;
}


int magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet)
{
    return _magicnet_send_packet(program, packet_type, packet, true);
}

int _magicnet_next_packet(struct magicnet_program *program, void **packet_out, bool reconnect_if_neccessary)
{
    int res = 0;
    struct magicnet_packet *packet = magicnet_packet_new();
    struct magicnet_client *client = program->client;
    struct magicnet_packet *packet_to_send = magicnet_packet_new();
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
    void *data = calloc(1, structure.size);
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

int magicnet_next_packet(struct magicnet_program *program, void **packet_out)
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

    struct magicnet_client *client = magicnet_tcp_network_connect_for_ip(MAGICNET_LOCAL_SERVER_ADDRESS, MAGICNET_SERVER_PORT, MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE, name);
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

void magicnet_transactions_request_init(struct magicnet_transactions_request *request)
{
    memset(request, 0, sizeof(struct magicnet_transactions_request));
    request->type = -1;
    request->total_per_page = MAGICNET_MAX_TRANSACTIONS_IN_TRANSACTIONS_LIST_REQUEST;
    request->page = 1;
}

void magicnet_transactions_request_set_flag(struct magicnet_transactions_request * request, int flag)
{
    request->flags |= flag;
}

void magicnet_transactions_request_set_type(struct magicnet_transactions_request *request, int type)
{
    request->type = type;
}

void magicnet_transactions_request_set_total_per_page(struct magicnet_transactions_request *request, int total_per_page)
{
    request->total_per_page = total_per_page;
}


void magicnet_transactions_request_set_page(struct magicnet_transactions_request *request, int page)
{
    request->page = page;
}

void magicnet_transactions_request_set_key(struct magicnet_transactions_request *request, struct key* key)
{
    memcpy(&request->key, key, sizeof(request->key));
}

// set target key
void magicnet_transactions_request_set_target_key(struct magicnet_transactions_request *request, struct key *target_key)
{
    memcpy(&request->target_key, target_key, sizeof(request->target_key));
}
void magicnet_transactions_request_remove_transaction_group_hash(struct magicnet_transactions_request *request)
{
    bzero(request->transaction_group_hash, sizeof(request->transaction_group_hash));
}


void magicnet_transactions_request_set_transaction_group_hash(struct magicnet_transactions_request *request, const char *transaction_group_hash)
{
    strncpy(request->transaction_group_hash, transaction_group_hash, sizeof(request->transaction_group_hash));
}


void magicnet_transactions_request_remove_block_hash(struct magicnet_transactions_request* request)
{
    bzero(request->block_hash, sizeof(request->block_hash));
}

void magicnet_transactions_request_set_block_hash(struct magicnet_transactions_request* request, const char* hash)
{
    bzero(request->block_hash, sizeof(request->block_hash));
    strncpy(request->block_hash, hash, sizeof(request->block_hash));
}

struct magicnet_transactions *magicnet_transactions_request(struct magicnet_program *program, struct magicnet_transactions_request* request_data)
{
    // Create transaction list packet
    int res = 0;
    struct magicnet_transactions* transactions = NULL;
    struct magicnet_packet *packet = magicnet_packet_new();
    struct magicnet_packet* response_packet = magicnet_packet_new();
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_TRANSACTION_LIST_REQUEST;
    magicnet_signed_data(packet)->payload.transaction_list_request.req = *request_data;

    // Send packet
    struct magicnet_client *client = program->client;
    res = magicnet_client_write_packet(client, packet, 0);
    if (res < 0)
    {
        goto out;
    }

    // Read a response packet
    res = magicnet_client_read_packet(client, response_packet);
    if (res < 0)
    {
        goto out;
    }
    if (magicnet_signed_data(response_packet)->type != MAGICNET_PACKET_TYPE_TRANSACTION_LIST_RESPONSE)
    {
        // We got a dodgy packet
        res = -1;
        goto out;
    }

    transactions = magicnet_transactions_new(magicnet_signed_data(response_packet)->payload.transaction_list_response.transactions);
    
    // Switch to the next page
    request_data->page++;

out:    
    magicnet_free_packet(packet);
    magicnet_free_packet(response_packet);
    return transactions;

}

struct magicnet_transactions *magicnet_transactions_new(struct vector *block_transactions_vec)
{
    struct magicnet_transactions *transactions = calloc(1, sizeof(struct magicnet_transactions));
    size_t total_transactions = vector_count(block_transactions_vec);
    transactions->transactions = calloc(1, sizeof(struct block_transaction) * total_transactions);
    vector_set_peek_pointer(block_transactions_vec, 0);
    struct block_transaction *transaction = vector_peek_ptr(block_transactions_vec);
    int i = 0;
    while (transaction)
    {
        transactions->transactions[i] = block_transaction_clone(transaction);
        transaction = vector_peek_ptr(block_transactions_vec);
        i++;
    }

    transactions->amount = total_transactions;
    return transactions;
}

void magicnet_transactions_free(struct magicnet_transactions *transactions)
{
    // Free the transactions
    for (int i = 0; i < transactions->amount; i++)
    {
        block_transaction_free(transactions->transactions[i]);
    }
    free(transactions);
}
