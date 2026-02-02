#include "magicnet/magicnet.h"
#include "magicnet/config.h"
#include "magicnet/vector.h"
#include "magicnet/nthread.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>

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
int magicnet_program_client_thread_poll(struct magicnet_nthread_action *action);
void magicnet_program_client_thread_poll_free(struct magicnet_nthread_action *action, void *private_data);

int mn_set_flags;

// not a multi-threading problem... hmm..
extern pthread_mutex_t tmp_mutex;

int magicnet_init(int flags, int t_threads)
{
    structure_vec = vector_create(sizeof(struct magicnet_registered_structure));
    program_vec = vector_create(sizeof(struct magicnet_program));
    srand(time(NULL));
    mn_set_flags = flags;

    pthread_mutex_init(&tmp_mutex, NULL);

    if (t_threads == 0)
    {
        // For now we require at least one thread
        t_threads = 1;
    }

    // Let's get those threads going.
    magicnet_threads_init(t_threads);

    return 0;
}

int magicnet_flags()
{
    return mn_set_flags;
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

    vector_free(block_send_packet->blocks);
}

void magicnet_transactions_list_response_packet_free(struct magicnet_packet *packet)
{
    block_transaction_vector_free(magicnet_signed_data(packet)->payload.transaction_list_response.transactions);
}

void magicnet_events_res_packet_free(struct magicnet_packet *packet)
{
    if (!magicnet_signed_data(packet)->payload.events_poll_res.events)
    {
        // Events already freed or not available since its NULL? then nothing to do
        return;
    }

    magicnet_events_vector_free(magicnet_signed_data(packet)->payload.events_poll_res.events);
}

void magicnet_reqres_req_packet_free(struct magicnet_packet *packet)
{
    if (magicnet_signed_data(packet)->payload.request_and_respond.input_data)
    {
        magicnet_reqres_input_data_free(magicnet_signed_data(packet)->payload.request_and_respond.input_data);
    }
}

void magicnet_reqres_res_packet_free(struct magicnet_packet *packet)
{
    if (magicnet_signed_data(packet)->payload.request_and_respond_response.output_data)
    {
        magicnet_reqres_output_data_free(magicnet_signed_data(packet)->payload.request_and_respond_response.output_data);
    }
}

void magicnet_free_packet_pointers(struct magicnet_packet *packet)
{
    if (!packet)
    {
        return;
    }

    // We shall free the tmp_buf
    if (packet->not_sent.tmp_buf)
    {
        buffer_free(packet->not_sent.tmp_buf);
        packet->not_sent.tmp_buf = NULL;
    }

    if (magicnet_signed_data(packet)->flags & MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE)
    {
        magicnet_council_certificate_free(magicnet_signed_data(packet)->my_certificate);
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

    case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        // Free the council certificate
        if (magicnet_signed_data(packet)->payload.verifier_signup.certificate)
        {
            magicnet_council_certificate_free(magicnet_signed_data(packet)->payload.verifier_signup.certificate);
        }
        break;
    case MAGICNET_PACKET_TYPE_BLOCK_SEND:
        magicnet_block_send_packet_free(packet);
        break;

    case MAGICNET_PACKET_TYPE_EVENTS_RES:
        magicnet_events_res_packet_free(packet);
        break;

    case MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND:
        magicnet_reqres_req_packet_free(packet);
        break;

    case MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND_RESPONSE:
        magicnet_reqres_res_packet_free(packet);
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

void magicnet_packet_free(struct magicnet_packet *packet)
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
    // Kill the old client..
    magicnet_close(program->client);
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

    // Use a secure random... temporary..
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
    magicnet_packet_free(packet);
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

int magicnet_update_transaction_payload(struct block_transaction *transaction, void *ptr, size_t size)
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

int magicnet_read_transaction_council_certificate_initiate_transfer_data(struct block_transaction *transaction, struct block_transaction_council_certificate_initiate_transfer_request *council_certificate_transfer)
{
    int res = 0;
    if (transaction->type != MAGICNET_TRANSACTION_TYPE_INITIATE_CERTIFICATE_TRANSFER)
    {
        res = -1;
        goto out;
    }

    struct buffer *buffer = buffer_wrap(transaction->data.ptr, transaction->data.size);
    res = buffer_read_int(buffer, &council_certificate_transfer->flags);
    if (res < 0)
    {
        goto out;
    }

    res = buffer_read_bytes(buffer, council_certificate_transfer->certificate_to_transfer_hash, sizeof(council_certificate_transfer->certificate_to_transfer_hash));
    if (res < 0)
    {
        goto out;
    }
    res = buffer_read_bytes(buffer, &council_certificate_transfer->new_owner_key, sizeof(council_certificate_transfer->new_owner_key));
    if (res < 0)
    {
        goto out;
    }

    // Verify the key
    if (!MAGICNET_key_valid(&council_certificate_transfer->new_owner_key))
    {
        res = -1;
        goto out;
    }

    if (council_certificate_transfer->flags & COUNCIL_CERTIFICATE_TRANSFER_FLAG_INCLUDES_CURRENT_CERTIFICATE)
    {
        // Read the current certificate
        res = magicnet_council_stream_alloc_and_read_certificate(buffer, &council_certificate_transfer->current_certificate);
        if (res < 0)
        {
            magicnet_log("Failed to read the current certificate\n");
            goto out;
        }

        // If we are self transfering also read the new self signed certificate
        if (council_certificate_transfer->flags & COUNCIL_CERTIFICATE_TRANSFER_FLAG_TRANSFER_WITHOUT_VOTE)
        {

            res = magicnet_council_stream_alloc_and_read_certificate(buffer, &council_certificate_transfer->new_unsigned_certificate);
            if (res < 0)
            {
                magicnet_log("Failed to read the new unsigned certificate\n");
                goto out;
            }

            // We should validate the certificate transfer, we cant validate the
            // certificate yet as its not sigend
            res = magicnet_council_certificate_verify(council_certificate_transfer->new_unsigned_certificate, MAGICNET_COUNCIL_CERTIFICATE_VERIFY_FLAG_IGNORE_FINAL_SIGNATURE);
            if (res < 0)
            {
                magicnet_log("Failed to verify the new unsigned certificate\n");
                goto out;
            }
        }
    }

out:
    return res;
}

int magicnet_council_request_certificate(struct magicnet_program *program, const char *council_certificate_hash, struct magicnet_council_certificate **certificate_out)
{
    int res = 0;
    struct request_and_respond_input_data *input_data = magicnet_reqres_input_data_create((void *)council_certificate_hash, strlen(council_certificate_hash));
    struct request_and_respond_output_data *output_data = NULL;
    struct magicnet_council_certificate *certificate = NULL;
    struct buffer *buffer = NULL;
    *certificate_out = NULL;
    res = magicnet_reqres_request(program->client, MAGICNET_REQRES_HANDLER_GET_COUNCIL_CERTIFICATE, input_data, &output_data);
    if (res < 0)
    {
        goto out;
    }

    certificate = magicnet_council_certificate_create();
    if (!output_data->output || output_data->size <= 0)
    {
        res = MAGICNET_ERROR_DATA_NO_LONGER_AVAILABLE;
        goto out;
    }

    buffer = buffer_wrap(output_data->output, output_data->size);
    res = magicnet_council_stream_read_certificate(buffer, certificate);
    if (res < 0)
    {
        goto out;
    }

    *certificate_out = certificate;

out:
    if (output_data)
    {
        magicnet_reqres_output_data_free(output_data);
    }
    if (input_data)
    {
        magicnet_reqres_input_data_free(input_data);
    }
    if (buffer)
    {
        buffer_free(buffer);
    }
    return res;
}

int magicnet_read_transaction_council_certificate_claim_request(struct block_transaction *transaction, struct block_transaction_council_certificate_claim_request *claim_req_out)
{
    int res = 0;
    struct buffer *buffer = buffer_wrap(transaction->data.ptr, transaction->data.size);
    // Read the sha256 certificate transfer request hash
    res = buffer_read_bytes(buffer, claim_req_out->initiate_transfer_transaction_hash, sizeof(claim_req_out->initiate_transfer_transaction_hash));
    if (res < 0)
    {
        goto out;
    }

    // Read the sha256 certificate hash
    res = buffer_read_bytes(buffer, claim_req_out->certificate_hash, sizeof(claim_req_out->certificate_hash));
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}
void magicnet_write_transaction_council_certificate_initiate_transfer_data_to_buffer(struct buffer *buffer, struct block_transaction_council_certificate_initiate_transfer_request *council_certificate_transfer)
{
    buffer_write_int(buffer, council_certificate_transfer->flags);
    buffer_write_bytes(buffer, council_certificate_transfer->certificate_to_transfer_hash, sizeof(council_certificate_transfer->certificate_to_transfer_hash));
    buffer_write_bytes(buffer, &council_certificate_transfer->new_owner_key, sizeof(council_certificate_transfer->new_owner_key));

    // If we have the certificate we should write it
    if (council_certificate_transfer->flags & COUNCIL_CERTIFICATE_TRANSFER_FLAG_INCLUDES_CURRENT_CERTIFICATE)
    {
        magicnet_council_stream_write_certificate(buffer, council_certificate_transfer->current_certificate);
    }

    if (council_certificate_transfer->flags & COUNCIL_CERTIFICATE_TRANSFER_FLAG_INCLUDES_NEW_CERTIFICATE)
    {
        magicnet_council_stream_write_certificate(buffer, council_certificate_transfer->new_unsigned_certificate);
    }
}

void magicnet_write_transaction_council_certificate_claim_request_data_to_buffer(struct buffer *buffer, struct block_transaction_council_certificate_claim_request *claim_req)
{
    buffer_write_bytes(buffer, claim_req->initiate_transfer_transaction_hash, sizeof(claim_req->initiate_transfer_transaction_hash));
    buffer_write_bytes(buffer, claim_req->certificate_hash, sizeof(claim_req->certificate_hash));
}

int magicnet_certificate_transfer_initiate(struct magicnet_program *program, int flags, const char *certificate_to_transfer_hash, struct key *new_owner_key)
{
    int res = 0;
    struct buffer *buffer = buffer_create();
    struct block_transaction_council_certificate_initiate_transfer_request council_certificate_transfer = {};
    council_certificate_transfer.flags = flags;
    strncpy(council_certificate_transfer.certificate_to_transfer_hash, certificate_to_transfer_hash, sizeof(council_certificate_transfer.certificate_to_transfer_hash));
    if (!MAGICNET_key_valid(new_owner_key))
    {
        res = -1;
        goto out;
    }

    memcpy(&council_certificate_transfer.new_owner_key, new_owner_key, sizeof(council_certificate_transfer.new_owner_key));

    magicnet_write_transaction_council_certificate_initiate_transfer_data_to_buffer(buffer, &council_certificate_transfer);
    res = magicnet_make_transaction_using_buffer(program, MAGICNET_TRANSACTION_TYPE_INITIATE_CERTIFICATE_TRANSFER, buffer);
    if (res < 0)
    {
        goto out;
    }

out:
    buffer_free(buffer);
    return res;
}

int magicnet_certificate_transfer_claim(struct magicnet_program *program, const char *initiate_transfer_transaction_hash, const char *certificate_hash)
{
    int res = 0;
    struct buffer *buffer = buffer_create();
    struct block_transaction_council_certificate_claim_request claim_req = {};
    strncpy(claim_req.initiate_transfer_transaction_hash, initiate_transfer_transaction_hash, sizeof(claim_req.initiate_transfer_transaction_hash));
    strncpy(claim_req.certificate_hash, certificate_hash, sizeof(claim_req.certificate_hash));
    magicnet_write_transaction_council_certificate_claim_request_data_to_buffer(buffer, &claim_req);
    res = magicnet_make_transaction_using_buffer(program, MAGICNET_TRANSACTION_TYPE_CLAIM_CERTIFICATE, buffer);
    buffer_free(buffer);
    return res;
}
void magicnet_money_transfer_data_write_to_buffer(struct buffer *buffer, struct block_transaction_money_transfer *money_transfer)
{
    buffer_write_double(buffer, money_transfer->amount);
    buffer_write_bytes(buffer, &money_transfer->recipient_key, sizeof(money_transfer->recipient_key));
    buffer_write_double(buffer, money_transfer->new_balances.recipient_balance);
    buffer_write_double(buffer, money_transfer->new_balances.sender_balance);
}

int magicnet_money_transfer_data_write(struct block_transaction *transaction, struct block_transaction_money_transfer *money_transfer)
{
    struct buffer *buffer = buffer_create();
    magicnet_money_transfer_data_write_to_buffer(buffer, money_transfer);
    magicnet_update_transaction_payload(transaction, buffer->data, buffer->len);
    buffer_free(buffer);
    return 0;
}

int magicnet_certificate_transfer_data_write(struct block_transaction *transaction, struct block_transaction_council_certificate_initiate_transfer_request *transfer_request)
{
    struct buffer *buffer = buffer_create();
    magicnet_write_transaction_council_certificate_initiate_transfer_data_to_buffer(buffer, transfer_request);
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

int magicnet_money_transfer_data(struct block_transaction *transaction, struct block_transaction_money_transfer *money_transfer)
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

int _magicnet_next_packet(struct magicnet_program *program, void **packet_out)
{
    int res = 0;
    size_t payload_size = 0;
    void *payload_data = NULL;
    void *payload_clone = NULL;
    // We must locate the USER DEFINED PACKET from the monitoring queue
    struct magicnet_packet *packet = magicnet_client_packet_monitoring_packet_queue_find_pop(program->client, MAGICNET_PACKET_TYPE_USER_DEFINED);
    if (!packet)
    {
        res = -1;
        goto out;
    }

    payload_size = magicnet_signed_data(packet)->payload.user_defined.data_len;
    payload_data = magicnet_signed_data(packet)->payload.user_defined.data;
    payload_clone = calloc(1, payload_size);
    if (!payload_clone)
    {
        goto out;
    }
    memcpy(payload_clone, magicnet_signed_data(packet)->payload.user_defined.data, payload_size);

    // We have our clone, transfer it to the caller.
    *packet_out = payload_clone;
    res = magicnet_signed_data(packet)->payload.user_defined.type;
out:
    if (res < 0)
    {
        if (payload_clone)
        {
            free(payload_clone);
        }
        if (packet)
        {
            magicnet_packet_free(packet);
        }
    }
    return res;
}

/**
 * This is a packet in terms of a custom magicnet program
 * not a protocol packet.
 */
int magicnet_next_packet(struct magicnet_program *program, void **packet_out)
{
    int res = -1;
    magicnet_client_lock(program->client);
    res = _magicnet_next_packet(program, packet_out);
out:
    magicnet_client_unlock(program->client);
    return res;
}

struct magicnet_program *magicnet_program_new()
{
    struct magicnet_program *program = calloc(1, sizeof(struct magicnet_program));
    return program;
}

void magicnet_program_free(struct magicnet_program *program)
{
    if (program->client)
    {
        magicnet_close(program->client);
    }
    free(program);
}

int magicnet_program_client_thread_poll_process_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    // Let's process the default protocol
    res = magicnet_default_poll_packet_process(client, packet);
    if (res < 0)
    {
        magicnet_log("%s error processing packet\n", __FUNCTION__);
        goto out;
    }

    magicnet_log("%s processing read packet\n", __FUNCTION__);

out:
    return res;
}

int magicnet_program_client_thread_poll(struct magicnet_nthread_action *action)
{
    int res = 0;

    struct magicnet_client *client = (struct magicnet_client *)action->private;

    res = magicnet_client_poll(client, magicnet_program_client_thread_poll_process_packet);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

void magicnet_program_client_thread_poll_free(struct magicnet_nthread_action *action, void *private_data)
{
    // No need to access the client it has been closed already.
    // by the network
}
struct magicnet_program *magicnet_program(const char *name)
{
    int res = 0;
    // Init the keys so we can deal with verification
    // we cant sign on a localhost client however.
    MAGICNET_keys_init();
    struct magicnet_program *program = magicnet_get_program(name);
    if (program)
    {
        // We already got the program
        return program;
    }

    // We must register the program

    program = magicnet_program_new();
    if (!program)
    {
        res = -1;
        goto out;
    }

    struct magicnet_client *client = magicnet_tcp_network_connect_for_ip(MAGICNET_LOCAL_SERVER_ADDRESS, MAGICNET_SERVER_PORT, MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE, name);
    if (!client)
    {
        res = -1;
        goto out;
    }

    strncpy(program->name, name, sizeof(program->name));
    vector_push(program_vec, program);
    program->client = client;

    // Lets setup monitoring before the threads begin
    // We only care about user defined packets, this is what we must montior
    magicnet_client_monitor_packet_type(client, MAGICNET_PACKET_TYPE_USER_DEFINED);

    struct magicnet_nthread_action *action = magicnet_threads_action_new(magicnet_program_client_thread_poll, client, magicnet_program_client_thread_poll_free);
    if (!action)
    {
        res = -1;
        goto out;
    }

    // Let's push this client to the thread for further polling and processing
    magicnet_threads_push_action(action);

    // Now it will be processed throughout the threads infinitely until negative is returend.
out:
    if (res < 0)
    {
        magicnet_program_free(program);
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

void magicnet_transactions_request_set_flag(struct magicnet_transactions_request *request, int flag)
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

void magicnet_transactions_request_set_key(struct magicnet_transactions_request *request, struct key *key)
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

void magicnet_transactions_request_remove_block_hash(struct magicnet_transactions_request *request)
{
    bzero(request->block_hash, sizeof(request->block_hash));
}

void magicnet_transactions_request_set_block_hash(struct magicnet_transactions_request *request, const char *hash)
{
    bzero(request->block_hash, sizeof(request->block_hash));
    strncpy(request->block_hash, hash, sizeof(request->block_hash));
}

struct magicnet_transactions *magicnet_transactions_request(struct magicnet_program *program, struct magicnet_transactions_request *request_data)
{
    // Create transaction list packet
    int res = 0;
    struct magicnet_transactions *transactions = NULL;
    struct magicnet_packet *packet = magicnet_packet_new();
    struct magicnet_packet *response_packet = magicnet_packet_new();
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
    magicnet_packet_free(packet);
    magicnet_packet_free(response_packet);
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
