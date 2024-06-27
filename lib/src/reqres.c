
/**
 * This is the local request and respond system, allows a local magicnet program to request information
 * from the server and be provided with it.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "magicnet.h"
#include "log.h"

static REQUEST_RESPONSE_HANDLER_FUNCTION request_response_handlers[MAGICNET_REQRES_MAX_HANDLERS] = {0};

struct request_and_respond_input_data *magicnet_reqres_input_data_create(void *input_data_ptr, size_t size)
{
    struct request_and_respond_input_data *input_data = calloc(1, sizeof(struct request_and_respond_input_data));
    if (input_data_ptr == NULL || size == 0)
    {
        return input_data;
    }
    input_data->input = calloc(size, sizeof(char));
    input_data->size = size;
    memcpy(input_data->input, input_data_ptr, size);
    return input_data;
}

struct request_and_respond_input_data *magicnet_reqres_input_data_clone(struct request_and_respond_input_data *input_data)
{
    if (!input_data)
    {
        return magicnet_reqres_input_data_create(NULL, 0);
    }
    return magicnet_reqres_input_data_create(input_data->input, input_data->size);
}

struct request_and_respond_output_data *magicnet_reqres_output_data_create(void *output_data_ptr, size_t size)
{
    struct request_and_respond_output_data *output_data = calloc(1, sizeof(struct request_and_respond_output_data));
    if (output_data_ptr == NULL || size == 0)
    {
        return output_data;
    }

    output_data->output = calloc(size, sizeof(char));
    output_data->size = size;
    memcpy(output_data->output, output_data_ptr, size);
    return output_data;
}

struct request_and_respond_output_data *magicnet_reqres_output_data_clone(struct request_and_respond_output_data *output_data)
{
    if (!output_data)
    {
        return magicnet_reqres_output_data_create(NULL, 0);
    }
    return magicnet_reqres_output_data_create(output_data->output, output_data->size);
}

void magicnet_reqres_output_data_free(struct request_and_respond_output_data *output_data)
{
    if (output_data->output)
    {
        free(output_data->output);
    }
    free(output_data);
}

void magicnet_reqres_input_data_free(struct request_and_respond_input_data *input_data)
{
    if (input_data->input)
    {
        free(input_data->input);
    }
    free(input_data);
}

int magicnet_reqres_validate_response_packet(struct magicnet_packet *response_packet)
{
    int res = 0;
    // If its a not found packet return not found
    if (magicnet_signed_data(response_packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
    }
    else if (magicnet_signed_data(response_packet)->type != MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND_RESPONSE)
    {
        // We had an unexpected response packet..
        res = MAGICNET_ERROR_CRITICAL_ERROR;
    }
    return res;
}

/**
 * Requests information from the local magicnet server
 * \param client - The client to request information from
 * \param type - The type of information to be requested
 * \param input_data - The input data to be used to fullfil a data request
 * \param output_data_out - A pointer to the variable you want to set to the output data
 * \return below zero on error otherwise successful
 */
int magicnet_reqres_request(struct magicnet_client *client, int type, struct request_and_respond_input_data *input_data, struct request_and_respond_output_data **output_data_out)
{
    int res = 0;

    struct magicnet_packet *req_packet = magicnet_packet_new();
    struct magicnet_packet *res_packet = magicnet_packet_new();
    magicnet_signed_data(req_packet)->type = MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND;
    magicnet_signed_data(req_packet)->payload.request_and_respond.type = type;
    magicnet_signed_data(req_packet)->payload.request_and_respond.input_data = magicnet_reqres_input_data_clone(input_data);

    // We will send the packet therefore requesting the given information from the client
    // Let's not forget we can be ignored by remote clients for such requests like this
    // these requests are generally for the local server only...
    res = magicnet_client_write_packet(client, req_packet, 0);
    if (res < 0)
    {
        goto out;
    }

    // Now we will wait for the response from the server
    res_packet = magicnet_packet_new();
    res = magicnet_client_read_packet(client, res_packet);
    if (res < 0)
    {
        goto out;
    }

    if (magicnet_signed_data(res_packet)->type == MAGICNET_PACKET_TYPE_NOT_FOUND)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }
    // Now we will check the response packet to see if it is the correct type
    if (magicnet_signed_data(res_packet)->type != MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND_RESPONSE)
    {
        magicnet_error("The server returned a different packet than we was expecting, it returned %i. It is important when using request and respond that no other packets are waiting to be read, ensure other requests are fullfilled before calling this function\n", magicnet_signed_data(res_packet)->type);
        res = -1;
        goto out;
    }

    // Now we will check the response packet to see if it is the correct type
    res = magicnet_reqres_validate_response_packet(res_packet);
    if (res < 0)
    {
        goto out;
    }


    *output_data_out = magicnet_reqres_output_data_clone(magicnet_signed_data(res_packet)->payload.request_and_respond_response.output_data);

out:
    magicnet_packet_free(req_packet);
    magicnet_packet_free(res_packet);
    return res;
}

int reqres_handler_available(int type)
{  
    if (type < 0 || type > MAGICNET_REQRES_MAX_HANDLERS)
    {
        return MAGICNET_ERROR_OUT_OF_BOUNDS;
    }

    if (request_response_handlers[type] != 0)
    {
        return MAGICNET_ERROR_ALREADY_EXISTANT;
    }

    return 0;
}

int reqres_register_handler(REQUEST_RESPONSE_HANDLER_FUNCTION handler, int type)
{
    int res = 0;
    res = reqres_handler_available(type);
    if (res < 0)
    {
        goto out;
    }
    request_response_handlers[type] = handler;

out:
    return res;
}

REQUEST_RESPONSE_HANDLER_FUNCTION reqres_get_handler(int type)
{
    if (type < 0 || type > MAGICNET_REQRES_MAX_HANDLERS)
    {
        return 0;
    }
    return request_response_handlers[type];
}