
/**
 * This is the local request and respond system, allows a local magicnet program to request information
 * from the server and be provided with it.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "magicnet.h"
#include "signaling.h"
#include "nthread.h"
#include "log.h"
int magicnet_reqres_poll(struct magicnet_nthread_action *action);
static REQUEST_RESPONSE_HANDLER_FUNCTION request_response_handlers[MAGICNET_REQRES_MAX_HANDLERS] = {0};

// test handler...
int magicnet_reqres_helloworld_handler(struct magicnet_request_input_data *input_data, struct magicnet_request_response_output_data **output_data_out)
{
    char *helloworld = calloc(1, strlen("hello world"));
    strncpy(helloworld, "hello world", strlen("hello world"));
    struct magicnet_request_response_output_data *output_data = magicnet_reqres_output_data_create(helloworld, strlen("hello world"));
    *output_data_out = output_data;
    return 0;
}

int magicnet_reqres_init()
{
    int res = 0;
    // Register the hello world handler
    reqres_register_handler(magicnet_reqres_helloworld_handler, MAGICNET_REQRES_HANDLER_HELLOWORLD_TEST);

    return res;
}
struct magicnet_request_input_data *magicnet_reqres_input_data_create(void *input_data_ptr, size_t size)
{
    struct magicnet_request_input_data *input_data = calloc(1, sizeof(struct magicnet_request_input_data));
    if (input_data_ptr == NULL || size == 0)
    {
        return input_data;
    }
    input_data->input = calloc(size, sizeof(char));
    input_data->size = size;
    memcpy(input_data->input, input_data_ptr, size);
    return input_data;
}

struct magicnet_request_input_data *magicnet_reqres_input_data_clone(struct magicnet_request_input_data *input_data)
{
    if (!input_data)
    {
        return magicnet_reqres_input_data_create(NULL, 0);
    }
    return magicnet_reqres_input_data_create(input_data->input, input_data->size);
}

struct magicnet_request_response_output_data *magicnet_reqres_output_data_create(void *output_data_ptr, size_t size)
{
    int res = 0;
    struct magicnet_request_response_output_data *output_data = calloc(1, sizeof(struct magicnet_request_response_output_data));

    // We are allowed outputs of NULL value.
    if (output_data_ptr && size > 0)
    {
        output_data->output = calloc(size, sizeof(char));
        if (!output_data->output)
        {
            res = -1;
            goto out;
        }

        output_data->size = size;

        memcpy(output_data->output, output_data_ptr, size);
    }
out:

    if (res < 0)
    {
        if (output_data->output)
        {
            free(output_data->output);
            output_data->output = NULL;
        }
        if (output_data)
        {
            free(output_data);
            output_data = NULL;
        }
    }
    return output_data;
}

struct magicnet_request_response_output_data *magicnet_reqres_output_data_clone(struct magicnet_request_response_output_data *output_data)
{
    if (!output_data)
    {
        return magicnet_reqres_output_data_create(NULL, 0);
    }
    return magicnet_reqres_output_data_create(output_data->output, output_data->size);
}

void magicnet_reqres_output_data_free(struct magicnet_request_response_output_data *output_data)
{
    if (output_data->output)
    {
        free(output_data->output);
    }
    free(output_data);
}

void magicnet_reqres_input_data_free(struct magicnet_request_input_data *input_data)
{
    if (input_data->input)
    {
        free(input_data->input);
    }
    free(input_data);
}

int magicnet_reqres_validate_res(struct magicnet_reqres_response *reqres_res)
{
    int res = 0;
    return res;
}

int magicnet_reqres_request_count(struct magicnet_reqres *reqres)
{
    return vector_count(reqres->requests);
}

int magicnet_reqres_response_count(struct magicnet_reqres *reqres)
{
    return vector_count(reqres->responses);
}

struct magicnet_reqres *magicnet_reqres_new(void *private)
{
    int res = 0;
    struct magicnet_reqres *reqres = calloc(1, sizeof(struct magicnet_reqres));
    if (!reqres)
    {
        res = -1;
        goto out;
    }

    pthread_mutex_init(&reqres->mutex, NULL);
    reqres->requests = vector_create(sizeof(struct magicnet_reqres_request *));
    if (!reqres->requests)
    {
        res = -1;
        goto out;
    }
    reqres->responses = vector_create(sizeof(struct magicnet_reqres_response *));
    if (!reqres->responses)
    {
        res = -1;
        goto out;
    }

    reqres->private = private;
out:

    if (res < 0)
    {
        if (reqres->requests)
        {
            vector_free(reqres->requests);
            reqres->requests = NULL;
        }

        if (reqres->responses)
        {
            vector_free(reqres->responses);
            reqres->responses = NULL;
        }

        free(reqres);
        reqres = NULL;
    }
    return reqres;
}

void magicnet_reqres_free(struct magicnet_reqres *reqres)
{
    if (reqres->requests)
    {
        vector_free(reqres->requests);
    }

    if (reqres->responses)
    {
        vector_free(reqres->responses);
    }

    free(reqres);
}

void magicnet_reqres_signal_desc_from_id(int id, struct magicnet_signal_desc *desc)
{
    desc->id = id;
    strncpy(desc->signal_type, "reqres-request", sizeof(desc->signal_type));
}

struct magicnet_reqres_request *magicnet_reqres_request_new(int id, int type, int signal_id, struct magicnet_request_input_data *input_data)
{
    int res = 0;
    struct magicnet_reqres_request *request = calloc(1, sizeof(struct magicnet_reqres_request));
    if (!request)
    {
        res = -1;
        goto out;
    }

    request->id = id;
    request->type = type;
    magicnet_reqres_signal_desc_from_id(signal_id, &request->signal_desc);

    request->data = magicnet_reqres_input_data_clone(input_data);
    // null data might be allowed..
out:
    if (res < 0)
    {
        if (request)
        {
            if (request->data)
            {
                magicnet_reqres_input_data_free(request->data);
                request->data = NULL;
            }
            free(request);
            request = NULL;
        }
    }
    return request;
}

struct magicnet_reqres_request *magicnet_reqres_request_clone(struct magicnet_reqres_request *req)
{
    int res = 0;
    struct magicnet_reqres_request *req_clone = calloc(1, sizeof(struct magicnet_reqres_request));
    if (!req_clone)
    {
        res = -1;
        goto out;
    }

    // Memcpy dont forget to change the pointers manually
    memcpy(req_clone, req, sizeof(*req_clone));
    req_clone->data = magicnet_reqres_input_data_clone(req_clone->data);
    if (!req_clone->data)
    {
        res = -1;
        goto out;
    }
out:
    if (res < 0)
    {
        if (req_clone)
        {
            if (req_clone->data)
            {
                magicnet_reqres_input_data_free(req_clone->data);
                req_clone->data = NULL;
            }
            free(req_clone);
            req_clone = NULL;
        }
    }
    return req_clone;
}

void magicnet_reqres_request_free(struct magicnet_reqres_request *req)
{
    if (req->data)
    {
        magicnet_reqres_input_data_free(req->data);
        req->data = NULL;
    }
    free(req);
}

int magicnet_reqres_request_push(struct magicnet_reqres *reqres, struct magicnet_reqres_request *req)
{
    int res = 0;

    // For memory safety the request needs to be cloned before pushed
    // so we maintain our own ownership
    // i dont care if it uses more memory right now this is a safer design
    // shared pointers are possibility later

    struct magicnet_reqres_request *req_cloned = magicnet_reqres_request_clone(req);
    if (!req_cloned)
    {
        res = -1;
        goto out;
    }

    // lets call the callback so they can modify it if they wish
    if (reqres->functions.request_callback)
    {
        reqres->functions.request_callback(reqres, req_cloned);
    }
    // We are now responsible for the req_cloned memory
    // owner of req remains responsible for his own memory.
    vector_push(reqres->requests, &req_cloned);

out:
    return res;
}

int magicnet_reqres_request_pop(struct magicnet_reqres *reqres, struct magicnet_reqres_request **req_out)
{
    if (vector_empty(reqres->requests))
    {
        return -1;
    }

    struct magicnet_reqres_request *req = vector_front_ptr_pop(reqres->requests);
    if (!req)
    {
        return -1;
    }

    *req_out = req;
    return 0;
}

int magicnet_reqres_response_pop(struct magicnet_reqres *reqres, struct magicnet_reqres_response **res_out)
{
    if (vector_empty(reqres->responses))
    {
        return -1;
    }

    struct magicnet_reqres_response *res = vector_front_ptr_pop(reqres->responses);
    if (!res)
    {
        return -1;
    }

    *res_out = res;
    return 0;
}

struct magicnet_reqres_response *magicnet_reqres_response_clone(struct magicnet_reqres_response *res)
{
    struct magicnet_reqres_response *res_clone = calloc(1, sizeof(struct magicnet_reqres_response));
    if (!res_clone)
    {
        goto out;
    }

    memcpy(res_clone, res, sizeof(*res_clone));
    // Dont forget to change the pointrs
    // these datas are allowed to be null
    res_clone->input_data = magicnet_reqres_input_data_clone(res->input_data);
    res_clone->output_data = magicnet_reqres_output_data_clone(res->output_data);

out:
    return res_clone;
}
/// lag is a bit unbareable
int magicnet_reqres_response_push(struct magicnet_reqres *reqres, struct magicnet_reqres_response *reqres_res)
{
    int res = 0;
    // Yeah we should probably clone here too
    // we will think abotu shared pointers another time
    // memory safety is important right now

    struct magicnet_reqres_response *res_cloned = magicnet_reqres_response_clone(reqres_res);
    if (!res_cloned)
    {
        res = -1;
        goto out;
    }

    // Lets call the event handler so they may modify the response if they choose
    if (reqres->functions.response_callback)
    {
        reqres->functions.response_callback(reqres, res_cloned);
    }

    // Push the cloned response
    vector_push(reqres->responses, &res_cloned);
out:
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
int magicnet_reqres_request_obj(struct magicnet_client *client, int type, struct magicnet_request_input_data *input_data, struct magicnet_request_response_output_data **output_data_out)
{
    int res = 0;

    struct magicnet_packet *req_packet = magicnet_packet_new();
    struct magicnet_reqres_response *reqres_res = NULL;
    struct magicnet_signal *signal = magicnet_signal_find_free("reqres-request");
    if (!signal)
    {
        res = -1;
        goto out;
    }

    magicnet_signed_data(req_packet)->type = MAGICNET_PACKET_TYPE_REQUEST;
    magicnet_signed_data(req_packet)->payload.request.type = type;
    magicnet_signed_data(req_packet)->payload.request.signal_id = signal->id;
    magicnet_signed_data(req_packet)->payload.request.input_data = magicnet_reqres_input_data_clone(input_data);

    // We will send the packet therefore requesting the given information from the client
    // Let's not forget we can be ignored by remote clients for such requests like this
    // these requests are generally for the local server only...
    res = magicnet_client_write_packet(client, req_packet, 0);
    if (res < 0)
    {
        goto out;
    }

    // Now we will wait for the response from the server
    res = magicnet_signal_wait_timed(signal, 30, (void **)&reqres_res);
    if (res < 0)
    {
        res = MAGICNET_ERROR_TRY_AGAIN;
        goto out;
    }

    if (reqres_res == NULL)
    {
        res = MAGICNET_ERROR_NOT_FOUND;
        goto out;
    }
    // Now we will check the response packet to see if it is the correct type
    if (reqres_res->flags & MAGICNET_REQRES_HANDLER_FLAG_FAILED)
    {
        // Yeah we failed
        res = MAGICNET_ERROR_CRITICAL_ERROR;
        goto out;
    }

    // Now we will check the response packet to see if it is the correct type
    res = magicnet_reqres_validate_res(reqres_res);
    if (res < 0)
    {
        goto out;
    }

    // Data is cloned belongs to the owner who called this function now.
    *output_data_out = magicnet_reqres_output_data_clone(reqres_res->output_data);

    // Our popped copy can be deleted

out:
    if (reqres_res)
    {
        magicnet_reqres_output_data_free(reqres_res->output_data);
        reqres_res->output_data = NULL;
    }
    magicnet_packet_free(req_packet);
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

REQUEST_RESPONSE_HANDLER_FUNCTION magicnet_reqres_get_handler(int type)
{
    if (type < 0 || type > MAGICNET_REQRES_MAX_HANDLERS)
    {
        return 0;
    }
    return request_response_handlers[type];
}

struct magicnet_reqres_response *magicnet_reqres_response_new(int type, int id, int flags, struct magicnet_signal_desc *signal_desc, struct magicnet_request_input_data *input_data, struct magicnet_request_response_output_data *output_data, void *private)
{
    struct magicnet_reqres_response *response = calloc(1, sizeof(struct magicnet_reqres_response));
    if (!response)
    {
        return NULL;
    }

    response->id = id;
    response->flags = flags;
    response->type = type;

    // let it crash to find the issue.
    response->signal_desc = *signal_desc;
    response->input_data = input_data;
    response->output_data = output_data;
    response->private = private;
    return response;
}

int magicnet_reqres_request_process_failure_push(struct magicnet_reqres *reqres, struct magicnet_reqres_request *req)
{
    int res = 0;
    int flags = MAGICNET_REQRES_HANDLER_FLAG_FAILED;
    struct magicnet_reqres_response *reqres_res = NULL;
    struct magicnet_request_input_data *input_data = NULL;
    struct magicnet_request_response_output_data *output_data = magicnet_reqres_output_data_create(NULL, 0);
    if (!output_data)
    {
        res = -1;
        goto out;
    }

    input_data = req->data;
    reqres_res = magicnet_reqres_response_new(req->type, req->id, flags, &req->signal_desc, input_data, output_data, NULL);
    if (reqres_res < 0)
    {
        goto out;
    }

    res = magicnet_reqres_response_push(reqres, reqres_res);
out:
    // cleanup later..
    return res;
}
int magicnet_reqres_request_process(struct magicnet_reqres *reqres, struct magicnet_reqres_request *req)
{
    int res = 0;

    struct magicnet_request_input_data *input_data = NULL;
    struct magicnet_request_response_output_data *output_data = NULL;
    struct magicnet_reqres_response *response = NULL;
    REQUEST_RESPONSE_HANDLER_FUNCTION reqres_handler = magicnet_reqres_get_handler(req->type);
    if (!reqres_handler)
    {
        res = -1;
        goto out;
    }

    res = reqres_handler(req->data, &output_data);
    if (res < 0)
    {
        // We failed the request, push it so they will know.
        magicnet_reqres_request_process_failure_push(reqres, req);
        goto out;
    }

    if (!output_data)
    {
        res = -1;
        goto out;
    }

    input_data = req->data;
    response = magicnet_reqres_response_new(req->type, req->id, 0, &req->signal_desc, input_data, output_data, NULL);
    if (!response)
    {
        res = -1;
        goto out;
    }

    // We have the result lets push to the output queue
    res = magicnet_reqres_response_push(reqres, response);

out:
    // cleanup later...
    return res;
}

void magicnet_reqres_lock(struct magicnet_reqres *reqres)
{
    pthread_mutex_lock(&reqres->mutex);
}

void magicnet_reqres_unlock(struct magicnet_reqres *reqres)
{
    pthread_mutex_unlock(&reqres->mutex);
}

int magicnet_reqres_begin_polling(struct magicnet_reqres *reqres)
{
    int res = 0;
    struct magicnet_nthread_action *poll_action = NULL;
    poll_action = magicnet_threads_action_new(magicnet_reqres_poll, reqres, NULL);
    if (!poll_action)
    {
        res = -1;
        goto out;
    }
    res = magicnet_threads_push_action(poll_action);
out:
    return res;
}

int magicnet_reqres_poll(struct magicnet_nthread_action *action)
{
    int res = 0;
    struct magicnet_reqres *reqres = action->private;

    magicnet_reqres_lock(reqres);
    // NO while loop because this is a thread pool
    // we will deal with one per cycle..
    if (magicnet_reqres_request_count(reqres) > 0)
    {
        // We have another one to deal with.
        struct magicnet_reqres_request *req = NULL;
        res = magicnet_reqres_request_pop(reqres, &req);
        if (res < 0)
        {
            goto out;
        }

        res = magicnet_reqres_request_process(reqres, req);
        if (res < 0)
        {
            goto out;
        }

        // You might think to delete the input data pointer, bad idea the pointers will only be deleted
        // once its no longer needed
    }

out:
    magicnet_reqres_unlock(reqres);
    return 0;
}