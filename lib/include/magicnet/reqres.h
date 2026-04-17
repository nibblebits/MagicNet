#ifndef MAGICNET_REQRES_H
#define MAGICNET_REQRES_H

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include "signaling.h"

struct magicnet_request_input_data
{
    void *input;
    size_t size;
};

struct magicnet_request_response_output_data
{
    void *output;
    size_t size;
};

struct magicnet_reqres_request
{
    long id;
    int type;
    // Signal shall be called when a response is available
    struct magicnet_signal_desc signal_desc;
    struct magicnet_request_input_data* data;
};

struct magicnet_reqres_response
{
    long id;
    int type;
    int flags;
    
    struct magicnet_signal_desc signal_desc;
    struct magicnet_request_input_data *input_data;
    struct magicnet_request_response_output_data *output_data;
};

struct magicnet_reqres
{

    /**
     * Pop, push mechanism we pop the request process and push the response.
     * the receiver can pop the response. Communication without socket blocking. 
     */

    // vector of struct magicnet_reqres_request*
    struct vector* requests;

    // vector of struct magicnet_reqres_response*
    struct vector* responses;
    
    pthread_mutex_t mutex;
};

// Request response system, allowing local host clients to request information from the local server
#define MAGICNET_REQRES_MAX_HANDLERS 200


enum
{
    MAGICNET_REQRES_HANDLER_FLAG_FAILED = 0b00000001
};

// For people writing modules for MagicNet Don't use any handler below 100 they are all reserved for internal system use
// Public use above 100 please, bare in mind that other modules might use the same ID so ensure you
// pick a completely random number
enum
{
    MAGICNET_REQRES_HANDLER_GET_COUNCIL_CERTIFICATE = 0,
};
typedef int (*REQUEST_RESPONSE_HANDLER_FUNCTION)(struct magicnet_request_input_data *input_data, struct magicnet_request_response_output_data **output_data_out);

int reqres_register_handler(REQUEST_RESPONSE_HANDLER_FUNCTION handler, int type);
REQUEST_RESPONSE_HANDLER_FUNCTION magicnet_reqres_get_handler(int type);

struct magicnet_client;
int magicnet_reqres_request_obj(struct magicnet_client *client, int type, struct magicnet_request_input_data *input_data, struct magicnet_request_response_output_data **output_data_out);
void magicnet_reqres_input_data_free(struct magicnet_request_input_data *input_data);
void magicnet_reqres_output_data_free(struct magicnet_request_response_output_data *output_data);
struct magicnet_request_response_output_data *magicnet_reqres_output_data_clone(struct magicnet_request_response_output_data *output_data);
struct magicnet_request_input_data *magicnet_reqres_input_data_clone(struct magicnet_request_input_data *input_data);
struct magicnet_request_response_output_data *magicnet_reqres_output_data_create(void *output_data_ptr, size_t size);
struct magicnet_request_input_data *magicnet_reqres_input_data_create(void *input_data_ptr, size_t size);
int magicnet_reqres_request_push(struct magicnet_reqres *reqres, struct magicnet_reqres_request *req);
int magicnet_reqres_response_push(struct magicnet_reqres *reqres, struct magicnet_reqres_response *res);

struct magicnet_reqres_request* magicnet_reqres_request_new(int id, int type, int signal_id, struct magicnet_request_input_data* input_data);
void magicnet_reqres_lock(struct magicnet_reqres *reqres);
void magicnet_reqres_unlock(struct magicnet_reqres *reqres);
struct magicnet_reqres_request* magicnet_reqres_request_clone(struct magicnet_reqres_request* req);
void magicnet_reqres_request_free(struct magicnet_reqres_request* req);
struct magicnet_reqres_response *magicnet_reqres_response_new(int type, int id, int flags, struct magicnet_signal_desc *signal_desc, struct magicnet_request_input_data *input_data, struct magicnet_request_response_output_data *output_data);
struct magicnet_reqres_response* magicnet_reqres_response_clone(struct magicnet_reqres_response* res);
int magicnet_reqres_request_count(struct magicnet_reqres *reqres);
int magicnet_reqres_response_count(struct magicnet_reqres* reqres);
int magicnet_reqres_response_pop(struct magicnet_reqres *reqres, struct magicnet_reqres_response **res_out);

int magicnet_reqres_begin_polling(struct magicnet_reqres* reqres);

#endif