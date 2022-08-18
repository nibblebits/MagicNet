
#ifndef MAGICNET_H
#define MAGICNET_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "magicnet/vector.h"
#include "magicnet/config.h"

struct magicnet_registered_structure
{
    // Numerical ID determined by the application using this network. This is the structure ID
    long type;
    // The size of the structure in bytes
    size_t size;
};

struct magicnet_client;
struct magicnet_program
{
    char name[MAGICNET_PROGRAM_NAME_SIZE];
    struct magicnet_client* client;
};

// Represents the magicnet program on the server side
struct magicnet_server_program
{
    char name[MAGICNET_PROGRAM_NAME_SIZE];

    // Vector of struct magicnet_packet 
    // All packets received with the given program name are stored here
    // for polling by the programs subscribed to them.
    struct vector* packets;
};
struct magicnet_server
{
    int sock;
};

struct magicnet_client
{
    int sock;
    struct sockaddr_in client_info;
    struct magicnet_server *server;
};

enum
{
    MAGICNET_PACKET_TYPE_USER_DEFINED,
    MAGICNET_PACKET_TYPE_PING,
};
struct magicnet_packet
{
    // The type of this packet see above.
    int type;
    struct payload
    {
        union
        {
            struct user_defined
            {
                // This is a predetermined packet type, determined by the application using the network
                long type;

                size_t data_len;

                // Program name
                char program_name[MAGICNET_PROGRAM_NAME_SIZE];

                // Pointer to the actual packet data known by the application using the network
                void *data;
            } user_defined;

        };
    } payload;
};

struct magicnet_server *magicnet_server_start();
struct magicnet_client *magicnet_accept(struct magicnet_server *server);
int magicnet_client_thread_start(struct magicnet_client *client);
int magicnet_client_preform_entry_protocol_write(struct magicnet_client* client, const char* program_name);
struct magicnet_client *giveme_tcp_network_connect(const char *ip_address, int port, int flags, const char* program_name);

int magicnet_init();
int magicnet_get_structure(int type, struct magicnet_registered_structure *struct_out);
int magicnet_register_structure(long type, size_t size);
struct magicnet_program *magicnet_program(const char *name);

#endif