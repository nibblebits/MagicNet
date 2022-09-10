
#ifndef MAGICNET_H
#define MAGICNET_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <pthread.h>
#include "magicnet/vector.h"
#include "magicnet/config.h"
#include "key.h"

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
    struct magicnet_client *client;
};

enum
{
    MAGICNET_PACKET_TYPE_EMPTY_PACKET,
    MAGICNET_PACKET_TYPE_USER_DEFINED = 158,
    MAGICNET_PACKET_TYPE_PING,
    MAGICNET_PACKET_TYPE_PONG,
    MAGICNET_PACKET_TYPE_POLL_PACKETS,
    MAGICNET_PACKET_TYPE_SERVER_SYNC,
    MAGICNET_PACKET_TYPE_NOT_FOUND,
};

enum
{
    MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE = 0b00000001,
    MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING = 0b00000010,
};

enum
{
    // Sent when the receiver of a packet should expect a packet to be sent upon reading this flag.
    MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET = 0b00000001
};

enum
{
    MAGICNET_ERROR_QUEUE_FULL = -1000,
    MAGICNET_ERROR_NOT_FOUND = -1001,
    MAGICNET_ERROR_RECEIVED_PACKET_BEFORE = -1002,
    MAGICNET_ACKNOWLEGED_ALL_OKAY = 0
};
struct magicnet_packet
{

    // The signature used to sign the signed_data
    struct signature signature;
    struct signed_data
    {
        // Random ID for the packet, prevents duplicate packets.
        int id;
        // The type of this packet see above.
        int type;
        int flags;
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

                struct sync
                {
                    int flags;
                    struct magicnet_packet *packet;
                } sync;
            };
        } payload;
    } signed_data;
};

struct magicnet_client
{
    int sock;
    int flags;
    time_t last_contact;
    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
    struct magicnet_packet awaiting_packets[MAGICNET_MAX_AWAITING_PACKETS];
    struct sockaddr_in client_info;
    off_t relay_packet_pos;
    struct magicnet_server *server;
};

struct magicnet_server
{
    int sock;
    // Clients our server accepted.
    struct magicnet_client clients[MAGICNET_MAX_INCOMING_CONNECTIONS];

    // Clients our server initiated the connection for
    struct magicnet_client outgoing_clients[MAGICNET_MAX_OUTGOING_CONNECTIONS];

    // Packets that should be relayed. Note when this is full it loops back around erasing the first packet again.
    struct relay_packets
    {
        struct magicnet_packet packets[MAGICNET_MAX_AWAITING_PACKETS];
        off_t pos;
    } relay_packets;

    // The packets that have been seen already.. If we encounter them again they should be ignored
    struct seen_packets
    {
        long packet_ids[MAGICNET_MAX_AWAITING_PACKETS];
        off_t pos;
    } seen_packets;

    pthread_mutex_t lock;

    // BELOW MUST BE PROCESSED ONLY BY THE SERVER THREAD
    off_t last_new_connection_attempt;
    const char *loaded_ip_addresses[MAGICNET_MAX_LOADED_IP_ADDRESSES];
    size_t total_loaded_ips;
    FILE *ip_file;
    // END
};

enum
{
    MAGICNET_CLIENT_FLAG_CONNECTED = 0b00000001,
    MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE = 0b00000010,

};
struct signed_data* magicnet_signed_data(struct magicnet_packet* packet);

int magicnet_network_thread_start(struct magicnet_server *server);
struct magicnet_server *magicnet_server_start();
struct magicnet_client *magicnet_accept(struct magicnet_server *server);
int magicnet_client_thread_start(struct magicnet_client *client);
int magicnet_client_preform_entry_protocol_write(struct magicnet_client *client, const char *program_name);
struct magicnet_client *magicnet_tcp_network_connect(const char *ip_address, int port, int flags, const char *program_name);
int magicnet_next_packet(struct magicnet_program *program, void **packet_out);
int magicnet_client_read_packet(struct magicnet_client *client, struct magicnet_packet *packet_out);
int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet);
int magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet);
int magicnet_send_pong(struct magicnet_client *client);
void magicnet_free_packet(struct magicnet_packet *packet);
void magicnet_free_packet_pointers(struct magicnet_packet *packet);
struct magicnet_packet *magicnet_packet_new();
int magicnet_init();
int magicnet_get_structure(int type, struct magicnet_registered_structure *struct_out);
int magicnet_register_structure(long type, size_t size);
struct magicnet_program *magicnet_program(const char *name);

#endif