#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include "magicnet/config.h"
#include "magicnet/magicnet.h"
#include "magicnet/log.h"

int magicnet_send_pong(struct magicnet_client *client);

struct magicnet_server *magicnet_server_start()
{
    int sockfd, len;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        magicnet_log("socket creation failed...\n");
        exit(0);
    }

    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(MAGICNET_SERVER_PORT);

    int _true = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &_true, sizeof(int)) < 0)
    {
        magicnet_log("Failed to set socket reusable option\n");
        return NULL;
    }

    // Binding newly created socket to given IP
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0)
    {
        magicnet_log("server socket bind failed...\n");
        return NULL;
    }

    if ((listen(sockfd, MAGICNET_MAX_CONNECTIONS)) != 0)
    {
        magicnet_log("TCP Server Listen failed...\n");
        return NULL;
    }

    struct magicnet_server *server = calloc(1, sizeof(struct magicnet_server));
    server->sock = sockfd;
    return server;
}


bool magicnet_client_in_use(struct magicnet_client* client)
{
    return client->flags & MAGICNET_CLIENT_FLAG_CONNECTED;
}

struct magicnet_client *magicnet_find_free_client(struct magicnet_server *server)
{
    for (int i = 0; i < MAGICNET_MAX_CONNECTIONS; i++)
    {
        if (!magicnet_client_in_use(&server->clients[i]))
        {
            bzero(&server->clients[i], sizeof(struct magicnet_client));
            return &server->clients[i];
        }
    }

    return NULL;
}

struct magicnet_client *magicnet_accept(struct magicnet_server *server)
{
    struct sockaddr_in client;
    int client_len = sizeof(client);

    int connfd = accept(server->sock, (struct sockaddr *)&client, &client_len);
    if (connfd < 0)
    {
        magicnet_log("Nobody connected with us :(\n");
        return NULL;
    }

    magicnet_log("Received connection from %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

    struct timeval timeout;
    timeout.tv_sec = MAGICNET_CLIENT_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        magicnet_log("Failed to set socket timeout\n");
        return NULL;
    }

    struct magicnet_client *mclient = magicnet_find_free_client(server);
    if (!mclient)
    {
        // We couldn't get a free client...
        magicnet_log("%s clients are full\n", __FUNCTION__);
        return NULL;
    }

    mclient->sock = connfd;
    mclient->server = server;
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    memcpy(&mclient->client_info, &client, sizeof(&client));
    return mclient;
}

void magicnet_close(struct magicnet_client *client)
{
    close(client->sock);
    client->flags &= ~MAGICNET_CLIENT_FLAG_CONNECTED;
    if (client->flags & MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE)
    {
        free(client);
    }
}

int magicnet_read_bytes(struct magicnet_client *client, void *ptr_out, size_t amount)
{
    int res = 0;
    size_t amount_read = 0;
    while (amount_read < amount)
    {
        res = recv(client->sock, ptr_out + amount_read, amount - amount_read, MSG_WAITALL);
        if (res <= 0)
        {
            res = -1;
            break;
        }
        amount_read += res;
    }
    client->last_contact = time(NULL);
    return res;
}

int magicnet_write_bytes(struct magicnet_client *client, void *ptr_out, size_t amount)
{
    int res = 0;
    size_t amount_written = 0;
    while (amount_written < amount)
    {
        res = write(client->sock, ptr_out + amount_written, amount - amount_written);
        if (res <= 0)
        {
            res = -1;
            break;
        }
        amount_written += res;
    }

    return res;
}

int magicnet_write_int(struct magicnet_client *client, int value)
{
    // Preform bit manipulation for big-endianness todo later...
    if (magicnet_write_bytes(client, &value, sizeof(value)) < 0)
    {
        return -1;
    }
    return 0;
}

int magicnet_write_long(struct magicnet_client *client, long value)
{
    // Preform bit manipulation for big-endianness todo later...
    if (magicnet_write_bytes(client, &value, sizeof(value)) < 0)
    {
        return -1;
    }
    return 0;
}



long magicnet_read_long(struct magicnet_client *client)
{
    long result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result)) < 0)
    {
        return -1;
    }

    // Preform bit manipulation depending on big-endianness.... for later..
    return result;
}

int magicnet_read_int(struct magicnet_client *client)
{
    int result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result)) < 0)
    {
        return -1;
    }

    // Preform bit manipulation for big-endianness todo later...
    return result;
}

short magicnet_read_short(struct magicnet_client *client)
{
    short result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result)) < 0)
    {
        return -1;
    }

    // prefor bit manipualtion for big endians on short.
    return result;
}

int magicnet_client_read_user_defined_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    void *data = NULL;
    size_t amount_left = 0;

    // Let's read the packet type.
    long packet_type = magicnet_read_long(client);
    if (packet_type < 0)
    {
        res = -1;
        goto out;
    }

    long data_size = magicnet_read_long(client);
    data = calloc(1, data_size);
    res = magicnet_read_bytes(client, data, data_size);
    if (res < 0)
    {
        goto out;
    }

    packet_out->payload.user_defined.type = packet_type;
    packet_out->payload.user_defined.data = data;

out:
    if (res < 0)
    {
        // An error?? Free the data
        if (data != NULL)
        {
            free(data);
        }
    }

    return res;
}

int magicnet_client_read_poll_packets_packet(struct magicnet_client* client, struct magicnet_packet* packet_out)
{
    packet_out->type = MAGICNET_PACKET_TYPE_POLL_PACKETS;
    return 0;
}


int magicnet_client_read_not_found_packet(struct magicnet_client* client, struct magicnet_packet* packet_out)
{
    packet_out->type = MAGICNET_PACKET_TYPE_NOT_FOUND;
    return 0;
}

int magicnet_client_read_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    int packet_type = 0;
    packet_type = magicnet_read_int(client);
    if (packet_type < 0)
    {
        return -1;
    }

    switch (packet_type)
    {
    case MAGICNET_PACKET_TYPE_PING:
        packet_out->type = MAGICNET_PACKET_TYPE_PING;
        break;
    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_read_user_defined_packet(client, packet_out);
        break;

    case MAGICNET_PACKET_TYPE_POLL_PACKETS:
        res = magicnet_client_read_poll_packets_packet(client, packet_out);
        break;

    case MAGICNET_PACKET_TYPE_NOT_FOUND:
        res = magicnet_client_read_not_found_packet(client, packet_out);
        break;
    default:
        magicnet_log("%s unexpected packet was provided\n", __FUNCTION__);
        res = -1;
        break;
    }

    return res;
}

int magicnet_client_write_packet_ping(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_write_int(client, MAGICNET_PACKET_TYPE_PING);
    return res;
}

int magicnet_client_write_packet_poll_packets(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_write_int(client, MAGICNET_PACKET_TYPE_POLL_PACKETS);
    return res;
}


int magicnet_client_write_packet_not_found(struct magicnet_client* client, struct magicnet_packet* packet)
{
    int res = 0;
    magicnet_write_int(client, MAGICNET_PACKET_TYPE_NOT_FOUND);
    return res;
}

int magicnet_client_write_packet_user_defined(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    void *data = NULL;

    res = magicnet_write_long(client, packet->payload.user_defined.type);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_long(client, packet->payload.user_defined.data_len);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, packet->payload.user_defined.data, packet->payload.user_defined.data_len);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}


int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    switch (packet->type)
    {
    case MAGICNET_PACKET_TYPE_PING:
        res = magicnet_client_write_packet_ping(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_POLL_PACKETS:
        res = magicnet_client_write_packet_poll_packets(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_write_packet_user_defined(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_NOT_FOUND:
        res = magicnet_client_write_packet_not_found(client, packet);
        break;
    }
    return res;
}

bool magicnet_connected(struct magicnet_client *client)
{
    return client->flags & MAGICNET_CLIENT_FLAG_CONNECTED;
}

struct magicnet_client *magicnet_tcp_network_connect(const char *ip_address, int port, int flags, const char *program_name)
{
    int sockfd;
    struct sockaddr_in servaddr, cli;

    struct in_addr addr = {};
    if (inet_aton(ip_address, &addr) == 0)
    {
        return NULL;
    }

    // socket create and varification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        return NULL;
    }

    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr = addr;
    servaddr.sin_port = htons(port);

    struct timeval timeout;
    timeout.tv_sec = MAGICNET_CLIENT_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        // giveme_log("Failed to set socket timeout\n");
        return NULL;
    }

    // connect the client socket to server socket
    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        return NULL;
    }

    struct magicnet_client *mclient = calloc(1, sizeof(struct magicnet_client));
    mclient->sock = sockfd;
    mclient->server = NULL;
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    if (program_name)
    {
        memcpy(mclient->program_name, program_name, sizeof(mclient->program_name));
    }

    if (flags & MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE)
    {
        mclient->flags |= MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE;
    }
    int res = magicnet_client_preform_entry_protocol_write(mclient, program_name);
    if (res < 0)
    {
        magicnet_close(mclient);
        mclient = NULL;
    }
    return mclient;
}

struct magicnet_packet *magicnet_recv_next_packet(struct magicnet_client *client)
{
    struct magicnet_packet *packet = calloc(1, sizeof(struct magicnet_packet));
    if (magicnet_client_read_packet(client, packet) < 0)
    {
        free(packet);
        return NULL;
    }

    if (packet->type == MAGICNET_PACKET_TYPE_PING)
    {
        magicnet_send_pong(client);
        // We don't show pings to the caller they are in the background..
        return magicnet_recv_next_packet(client);
    }

    return packet;
}


struct magicnet_packet* magicnet_client_get_available_free_to_use_packet(struct magicnet_client* client)
{
    struct magicnet_packet* packet = NULL;
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (client->awaiting_packets[i].flags & MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE)
        {
            client->awaiting_packets[i].type &= ~MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
            packet = &client->awaiting_packets[i];
        }
    }

    return packet;
}

struct magicnet_packet* magicnet_client_get_next_packet_to_process(struct magicnet_client* client)
{
    struct magicnet_packet* packet = NULL;
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (client->awaiting_packets[i].flags & MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING)
        {
            packet = &client->awaiting_packets[i];
        }
    }
    return packet;
}

int magicnet_client_add_awaiting_packet(struct magicnet_client* client, struct magicnet_packet* packet)
{
    struct magicnet_packet* awaiting_packet = magicnet_client_get_available_free_to_use_packet(client);
    if (!awaiting_packet)
    {
        return MAGICNET_ERROR_QUEUE_FULL;
    }

    memcpy(awaiting_packet, packet, sizeof(struct magicnet_packet));
    awaiting_packet->flags |= MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING;
    return 0;
}

/**
 * @brief Marks the packet in the client->awaiting_packets array as processed
 * \note The packet point must be the same pointer returned from magicnet_client_get_next_packet_to_process
 * @param client 
 * @param packet 
 */
void magicnet_client_mark_packet_processed(struct magicnet_client* client, struct magicnet_packet* packet)
{
    memset(packet, 0, sizeof(struct magicnet_packet));
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (&client->awaiting_packets[i] == packet)
        {
            packet->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
            break;
        }
    }
}

int magicnet_client_process_packet_poll_packets(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    struct magicnet_packet* packet_to_process = NULL;
    packet_to_process = magicnet_client_get_next_packet_to_process(client);
    if (!packet_to_process)
    {
        res = magicnet_client_write_packet(client, &(struct magicnet_packet){.type = MAGICNET_PACKET_TYPE_NOT_FOUND});
        goto out;

    }

    // We have a packet they could use.. Lets send it there way
    res = magicnet_client_write_packet(client, packet_to_process);
    if (res < 0)
    {
        goto out;
    }

    magicnet_client_mark_packet_processed(client, packet_to_process);
out:
    return res;
}

int magicnet_client_process_user_defined_packet(struct magicnet_client* client, struct magicnet_packet* packet)
{
    int res = 0;
    // We must find all the clients of the same program name
    for (int i = 0; i < MAGICNET_MAX_CONNECTIONS; i++)
    {
        struct magicnet_client* cli = &client->server->clients[i];
        if (!magicnet_client_in_use(client))
        {
            continue;
        }

        // Same program name as the sending client? Then add it to the packet queue of the connected client
        if (strncmp(cli->program_name, client->program_name, sizeof(cli->program_name)) == 0)
        {
            magicnet_client_add_awaiting_packet(client, packet);
        }
    }
    return res;
}

int magicnet_client_process_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    switch (packet->type)
    {
    case MAGICNET_PACKET_TYPE_POLL_PACKETS:
        res = magicnet_client_process_packet_poll_packets(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_process_user_defined_packet(client, packet);
        break;

    default:
        magicnet_log("%s Illegal packet provided\n", __FUNCTION__);
        res = -1;
        ;
    }
    return res;
}

int magicnet_client_manage_next_packet(struct magicnet_client *client)
{
    int res = 0;
    struct magicnet_packet *packet = magicnet_recv_next_packet(client);
    if (!packet)
    {
        magicnet_log("%s failed to receive new packet from client\n", __FUNCTION__);

        res = -1;
        goto out;
    }

    if (magicnet_client_process_packet(client, packet) < 0)
    {
        res = -1;
        goto out;
    }

out:
    if (packet)
    {
        free(packet);
    }
    return res;
}

int magicnet_client_preform_entry_protocol_read(struct magicnet_client *client)
{
    struct magicnet_server *server = client->server;
    int res = 0;
    int signature = magicnet_read_int(client);
    if (signature != MAGICNET_ENTRY_SIGNATURE)
    {
        magicnet_log("%s somebody connected to us but doesnt understand our protocol.. Probably some accidental connection.. Dropping\n", __FUNCTION__);
        return -1;
    }
    // We need to find out what they are listening too before we can accept them.
    // What is the program they are subscribing too, lets read it.
    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
    res = magicnet_read_bytes(client, program_name, sizeof(program_name));
    if (res < 0)
    {
        return -1;
    }

    memcpy(client->program_name, program_name, sizeof(client->program_name));
    res = magicnet_write_int(client, MAGICNET_ENTRY_SIGNATURE);
    return res;
}

int magicnet_client_preform_entry_protocol_write(struct magicnet_client *client, const char *program_name)
{
    int res = 0;
    res = magicnet_write_int(client, MAGICNET_ENTRY_SIGNATURE);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, (void *)program_name, MAGICNET_PROGRAM_NAME_SIZE);
    if (res < 0)
    {
        goto out;
    }

    // Now lets see if we got the signature back
    int sig = 0;
    res = magicnet_read_bytes(client, &sig, sizeof(sig));
    if (res < 0)
    {
        goto out;
    }

    if (sig != MAGICNET_ENTRY_SIGNATURE)
    {
        // Bad signature
        res = -1;
        goto out;
    }
out:
    return res;
}

bool magicnet_client_needs_ping(struct magicnet_client *client)
{
    return time(NULL) - client->last_contact >= 5;
}

int magicnet_ping(struct magicnet_client *client)
{
    int res = magicnet_client_write_packet(client, &(struct magicnet_packet){.type = MAGICNET_PACKET_TYPE_PING});
    if (res < 0)
    {
        return res;
    }

    return 0;
}

int magicnet_send_pong(struct magicnet_client *client)
{
    int res = magicnet_client_write_packet(client, &(struct magicnet_packet){.type = MAGICNET_PACKET_TYPE_PONG});
    if (res < 0)
    {
        return res;
    }

    return 0;
}

int magicnet_ping_pong(struct magicnet_client *client)
{
    int res = magicnet_ping(client);
    struct magicnet_packet packet = {};
    res = magicnet_client_read_packet(client, &packet);
    if (res < 0)
    {
        return res;
    }

    return packet.type == MAGICNET_PACKET_TYPE_PONG;
}

void *magicnet_client_thread(void *_client)
{
    int res = 0;
    struct magicnet_client *client = _client;

    res = magicnet_client_preform_entry_protocol_read(client);
    if (res < 0)
    {
        // entry protocol failed.. illegal client!
        goto out;
    }

    while (res >= 0)
    {
        res = magicnet_client_manage_next_packet(client);
    }
out:
    magicnet_close(client);
    return NULL;
}
int magicnet_client_thread_start(struct magicnet_client *client)
{
    pthread_t threadId;
    if (pthread_create(&threadId, NULL, &magicnet_client_thread, client))
    {
        return -1;
    }

    return 0;
}