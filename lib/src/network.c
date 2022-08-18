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

    struct magicnet_client *mclient = calloc(1, sizeof(struct magicnet_client));
    mclient->sock = connfd;
    mclient->server = server;
    memcpy(&mclient->client_info, &client, sizeof(&client));
    return mclient;
}

void magicnet_close(struct magicnet_client *client)
{
    close(client->sock);
    free(client);
}

long magicnet_read_long(struct magicnet_client *client)
{
    long result = 0;
    if (recv(client->sock, &result, sizeof(result), 0) < 0)
    {
        return -1;
    }

    // Preform bit manipulation depending on big-endianness.... for later..
    return result;
}

int magicnet_write_int(struct magicnet_client *client, int value)
{
    // Preform bit manipulation for big-endianness todo later...
    if (send(client->sock, &value, sizeof(value), 0) < 0)
    {
        return -1;
    }
    return 0;
}

int magicnet_read_int(struct magicnet_client *client)
{
    int result = 0;
    if (recv(client->sock, &result, sizeof(result), 0) < 0)
    {
        return -1;
    }

    // Preform bit manipulation for big-endianness todo later...
    return result;
}

short magicnet_read_short(struct magicnet_client *client)
{
    short result = 0;
    if (recv(client->sock, &result, sizeof(result), 0) < 0)
    {
        return -1;
    }

    // prefor bit manipualtion for big endians on short.
    return result;
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

    // Read the program name
    res = magicnet_read_bytes(client, packet_out->payload.user_defined.program_name, sizeof(packet_out->payload.user_defined.program_name));
    if (res < 0)
    {
        goto out;
    }

    // We've the packet type.. lets read the packet size now.
    // We have the packet data size
    short packet_size = magicnet_read_short(client);

    // Let's read the full packet.
    data = calloc(1, packet_size);
    res = magicnet_read_bytes(client, data, packet_size);
    if (res < 0)
    {
        goto out;
    }

    packet_out->payload.user_defined.type = packet_type;
    packet_out->payload.user_defined.data = data;
    packet_out->payload.user_defined.data_len = packet_size;

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

int magicnet_client_read_initialize_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    // Read the program name

    res = magicnet_read_bytes(client, packet_out->payload.user_defined.program_name, sizeof(packet_out->payload.user_defined.program_name));
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
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
    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_read_user_defined_packet(client, packet_out);
        break;
    }
}

struct magicnet_client *giveme_tcp_network_connect(const char *ip_address, int port, int flags, const char* program_name)
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
    int res = magicnet_client_preform_entry_protocol_write(mclient, program_name);
    if (res < 0)
    {
        magicnet_close(mclient);
        mclient = NULL;
    }
    return mclient;
}

int magicnet_client_process_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    switch (packet->type)
    {
    }
    return res;
}

int magicnet_client_manage_next_packet(struct magicnet_client *client)
{
    struct magicnet_packet packet;
    if (magicnet_client_read_packet(client, &packet) < 0)
    {
        return -1;
    }

    if (magicnet_client_process_packet(client, &packet) < 0)
    {
        return -1;
    }

    return 0;
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

    res = magicnet_write_bytes(client, (void*)program_name, MAGICNET_PROGRAM_NAME_SIZE);
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