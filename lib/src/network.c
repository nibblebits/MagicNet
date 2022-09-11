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
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include "magicnet/config.h"
#include "magicnet/magicnet.h"
#include "magicnet/log.h"
#include "key.h"

int magicnet_send_pong(struct magicnet_client *client);
void magicnet_close(struct magicnet_client *client);
int magicnet_client_process_user_defined_packet(struct magicnet_client *client, struct magicnet_packet *packet);
int magicnet_server_poll_process(struct magicnet_client *client, struct magicnet_packet *packet);
struct signed_data *magicnet_signed_data(struct magicnet_packet *packet)
{
    return &packet->signed_data;
}

struct magicnet_packet *magicnet_packet_new()
{
    struct magicnet_packet *packet = calloc(1, sizeof(struct magicnet_packet));
    magicnet_signed_data(packet)->id = rand() % 999999999;
    return packet;
}

void magicnet_server_create_files()
{
    // We should setup the seeder for when we use random.

    struct timespec time_seed;
    // CLOCK_MONOTONIC: absolute elapsed wall-clock time since // an arbitrary point in the past.
    clock_gettime(CLOCK_MONOTONIC, &time_seed);
    // use nanoseconds to seed RNG.
    srand((time_t)time_seed.tv_nsec);

    char data_directory[PATH_MAX];
    sprintf(data_directory, "%s/%s", getenv("HOME"), ".magicnet");
    DIR *dir = opendir(data_directory);
    if (!dir)
    {
        // First time setup
        mkdir(data_directory, 0775);
    }
}
bool magicnet_loaded_ips_full(struct magicnet_server *server)
{
    return server->total_loaded_ips >= MAGICNET_MAX_LOADED_IP_ADDRESSES;
}

const char **magicnet_get_free_loaded_ip_slot(struct magicnet_server *server)
{
    for (int i = 0; i < MAGICNET_MAX_LOADED_IP_ADDRESSES; i++)
    {
        if (server->loaded_ip_addresses[i] == NULL)
            return (const char **)&server->loaded_ip_addresses;
    }

    return NULL;
}

int magicnet_loaded_ips_add(struct magicnet_server *server, const char *ip_address)
{
    if (magicnet_loaded_ips_full(server))
    {
        magicnet_log("%s the ip list is full\n", __FUNCTION__);
        return -1;
    }

    const char **free_ip_slot = magicnet_get_free_loaded_ip_slot(server);
    *free_ip_slot = ip_address;
    server->total_loaded_ips++;
    return 0;
}
bool magicnet_is_ip_loaded(struct magicnet_server *server, const char *ip_address)
{
    for (int i = 0; i < MAGICNET_MAX_LOADED_IP_ADDRESSES; i++)
    {
        if (strncmp(server->loaded_ip_addresses[i], ip_address, strlen(server->loaded_ip_addresses[i])) == 0)
        {
            return true;
        }
    }

    return false;
}

int magicnet_load_ips(struct magicnet_server *server)
{
    // Normally we would load randomly but for now in order.

    magicnet_loaded_ips_add(server, "104.248.237.170");
    // TODO
    // size_t read = 0;
    // size_t len = 0;
    // char *line = NULL;
    // while ((read = getline(&line, &len, server->ip_file)) != -1)
    // {
    //     magicnet_loaded_ips_add(server, line);
    // }
    // return 0;
}

int magicnet_ip_file_add_ip(struct magicnet_server *server, const char *ip_address)
{
    int res = magicnet_loaded_ips_add(server, ip_address);
    if (res < 0)
    {
        return -1;
    }
    return fwrite(ip_address, strlen(ip_address), 1, server->ip_file) > 0 ? 0 : -1;
}

struct magicnet_server *magicnet_server_start()
{
    int sockfd, len;
    struct sockaddr_in servaddr, cli;

    magicnet_server_create_files();

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

    if ((listen(sockfd, MAGICNET_MAX_INCOMING_CONNECTIONS)) != 0)
    {
        magicnet_log("TCP Server Listen failed...\n");
        return NULL;
    }

    struct magicnet_server *server = calloc(1, sizeof(struct magicnet_server));
    server->sock = sockfd;
    if (pthread_mutex_init(&server->lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the server lock\n");
        return NULL;
    }

    char ip_file[PATH_MAX];
    sprintf(ip_file, "%s/%s/%s", getenv("HOME"), ".magicnet", "ips.txt");

    FILE *ip_file_p = fopen(ip_file, "a");
    if (!ip_file_p)
    {
        magicnet_log("IP file could not be opened\n");
        return NULL;
    }
    server->ip_file = ip_file_p;
    magicnet_load_ips(server);

    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        magicnet_signed_data(&server->relay_packets.packets[i])->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
        server->seen_packets.packet_ids[i] = -1;
    }

    srand(time(NULL));

    MAGICNET_load_keypair();

    server->next_block.verifier_votes.votes = vector_create(sizeof(struct magicnet_key_vote*));
    server->next_block.signed_up_verifiers = vector_create(sizeof(struct key*));
    return server;
}

bool magicnet_server_has_seen_packet(struct magicnet_server *server, struct magicnet_packet *packet)
{
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (server->seen_packets.packet_ids[i] == magicnet_signed_data(packet)->id)
            return true;
    }

    return false;
}

int magicnet_server_add_seen_packet(struct magicnet_server *server, struct magicnet_packet *packet)
{
    // Do we already have this packet to relay?
    long *seen_packet_id_ptr = &server->seen_packets.packet_ids[server->seen_packets.pos % MAGICNET_MAX_AWAITING_PACKETS];
    *seen_packet_id_ptr = magicnet_signed_data(packet)->id;
    server->seen_packets.pos++;
    return 0;
}

bool magicnet_client_in_use(struct magicnet_client *client)
{
    return client->flags & MAGICNET_CLIENT_FLAG_CONNECTED;
}

struct magicnet_client *magicnet_find_free_client(struct magicnet_server *server)
{
    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        if (!magicnet_client_in_use(&server->clients[i]))
        {
            bzero(&server->clients[i], sizeof(struct magicnet_client));
            return &server->clients[i];
        }
    }

    return NULL;
}

struct magicnet_client *magicnet_find_free_outgoing_client(struct magicnet_server *server)
{
    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        if (!magicnet_client_in_use(&server->outgoing_clients[i]))
        {
            bzero(&server->outgoing_clients[i], sizeof(struct magicnet_client));
            return &server->outgoing_clients[i];
        }
    }

    return NULL;
}

void magicnet_server_lock(struct magicnet_server *server)
{
    pthread_mutex_lock(&server->lock);
}

void magicnet_server_unlock(struct magicnet_server *server)
{
    pthread_mutex_unlock(&server->lock);
}

void magicnet_init_client(struct magicnet_client *client, struct magicnet_server *server, int connfd, struct sockaddr_in *addr_in)
{
    memset(client, 0, sizeof(struct magicnet_client));
    client->sock = connfd;
    client->server = server;
    client->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    memcpy(&client->client_info, addr_in, sizeof(&client->client_info));

    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        magicnet_signed_data(&client->awaiting_packets[i])->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
    }
}

struct magicnet_client *magicnet_tcp_network_connect_for_server(struct magicnet_server *server, const char *ip_address, int port, const char *program_name)
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
        // magicnet_log("Failed to set socket timeout\n");
        return NULL;
    }

    // connect the client socket to server socket
    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        return NULL;
    }

    magicnet_server_lock(server);
    struct magicnet_client *mclient = magicnet_find_free_outgoing_client(server);
    if (!mclient)
    {
        return NULL;
    }
    magicnet_init_client(mclient, server, sockfd, &servaddr);
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    mclient->relay_packet_pos = server->relay_packets.pos;
    magicnet_server_unlock(server);

    if (program_name)
    {
        memcpy(mclient->program_name, program_name, sizeof(mclient->program_name));
    }

    int res = magicnet_client_preform_entry_protocol_write(mclient, program_name);
    if (res < 0)
    {
        magicnet_close(mclient);
        mclient = NULL;
    }

    // Let's find a free slot
    return mclient;
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

    magicnet_server_lock(server);
    struct magicnet_client *mclient = magicnet_find_free_client(server);
    if (!mclient)
    {
        // We couldn't get a free client...
        magicnet_log("%s clients are full\n", __FUNCTION__);
        magicnet_server_unlock(server);
        return NULL;
    }

    magicnet_init_client(mclient, server, connfd, &client);
    mclient->relay_packet_pos = server->relay_packets.pos;
    if (strcmp(inet_ntoa(client.sin_addr), "127.0.0.1") == 0)
    {
        // This is a localhost connection, therefore packets that are not signed are allowed.
        mclient->flags |= MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST;
    }
    magicnet_server_unlock(server);

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

int magicnet_read_bytes(struct magicnet_client *client, void *ptr_out, size_t amount, struct buffer* store_in_buffer)
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

        // Sometimes we are to store the result in a buffer for debugging and validation purposes..
        if (store_in_buffer)
        {
            buffer_write_bytes(store_in_buffer, ptr_out + amount_read, amount-amount_read);
        }

        amount_read += res;
    }
    client->last_contact = time(NULL);
    return res;
}

int magicnet_write_bytes(struct magicnet_client *client, void *ptr_out, size_t amount, struct buffer *store_in_buffer)
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

        // Sometimes we are to store the result in a buffer for debugging and validation purposes..
        if (store_in_buffer)
        {
            buffer_write_bytes(store_in_buffer, ptr_out + amount_written, amount-amount_written);
        }

        amount_written += res;
    }

    return res;
}

int magicnet_write_int(struct magicnet_client *client, int value, struct buffer *store_in_buffer)
{
    // Preform bit manipulation for big-endianness todo later...
    if (magicnet_write_bytes(client, &value, sizeof(value), store_in_buffer) < 0)
    {
        return -1;
    }

    return 0;
}

int magicnet_write_long(struct magicnet_client *client, long value, struct buffer *store_in_buffer)
{
    // Preform bit manipulation for big-endianness todo later...
    if (magicnet_write_bytes(client, &value, sizeof(value), store_in_buffer) < 0)
    {
        return -1;
    }
    return 0;
}

long magicnet_read_long(struct magicnet_client *client, struct buffer* store_in_buffer)
{
    long result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result), store_in_buffer) < 0)
    {
        return -1;
    }

    // Preform bit manipulation depending on big-endianness.... for later..
    return result;
}

int magicnet_read_int(struct magicnet_client *client, struct buffer* store_in_buffer)
{
    int result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result), store_in_buffer) < 0)
    {
        return -1;
    }

    // Preform bit manipulation for big-endianness todo later...
    return result;
}

short magicnet_read_short(struct magicnet_client *client, struct buffer* store_in_buffer)
{
    short result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result), store_in_buffer) < 0)
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
    long packet_type = magicnet_read_long(client, packet_out->not_sent.tmp_buf);
    if (packet_type < 0)
    {
        res = -1;
        goto out;
    }

    long data_size = magicnet_read_long(client, packet_out->not_sent.tmp_buf);
    data = calloc(1, data_size);
    res = magicnet_read_bytes(client, data, data_size, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, magicnet_signed_data(packet_out)->payload.user_defined.program_name, sizeof(magicnet_signed_data(packet_out)->payload.user_defined.program_name), packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    magicnet_signed_data(packet_out)->payload.user_defined.type = packet_type;
    magicnet_signed_data(packet_out)->payload.user_defined.data_len = data_size;
    magicnet_signed_data(packet_out)->payload.user_defined.data = data;

    // Send a received back
    res = magicnet_write_int(client, MAGICNET_ACKNOWLEGED_ALL_OKAY, NULL);
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

int magicnet_client_read_poll_packets_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    magicnet_signed_data(packet_out)->type = MAGICNET_PACKET_TYPE_POLL_PACKETS;
    return 0;
}

int magicnet_client_read_not_found_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    magicnet_signed_data(packet_out)->type = MAGICNET_PACKET_TYPE_NOT_FOUND;
    return 0;
}

int magicnet_client_read_server_sync_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    int flags = 0;

    flags = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (flags < 0)
    {
        res = -1;
        goto out;
    }

    if (flags & MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET)
    {
        // They also sent us a packet of their own in this sync.. Lets read it
        magicnet_signed_data(packet_out)->payload.sync.packet = magicnet_packet_new();
        res = magicnet_client_read_packet(client, magicnet_signed_data(packet_out)->payload.sync.packet);
        if (res < 0)
        {
            goto out;
        }

        if (magicnet_signed_data(packet_out)->payload.sync.packet->signed_data.type != MAGICNET_PACKET_TYPE_EMPTY_PACKET)
        {
            magicnet_log("non empty packet provided type=%i ID=%i\n", magicnet_signed_data(packet_out)->payload.sync.packet->signed_data.type, magicnet_signed_data(packet_out)->payload.sync.packet->signed_data.id);
        }
    }

    magicnet_signed_data(packet_out)->payload.sync.flags = flags;

out:
    return res;
}

int magicnet_client_read_packet_empty(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    return 0;
}

int magicnet_client_read_verifier_signup_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    return 0;
}


int magicnet_client_verify_packet_was_signed(struct magicnet_packet *packet)
{
    if (!packet->not_sent.tmp_buf)
    {
        magicnet_log("%s cannot verify if packet was signed when no temporary buffer was set\n", __FUNCTION__);
        return -1;
    }

    // Let's ensure that they signed the hash that was given to us
    int res = public_verify(&packet->pub_key, packet->datahash, sizeof(packet->datahash), &packet->signature);
    if (res < 0)
    {
        magicnet_log("%s the signatuure was not signed with the public key provided\n", __FUNCTION__);
        return -1;
    }

    char tmp_buf[SHA256_STRING_LENGTH];
    sha256_data(buffer_ptr(packet->not_sent.tmp_buf), tmp_buf, packet->not_sent.tmp_buf->len);
    if (strncmp(tmp_buf, packet->datahash, sizeof(tmp_buf)) != 0)
    {
        magicnet_log("%s the signature signed the hash but the hash is not the hash of the data provided\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

int magicnet_client_read_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    int packet_id = 0;
    int packet_type = 0;

    packet_out->not_sent.tmp_buf = buffer_create();

    packet_id = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (packet_id < 0)
    {
        return -1;
    }

    packet_type = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (packet_type < 0)
    {
        return -1;
    }

    switch (packet_type)
    {

    case MAGICNET_PACKET_TYPE_EMPTY_PACKET:
        res = magicnet_client_read_packet_empty(client, packet_out);
        break;
    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_read_user_defined_packet(client, packet_out);
        break;

    case MAGICNET_PACKET_TYPE_POLL_PACKETS:
        res = magicnet_client_read_poll_packets_packet(client, packet_out);
        break;

    case MAGICNET_PACKET_TYPE_SERVER_SYNC:
        res = magicnet_client_read_server_sync_packet(client, packet_out);
        break;

    case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        res = magicnet_client_read_verifier_signup_packet(client, packet_out);
        break;
    case MAGICNET_PACKET_TYPE_NOT_FOUND:
        res = magicnet_client_read_not_found_packet(client, packet_out);
        break;
    default:
        magicnet_log("%s unexpected packet was provided %i\n", __FUNCTION__, packet_type);
        res = -1;
        break;
    }
    magicnet_signed_data(packet_out)->id = packet_id;
    magicnet_signed_data(packet_out)->type = packet_type;

    bool has_signature = false;

    has_signature = magicnet_read_int(client, NULL);
    if (!has_signature && !(client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST))
    {
        magicnet_log("%s only localhost clients are allowed to not sign packets. All remote packets must be signed!\n", __FUNCTION__);
        return -1;
    }


    if (has_signature)
    {
        res = magicnet_read_bytes(client, &packet_out->pub_key, sizeof(packet_out->pub_key), NULL);
        if (res < 0)
        {
            return res;
        }

        res = magicnet_read_bytes(client, &packet_out->signature, sizeof(packet_out->signature), NULL);
        if (res < 0)
        {
            return res;
        }
    }

    res = magicnet_read_bytes(client, &packet_out->datahash, sizeof(packet_out->datahash), NULL);
    if (res < 0)
    {
        return -1;
    }

    // Now the packet is constructed lets verify its contents if it has been signed.
    if (has_signature)
    {
        res = magicnet_client_verify_packet_was_signed(packet_out);
        if (res < 0)
        {
            magicnet_log("%s packet was signed incorrectly\n", __FUNCTION__);
            return res;
        }
    }
out:
    buffer_free(packet_out->not_sent.tmp_buf);
    packet_out->not_sent.tmp_buf = NULL;

    // Write the response code back to the client
    magicnet_write_int(client, res, NULL);

    return res;
}

int magicnet_client_write_packet_ping(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    return res;
}

int magicnet_client_write_packet_poll_packets(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    return res;
}

int magicnet_client_write_packet_not_found(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    return res;
}

int magicnet_client_write_packet_user_defined(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    void *data = NULL;
    res = magicnet_write_long(client, magicnet_signed_data(packet)->payload.user_defined.type, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_long(client, magicnet_signed_data(packet)->payload.user_defined.data_len, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, magicnet_signed_data(packet)->payload.user_defined.data, magicnet_signed_data(packet)->payload.user_defined.data_len, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, magicnet_signed_data(packet)->payload.user_defined.program_name, sizeof(magicnet_signed_data(packet)->payload.user_defined.program_name), packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Read the response.
    res = magicnet_read_int(client, NULL);
out:
    return res;
}

int magicnet_client_write_packet_server_poll(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.sync.flags, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    if (magicnet_signed_data(packet)->payload.sync.flags & MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET)
    {
        // We need to send the packet
        if (magicnet_signed_data(packet)->payload.sync.packet->signed_data.type == MAGICNET_PACKET_TYPE_SERVER_SYNC)
        {
            // This will result in an infinite loop, to prevent denial of service attacks we must refuse
            magicnet_log("%s Attempting to provide a sync packet as server poll payload. This may result in an infinite loop so is not allowed\n", __FUNCTION__);
            res = -1;
            goto out;
        }
        res = magicnet_client_write_packet(client, magicnet_signed_data(packet)->payload.sync.packet, 0);
    }
out:
    return res;
}

int magicnet_client_write_packet_empty(struct magicnet_client *client, struct magicnet_packet *packet)
{

    return 0;
}


int magicnet_client_write_packet_verifier_signup(struct magicnet_client *client, struct magicnet_packet *packet)
{

    return 0;
}


int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet, int flags)
{
    int res = 0;
    packet->not_sent.tmp_buf = buffer_create();
    res = magicnet_write_int(client, magicnet_signed_data(packet)->id, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        return res;
    }

    res = magicnet_write_int(client, magicnet_signed_data(packet)->type, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        return res;
    }

    switch (magicnet_signed_data(packet)->type)
    {

    case MAGICNET_PACKET_TYPE_EMPTY_PACKET:
        res = magicnet_client_write_packet_empty(client, packet);

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

    case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        res = magicnet_client_write_packet_verifier_signup(client, packet);
        break;
    case MAGICNET_PACKET_TYPE_SERVER_SYNC:
        res = magicnet_client_write_packet_server_poll(client, packet);
        break;
    }

    // Okay we have a buffer of all the data we sent to the peer, lets get it and hash it so that
    // we can prove who signed this packet later on..

    sha256_data(buffer_ptr(packet->not_sent.tmp_buf), packet->datahash, packet->not_sent.tmp_buf->len);
    if (flags & MAGICNET_PACKET_FLAG_MUST_BE_SIGNED)
    {
        if (!MAGICNET_nulled_signature(&packet->signature))
        {
            magicnet_log("%s you asked us to sign the packet but it was already signed.. We will not send this packet as it may be a potential attacker playing games\n", __FUNCTION__);
            res = -1;
            return res;
        }

        packet->pub_key = *MAGICNET_public_key();
        res = private_sign(packet->datahash, sizeof(packet->datahash), &packet->signature);
        if (res < 0)
        {
            magicnet_log("%s Failed to sign data with signature\n", __FUNCTION__);
            return -1;
        }
    }

    // Its possible packet was already signed
    bool has_signature = !MAGICNET_nulled_signature(&packet->signature);
    res = magicnet_write_int(client, has_signature, NULL);
    if (res < 0)
    {
        return res;
    }

    // Send the key and signature if their is any
    if (has_signature)
    {
        res = magicnet_write_bytes(client, &packet->pub_key, sizeof(packet->pub_key), NULL);
        if (res < 0)
        {
            return res;
        }

        res = magicnet_write_bytes(client, &packet->signature, sizeof(packet->signature), NULL);
        if (res < 0)
        {
            return res;
        }
    }

    // Send the data hash
    res = magicnet_write_bytes(client, packet->datahash, sizeof(packet->datahash), NULL);
    if (res < 0)
    {
        return res;
    }

    buffer_free(packet->not_sent.tmp_buf);
    packet->not_sent.tmp_buf = NULL;

    // We expect to receive a response byte
    res = magicnet_read_int(client, NULL);
    // If the respponse is a critical error then we will change it to unknown
    // since its illegal in our protocol to transmit critical error codes to prevent abuses to terminate connections
    if (res == MAGICNET_ERROR_CRITICAL_ERROR)
    {
        res = MAGICNET_ERROR_UNKNOWN;
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
        // magicnet_log("Failed to set socket timeout\n");
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

struct magicnet_packet *magicnet_recv_next_packet(struct magicnet_client *client, int* res_out)
{
    struct magicnet_packet *packet = magicnet_packet_new();
    int res = magicnet_client_read_packet(client, packet);
    if (res < 0)
    {
        magicnet_free_packet(packet);
        packet = NULL;
    }

    *res_out = res;
    return packet;
}

struct magicnet_packet *magicnet_client_get_available_free_to_use_packet(struct magicnet_client *client)
{
    struct magicnet_packet *packet = NULL;
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (magicnet_signed_data(&client->awaiting_packets[i])->flags & MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE)
        {
            magicnet_signed_data(&client->awaiting_packets[i])->type &= ~MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
            packet = &client->awaiting_packets[i];
        }
    }

    return packet;
}

struct magicnet_packet *magicnet_client_get_next_packet_to_process(struct magicnet_client *client)
{
    struct magicnet_packet *packet = NULL;
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (magicnet_signed_data(&client->awaiting_packets[i])->flags & MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING)
        {
            packet = &client->awaiting_packets[i];
            break;
        }
    }
    return packet;
}

/**
 * @brief Copies the packet including copying all internal pointers and creating new memory
 * for the destination packet
 *
 * @param packet_in
 * @param packet_out
 */
void magicnet_copy_packet(struct magicnet_packet *packet_out, struct magicnet_packet *packet_in)
{
    memcpy(packet_out, packet_in, sizeof(struct magicnet_packet));
    switch (magicnet_signed_data(packet_in)->type)
    {
    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        magicnet_signed_data(packet_out)->payload.user_defined.data = calloc(1, magicnet_signed_data(packet_out)->payload.user_defined.data_len);
        memcpy(magicnet_signed_data(packet_out)->payload.user_defined.data, magicnet_signed_data(packet_in)->payload.user_defined.data, magicnet_signed_data(packet_out)->payload.user_defined.data_len);
        break;
    }
}
bool magicnet_client_has_awaiting_packet_been_queued(struct magicnet_client *client, struct magicnet_packet *packet)
{
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (magicnet_signed_data(&client->awaiting_packets[i])->id == magicnet_signed_data(packet)->id)
        {
            return true;
        }
    }

    return false;
}
int magicnet_client_add_awaiting_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{

    if (magicnet_client_has_awaiting_packet_been_queued(client, packet))
    {
        return MAGICNET_ERROR_RECEIVED_PACKET_BEFORE;
    }

    struct magicnet_packet *awaiting_packet = magicnet_client_get_available_free_to_use_packet(client);
    if (!awaiting_packet)
    {
        return MAGICNET_ERROR_QUEUE_FULL;
    }

    // Let us check if the packet has already been sent before
    magicnet_copy_packet(awaiting_packet, packet);
    magicnet_signed_data(awaiting_packet)->flags |= MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING;
    magicnet_signed_data(awaiting_packet)->flags &= ~MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
    return 0;
}

bool magicnet_server_has_relay_packet_been_queued(struct magicnet_server *server, struct magicnet_packet *packet)
{
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (magicnet_signed_data(&server->relay_packets.packets[i])->id == magicnet_signed_data(packet)->id)
        {
            return true;
        }
    }

    return false;
}

int magicnet_server_add_packet_to_relay(struct magicnet_server *server, struct magicnet_packet *packet)
{
    if (magicnet_server_has_relay_packet_been_queued(server, packet))
    {
        return MAGICNET_ERROR_RECEIVED_PACKET_BEFORE;
    }

    // Do we already have this packet to relay?
    struct magicnet_packet *free_relay_packet = &server->relay_packets.packets[server->relay_packets.pos % MAGICNET_MAX_AWAITING_PACKETS];
    if (!(magicnet_signed_data(free_relay_packet)->flags & MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE))
    {
        magicnet_free_packet_pointers(free_relay_packet);
    }

    magicnet_copy_packet(free_relay_packet, packet);
    magicnet_signed_data(free_relay_packet)->flags &= ~MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;

    server->relay_packets.pos++;
    return 0;
}

struct magicnet_packet *magicnet_client_next_packet_to_relay(struct magicnet_client *client)
{
    if (!client->server)
    {
        return NULL;
    }

    struct magicnet_server *server = client->server;
    struct magicnet_packet *packet = &server->relay_packets.packets[client->relay_packet_pos % MAGICNET_MAX_AWAITING_PACKETS];

    if (!(magicnet_signed_data(packet)->flags & MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE))
    {
        // Yeah we had a valid packet we can use this.
        client->relay_packet_pos++;
    }
    return packet;
}
/**
 * @brief Marks the packet in the client->awaiting_packets array as processed
 * \note The packet point must be the same pointer returned from magicnet_client_get_next_packet_to_process
 * @param client
 * @param packet
 */
void magicnet_client_mark_packet_processed(struct magicnet_client *client, struct magicnet_packet *packet)
{
    memset(packet, 0, sizeof(struct magicnet_packet));
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (magicnet_signed_data(&client->awaiting_packets[i])->id == magicnet_signed_data(packet)->id)
        {
            magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
            break;
        }
    }
}

int magicnet_client_process_packet_poll_packets(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_log("%s polling packet request\n", __FUNCTION__);
    struct magicnet_packet *packet_to_process = NULL;
    struct magicnet_packet *packet_to_send = NULL;
    magicnet_server_lock(client->server);
    packet_to_process = magicnet_client_get_next_packet_to_process(client);
    magicnet_server_unlock(client->server);

    if (!packet_to_process)
    {
        packet_to_send = magicnet_packet_new();
        magicnet_signed_data(packet_to_send)->type = MAGICNET_PACKET_TYPE_NOT_FOUND;
        res = magicnet_client_write_packet(client, packet_to_send, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
        magicnet_log("%s Not found\n", __FUNCTION__);

        goto out;
    }

    magicnet_log("%s packet found\n", __FUNCTION__);
    // We have a packet they could use.. Lets send it there way.. We wont sign it as it should already be signed.
    res = magicnet_client_write_packet(client, packet_to_process, 0);
    if (res < 0)
    {
        goto out;
    }

out:
    // Free the internal pointers of this packet since we don't care about it anymore as its been sent.
    // Note dont use packet_free as this packet is declared in an array its not a pointer. It will
    // be reused for a different packet once marked as processed.
    if (packet_to_process)
    {
        magicnet_free_packet_pointers(packet_to_process);
        magicnet_client_mark_packet_processed(client, packet_to_process);
    }
    if (packet_to_send)
    {
        magicnet_free_packet(packet_to_send);
    }
    return res;
}

int magicnet_client_process_user_defined_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    // We got to lock this server
    magicnet_server_lock(client->server);

    // We must find all the clients of the same program name
    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        struct magicnet_client *cli = &client->server->clients[i];
        if (!magicnet_client_in_use(client))
        {
            continue;
        }

        // Same program name as the sending client? Then add it to the packet queue of the connected client
        if (strncmp(cli->program_name, magicnet_signed_data(packet)->payload.user_defined.program_name, sizeof(cli->program_name)) == 0)
        {
            magicnet_client_add_awaiting_packet(cli, packet);
        }
    }
    magicnet_server_add_packet_to_relay(client->server, packet);
    magicnet_server_unlock(client->server);
    return res;
}

int magicnet_client_process_server_sync_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct magicnet_packet *packet_to_relay = magicnet_packet_new();
    // We got to lock this server
    magicnet_server_lock(client->server);
    magicnet_copy_packet(packet_to_relay, magicnet_client_next_packet_to_relay(client));
    magicnet_server_unlock(client->server);

    // We have a packet lets send to the client
    res = magicnet_client_write_packet(client, packet_to_relay, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        goto out;
    }

    // Do we also have a packet from them?
    if (magicnet_signed_data(packet)->payload.sync.flags & MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET)
    {
        res = magicnet_server_poll_process(client, magicnet_signed_data(packet)->payload.sync.packet);
        if (res < 0)
        {
            goto out;
        }
    }

out:
    magicnet_free_packet(packet_to_relay);
    return res;
}


bool magicnet_server_verifier_is_signed_up(struct magicnet_server* server, struct key* key)
{
    vector_set_peek_pointer(server->next_block.signed_up_verifiers, 0);
    struct key* key_in_vec = vector_peek_ptr(server->next_block.signed_up_verifiers);
    while(key_in_vec)
    {
        if (key_cmp(key_in_vec, key))
        {
            return true;
        }
        key_in_vec = vector_peek_ptr(server->next_block.signed_up_verifiers);
    }

    return false;
}

int magicnet_server_verifier_signup(struct magicnet_server* server, struct key* pub_key)
{
    int res = 0;
    // Already signed up.
    if (magicnet_server_verifier_is_signed_up(server, pub_key))
    {
        res = MAGICNET_ERROR_ALREADY_EXISTANT;
        goto out;
    }

    // We allow a maximum of 20480 verifiers if we have too many we will reject this signup
    if (vector_count(server->next_block.signed_up_verifiers) > MAGICNET_MAX_VERIFIER_CONTESTANTS)
    {
        res = MAGICNET_ERROR_QUEUE_FULL;
        goto out;
    }
    
    // We must now add this verifier to the vector
    // Clone the key
    struct key* cloned_key = calloc(1, sizeof(struct key));
    memcpy(cloned_key, pub_key, sizeof(struct key));
    vector_push(server->next_block.signed_up_verifiers, &cloned_key);

    magicnet_log("%s new verifier signup %s\n", __FUNCTION__, pub_key->key);
out:
    return res;
}
int magicnet_client_process_verifier_signup(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    if (!client->server)
    {
        magicnet_log("%s no server instance for this client to use for verifier signup\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    magicnet_server_lock(client->server);
    res = magicnet_server_verifier_signup(client->server, &packet->pub_key);
    magicnet_server_unlock(client->server);
    

out:
    return res; 
}
int magicnet_client_process_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    assert(client->server);

    int res = 0;
    switch (magicnet_signed_data(packet)->type)
    {
    case MAGICNET_PACKET_TYPE_POLL_PACKETS:
        res = magicnet_client_process_packet_poll_packets(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_process_user_defined_packet(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        res = magicnet_client_process_verifier_signup(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_SERVER_SYNC:
        res = magicnet_client_process_server_sync_packet(client, packet);
        break;
    case MAGICNET_PACKET_TYPE_EMPTY_PACKET:
        // empty..
        res = 0;
        break;
    default:
        magicnet_log("%s Illegal packet provided\n", __FUNCTION__);
        res = -1;
    }

    // We have seen this packet now.
    magicnet_server_add_seen_packet(client->server, packet);
    return res;
}

int magicnet_client_manage_next_packet(struct magicnet_client *client)
{
    int res = 0;
    struct magicnet_packet *packet = magicnet_recv_next_packet(client, &res);
    if (!packet)
    {
        magicnet_log("%s failed to receive new packet from client\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_client_process_packet(client, packet);
    if (res < 0)
    {
        goto out;
    }

out:
    if (packet)
    {
        magicnet_free_packet(packet);
    }
    return res;
}

int magicnet_client_preform_entry_protocol_read(struct magicnet_client *client)
{
    struct magicnet_server *server = client->server;
    int res = 0;
    int signature = magicnet_read_int(client, NULL);
    if (signature != MAGICNET_ENTRY_SIGNATURE)
    {
        magicnet_log("%s somebody connected to us but doesnt understand our protocol.. Probably some accidental connection.. Dropping\n", __FUNCTION__);
        return -1;
    }
    // We need to find out what they are listening too before we can accept them.
    // What is the program they are subscribing too, lets read it.
    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
    res = magicnet_read_bytes(client, program_name, sizeof(program_name), NULL);
    if (res < 0)
    {
        return -1;
    }

    memcpy(client->program_name, program_name, sizeof(client->program_name));
    res = magicnet_write_int(client, MAGICNET_ENTRY_SIGNATURE, NULL);
    return res;
}

int magicnet_client_preform_entry_protocol_write(struct magicnet_client *client, const char *program_name)
{
    int res = 0;
    res = magicnet_write_int(client, MAGICNET_ENTRY_SIGNATURE, NULL);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, (void *)program_name, MAGICNET_PROGRAM_NAME_SIZE, NULL);
    if (res < 0)
    {
        goto out;
    }

    // Now lets see if we got the signature back
    int sig = 0;
    sig = magicnet_read_int(client, NULL);
    if (sig < 0)
    {
        res = -1;
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
    // assert(0==1)
    // int res = magicnet_client_write_packet(client, &(struct magicnet_packet){.type = MAGICNET_PACKET_TYPE_PING});
    // if (res < 0)
    // {
    //     return res;
    // }

    return 0;
}

int magicnet_send_pong(struct magicnet_client *client)
{
    // assert(0==1);
    // int res = magicnet_client_write_packet(client, &(struct magicnet_packet){.type = MAGICNET_PACKET_TYPE_PONG});
    // if (res < 0)
    // {
    //     return res;
    // }

    return 0;
}

int magicnet_ping_pong(struct magicnet_client *client)
{
    // int res = magicnet_ping(client);
    // struct magicnet_packet packet = {};
    // res = magicnet_client_read_packet(client, &packet);
    // if (res < 0)
    // {
    //     return res;
    // }
    return 0;
    // return packet.type == MAGICNET_PACKET_TYPE_PONG;
}

int magicnet_server_poll_process_user_defined_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    // We have a user defined packet, lets relay to all our localhost listening clients..
    res = magicnet_client_process_user_defined_packet(client, packet);

    return res;
}
int magicnet_server_poll_process(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_server_lock(client->server);
    if (magicnet_server_has_seen_packet(client->server, packet))
    {
        magicnet_server_unlock(client->server);
        return 0;
    }
    magicnet_server_unlock(client->server);

    switch (magicnet_signed_data(packet)->type)
    {
    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_server_poll_process_user_defined_packet(client, packet);
        break;
    };

    magicnet_server_lock(client->server);
    res = magicnet_server_add_seen_packet(client->server, packet);
    magicnet_server_unlock(client->server);

    return res;
}
int magicnet_server_poll(struct magicnet_client *client)
{
    int res = 0;

    // We also want to send a packet of our own
    int flags = MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET;

    struct magicnet_packet *packet_to_send = magicnet_packet_new();
    struct magicnet_packet *packet_to_relay = magicnet_packet_new();
    magicnet_server_lock(client->server);
    magicnet_copy_packet(packet_to_relay, magicnet_client_next_packet_to_relay(client));
    magicnet_server_unlock(client->server);
    if (magicnet_signed_data(packet_to_relay)->type != MAGICNET_PACKET_TYPE_EMPTY_PACKET)
    {
        magicnet_log("non empty packet to send\n");
    }
    magicnet_signed_data(packet_to_send)->type = MAGICNET_PACKET_TYPE_SERVER_SYNC;
    magicnet_signed_data(packet_to_send)->payload.sync.flags = flags;
    magicnet_signed_data(packet_to_send)->payload.sync.packet = packet_to_relay;
    res = magicnet_client_write_packet(client, packet_to_send, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        goto out;
    }

    struct magicnet_packet *packet = magicnet_recv_next_packet(client, &res);
    if (packet == NULL)
    {
        goto out;
    }

    if (magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_EMPTY_PACKET)
    {
        res = 0;
        goto out;
    }

    // Alright we got a packet to relay.. Lets deal with it
    res = magicnet_server_poll_process(client, packet);
    if (res < 0)
    {
        goto out;
    }

out:
    magicnet_free_packet(packet_to_send);
    magicnet_free_packet(packet);
    magicnet_free_packet(packet_to_relay);
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

    while (res != MAGICNET_ERROR_CRITICAL_ERROR)
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

bool magicnet_server_is_accepted_connection_connected(struct magicnet_server *server, const char *ip_address)
{
    struct in_addr addr = {};
    if (inet_aton(ip_address, &addr) == 0)
    {
        return false;
    }
    for (int i = 0; i < MAGICNET_MAX_OUTGOING_CONNECTIONS; i++)
    {
        struct magicnet_client *client = &server->clients[i];
        if (client->flags & MAGICNET_CLIENT_FLAG_CONNECTED &&
            addr.s_addr == client->client_info.sin_addr.s_addr)
        {
            return true;
        }
    }
    return false;
}

bool magicnet_server_is_outgoing_connection_connected(struct magicnet_server *server, const char *ip_address)
{
    struct in_addr addr = {};
    if (inet_aton(ip_address, &addr) == 0)
    {
        return false;
    }
    for (int i = 0; i < MAGICNET_MAX_OUTGOING_CONNECTIONS; i++)
    {
        struct magicnet_client *client = &server->outgoing_clients[i];
        if (client->flags & MAGICNET_CLIENT_FLAG_CONNECTED &&
            addr.s_addr == client->client_info.sin_addr.s_addr)
        {
            return true;
        }
    }
    return false;
}
bool magicnet_server_is_ip_connected(struct magicnet_server *server, const char *ip_address)
{
    if (magicnet_server_is_accepted_connection_connected(server, ip_address))
    {
        return true;
    }

    if (magicnet_server_is_outgoing_connection_connected(server, ip_address))
    {
        return true;
    }
    return false;
}

const char *magicnet_server_get_next_ip_to_connect_to(struct magicnet_server *server)
{
    const char *conn_ip = NULL;
    for (int i = 0; i < MAGICNET_MAX_LOADED_IP_ADDRESSES; i++)
    {
        const char *ip = server->loaded_ip_addresses[i];
        magicnet_server_lock(server);
        if (ip && !magicnet_server_is_ip_connected(server, ip))
        {
            conn_ip = ip;
        }
        magicnet_server_unlock(server);
        break;
    }

    return conn_ip;
}

bool magicnet_client_have_we_offered_to_make_next_block(struct magicnet_client* client)
{
    return client->flags & MAGICNET_CLIENT_FLAG_WE_OFFERED_TO_VERIFY_NEXT_BLOCK;
}

int magicnet_offer_to_client_to_verify_next_block(struct magicnet_client* client)
{
    int res = 0;
    struct magicnet_packet* packet = magicnet_packet_new();
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP;
    res = magicnet_client_write_packet(client, packet, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    magicnet_free_packet(packet);
    client->flags |= MAGICNET_CLIENT_FLAG_WE_OFFERED_TO_VERIFY_NEXT_BLOCK;
    return res;
}
void *magicnet_server_client_thread(void *_client)
{
    struct magicnet_client *client = _client;
    magicnet_log("%s new outbound connection created\n", __FUNCTION__);

    int res = 0;
    while (res >= 0)
    {
        // After half time we must send our key to be a verifier.
        if ((time(NULL) % MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS) > MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS / 2)
        {
            if (magicnet_client_have_we_offered_to_make_next_block(client))
            {
                // Okay lets offer this
                magicnet_offer_to_client_to_verify_next_block(client);
            }
        }
        // We must ask the server to relay packets to us
        magicnet_server_poll(client);
        usleep(2000000);
    }
    magicnet_close(client);
}

void magicnet_server_attempt_new_connections(struct magicnet_server *server)
{
    const char *ip = magicnet_server_get_next_ip_to_connect_to(server);
    if (!ip)
    {
        return;
    }

    struct magicnet_client *client = magicnet_tcp_network_connect_for_server(server, ip, MAGICNET_SERVER_PORT, MAGICNET_LISTEN_ALL_PROGRAM);
    if (client)
    {
        pthread_t threadId;
        if (pthread_create(&threadId, NULL, &magicnet_server_client_thread, client))
        {
            // Error thread not created.
            return;
        }
    }
}

bool magicnet_server_should_make_new_connections(struct magicnet_server *server)
{
    return (time(NULL) - server->last_new_connection_attempt) >= MAGICNET_ATTEMPT_NEW_CONNECTIONS_AFTER_SECONDS;
}
int magicnet_server_process(struct magicnet_server *server)
{
    int res = 0;
    if (magicnet_server_should_make_new_connections(server))
    {
        magicnet_server_attempt_new_connections(server);
        server->last_new_connection_attempt = time(NULL);
    }

    return res;
}
void *magicnet_server_thread(void *_server)
{
    struct magicnet_server *server = _server;
    while (1)
    {
        magicnet_server_process(server);
        usleep(500000);
    }
}

int magicnet_network_thread_start(struct magicnet_server *server)
{
    pthread_t threadId;
    if (pthread_create(&threadId, NULL, &magicnet_server_thread, server))
    {
        return -1;
    }

    return 0;
}