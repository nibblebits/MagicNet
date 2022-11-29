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
#include "magicnet/database.h"
#include "magicnet/config.h"
#include "magicnet/magicnet.h"
#include "magicnet/log.h"
#include "key.h"

int magicnet_send_pong(struct magicnet_client *client);
void magicnet_close(struct magicnet_client *client);
int magicnet_client_process_user_defined_packet(struct magicnet_client *client, struct magicnet_packet *packet);
int magicnet_server_poll_process(struct magicnet_client *client, struct magicnet_packet *packet);
void magicnet_server_reset_block_sequence(struct magicnet_server *server);
void magicnet_server_get_thread_ids(struct magicnet_server *server, struct vector *thread_id_vec_out)
{
    vector_set_peek_pointer(server->thread_ids, 0);
    pthread_t *thread_id = vector_peek(server->thread_ids);
    while (thread_id)
    {
        vector_push(thread_id_vec_out, thread_id);
        thread_id = vector_peek(server->thread_ids);
    }
}
void magicnet_server_shutdown_server_instance(struct magicnet_server *server)
{
    struct vector *thread_ids = vector_create(sizeof(pthread_t));
    magicnet_server_lock(server);
    server->shutdown = true;
    magicnet_server_get_thread_ids(server, thread_ids);
    magicnet_server_unlock(server);

    magicnet_important("%s waiting on %i threads in the server instance to finish\n", __FUNCTION__, vector_count(thread_ids));

    vector_set_peek_pointer(thread_ids, 0);
    pthread_t *thread_id = vector_peek(thread_ids);
    while (thread_id)
    {
        pthread_join(*thread_id, NULL);
        thread_id = vector_peek(thread_ids);
    }

    vector_free(thread_ids);
}

void magicnet_server_add_thread(struct magicnet_server *server, pthread_t thread_id)
{
    vector_push(server->thread_ids, &thread_id);
}

void magicnet_server_remove_thread(struct magicnet_server *server, pthread_t thread_id)
{
    vector_set_peek_pointer(server->thread_ids, 0);
    pthread_t *_thread_id = vector_peek(server->thread_ids);
    while (_thread_id)
    {
        if (thread_id == *_thread_id)
        {
            vector_pop_last_peek(server->thread_ids);
            break;
        }
        _thread_id = vector_peek(server->thread_ids);
    }
}

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

/**
 * @brief Clears the signature and hash of this packet, sets the MAGICNET_PACKET_FLAG_MUST_BE_SIGNED flag
 * to ensure it gets signed when we send this packet.
 *
 * @param packet
 * @return int
 */
int magicnet_packet_resign_on_send(struct magicnet_packet *packet)
{
    memset(packet->datahash, 0, sizeof(packet->datahash));
    memset(&packet->signature, 0, sizeof(packet->signature));
    packet->signed_data.flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    return 0;
}

struct magicnet_client *magicnet_client_new()
{
    return calloc(1, sizeof(struct magicnet_client));
}
void magicnet_client_free(struct magicnet_client *client)
{
    free(client);
}

void magicnet_server_free(struct magicnet_server *server)
{
    if (!server)
    {
        return;
    }
    magicnet_server_reset_block_sequence(server);
    vector_free(server->next_block.block_transactions);
    vector_free(server->next_block.signed_up_verifiers);
    vector_free(server->next_block.verifier_votes.vote_counts);
    vector_free(server->next_block.verifier_votes.votes);
    vector_free(server->thread_ids);
    pthread_rwlock_destroy(&server->lock);
    free(server);
}

void magicnet_ip_count_vec_free(struct vector *vec)
{
    vector_set_peek_pointer(vec, 0);
    struct magicnet_ip_count *ip_vec_count = vector_peek_ptr(vec);
    while (ip_vec_count)
    {
        free(ip_vec_count);
        ip_vec_count = vector_peek_ptr(vec);
    }

    vector_free(vec);
}

void magicnet_ip_count_vec_add_or_increment(struct vector *vec, const char *ip_addr)
{
    vector_set_peek_pointer(vec, 0);
    struct magicnet_ip_count *ip_vec_count = vector_peek_ptr(vec);
    while (ip_vec_count)
    {
        if (strncmp(ip_vec_count->ip_address, ip_addr, sizeof(ip_vec_count->ip_address)) == 0)
        {
            ip_vec_count->count++;
            break;
        }
        ip_vec_count = vector_peek_ptr(vec);
    }

    if (!ip_vec_count)
    {
        ip_vec_count = calloc(1, sizeof(struct magicnet_ip_count));
        ip_vec_count->count = 1;
        strncpy(ip_vec_count->ip_address, ip_addr, sizeof(ip_vec_count->ip_address));
        vector_push(vec, &ip_vec_count);
    }
}

const char *magicnet_ip_count_get_dominant(struct vector *ip_count_vec)
{
    struct magicnet_ip_count *dominant_ip_count = NULL;
    vector_set_peek_pointer(ip_count_vec, 0);
    struct magicnet_ip_count *ip_count = vector_peek_ptr(ip_count_vec);
    dominant_ip_count = ip_count;
    while (ip_count)
    {
        if (ip_count->count > dominant_ip_count->count)
        {
            dominant_ip_count = ip_count;
        }
        ip_count = vector_peek_ptr(ip_count_vec);
    }

    if (dominant_ip_count)
    {
        return dominant_ip_count->ip_address;
    }

    return NULL;
}

void magicnet_server_test_port_forwarded(struct magicnet_server *server)
{
    server->port_forwarded = false;
    struct magicnet_client *client = magicnet_tcp_network_connect_for_ip(server->our_ip, MAGICNET_SERVER_PORT, 0, "test-program");
    if (client)
    {
        magicnet_log("%s we have detected we are port forwarded and can receive incoming connections\n", __FUNCTION__);
        server->port_forwarded = true;
        magicnet_close(client);
    }
    else
    {
        magicnet_log("%s we have detected we have not port forwarded. We recommend port forwarding for better preformance on the network\n", __FUNCTION__);
    }
}

void magicnet_server_recalculate_my_ip(struct magicnet_server *server)
{
    struct vector *ip_vec = vector_create(sizeof(struct magicnet_ip_count *));

    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        if (magicnet_connected(&server->clients[i]))
        {
            magicnet_ip_count_vec_add_or_increment(ip_vec, server->clients[i].my_ip_address_to_client);
        }
    }

    for (int i = 0; i < MAGICNET_MAX_OUTGOING_CONNECTIONS; i++)
    {
        if (magicnet_connected(&server->outgoing_clients[i]))
        {
            magicnet_ip_count_vec_add_or_increment(ip_vec, server->outgoing_clients[i].my_ip_address_to_client);
        }
    }

    const char *dominant_ip = magicnet_ip_count_get_dominant(ip_vec);

    // We must never allow 127.0.0.1 to be seen as our global ip address
    // this may allow exploitable things to happen.
    if (dominant_ip && strncmp(dominant_ip, "127.0.0.1", sizeof(dominant_ip)) != 0)
    {
        if (strncmp(server->our_ip, dominant_ip, sizeof(server->our_ip)) != 0)
        {
            magicnet_log("%s our ip address has been detected as %s\n", __FUNCTION__, dominant_ip);
            magicnet_server_test_port_forwarded(server);
        }
        strncpy(server->our_ip, dominant_ip, sizeof(server->our_ip));
    }

    magicnet_ip_count_vec_free(ip_vec);
}

struct magicnet_server *magicnet_server_start(int port)
{
    int sockfd, len;
    struct sockaddr_in servaddr, cli;

    // Ignore all SIGPIPE
    signal(SIGPIPE, SIG_IGN);

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
    servaddr.sin_port = htons(port);

    int _true = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &_true, sizeof(int)) < 0)
    {
        magicnet_log("Failed to set socket reusable option\n");
        return NULL;
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &_true, sizeof(int)) < 0)
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
    if (pthread_rwlock_init(&server->lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the server lock\n");
        return NULL;
    }

    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        server->seen_packets.packet_ids[i] = -1;
    }

    srand(time(NULL));

    server->next_block.verifier_votes.votes = vector_create(sizeof(struct magicnet_key_vote *));
    server->next_block.verifier_votes.vote_counts = vector_create(sizeof(struct magicnet_vote_count *));
    server->next_block.signed_up_verifiers = vector_create(sizeof(struct key *));
    server->next_block.block_transactions = vector_create(sizeof(struct block_transaction *));
    server->server_started = time(NULL);
    server->first_block_cycle = server->server_started + (MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS - (server->server_started % MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS));
    server->thread_ids = vector_create(sizeof(pthread_t));
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

void magicnet_server_read_lock(struct magicnet_server *server)
{
    pthread_rwlock_rdlock(&server->lock);
}

void magicnet_server_lock(struct magicnet_server *server)
{
    pthread_rwlock_wrlock(&server->lock);
}

void magicnet_server_unlock(struct magicnet_server *server)
{
    pthread_rwlock_unlock(&server->lock);
}

bool magicnet_server_awaiting_transaction_exists(struct magicnet_server *server, struct block_transaction *transaction)
{
    vector_set_peek_pointer(server->next_block.block_transactions, 0);
    struct block_transaction *current_trans = vector_peek_ptr(server->next_block.block_transactions);
    while (current_trans)
    {
        if (strncmp(current_trans->hash, transaction->hash, sizeof(current_trans->hash)) == 0)
        {
            return true;
        }
        current_trans = vector_peek_ptr(server->next_block.block_transactions);
    }

    return false;
}

int magicnet_server_awaiting_transaction_add(struct magicnet_server *server, struct block_transaction *transaction)
{
    int res = 0;
    if (vector_count(server->next_block.block_transactions) > 0)
    {
        res = MAGICNET_ERROR_QUEUE_FULL;
        goto out;
    }

    if (magicnet_server_awaiting_transaction_exists(server, transaction))
    {
        res = MAGICNET_ERROR_ALREADY_EXISTANT;
        goto out;
    }

    // Let us clone the transaction because we aren't responsible for the memory of the one passed to us.
    // the clone will be deleted when the block sequence completes
    struct block_transaction *cloned_transaction = block_transaction_clone(transaction);
    vector_push(server->next_block.block_transactions, &cloned_transaction);
out:
    return res;
}

bool magicnet_server_has_voted(struct magicnet_server *server, struct key *voter_key)
{
    vector_set_peek_pointer(server->next_block.verifier_votes.votes, 0);
    struct magicnet_key_vote *key_vote = vector_peek_ptr(server->next_block.verifier_votes.votes);
    while (key_vote)
    {
        if (key_cmp(voter_key, &key_vote->vote_from))
        {
            return true;
        }
        key_vote = vector_peek_ptr(server->next_block.verifier_votes.votes);
    }

    return false;
}

size_t magicnet_client_time_elapsed(struct magicnet_client *client)
{
    return time(NULL) - client->connection_began;
}

size_t magicnet_client_average_download_speed(struct magicnet_client *client)
{
    off_t total_seconds_running = time(NULL) - client->connection_began;
    if (total_seconds_running == 0)
    {
        return 0;
    }
    return client->total_bytes_received / total_seconds_running;
}

size_t magicnet_client_average_upload_speed(struct magicnet_client *client)
{
    off_t total_seconds_running = magicnet_client_time_elapsed(client);
    if (total_seconds_running == 0)
    {
        return 0;
    }
    return client->total_bytes_sent / total_seconds_running;
}
/**
 * @brief Converts the first 8 bytes of this key into a long.
 *
 * @param key
 * @return long
 */
long magicnet_key_number(struct key *key)
{
    char eight_bytes[9] = {};
    char *ptr = NULL;
    strncpy(eight_bytes, key->key, 8);

    return strtol(eight_bytes, &ptr, 16);
}
/**
 * @brief This function attempts to break a tie between votes to create the next block
 * if it fails to break the tie then NULL is returned. The algorithm for how the function breaks a tie will work across
 * all peers as we do not rely on verifier signup order.
 *  *
 * @param vector_of_keys
 * @return struct key*
 */
struct key *magicnet_verifier_tie_breaker(struct vector *vector_of_keys)
{
    if (vector_empty(vector_of_keys))
    {
        return NULL;
    }

    if (vector_count(vector_of_keys) == 1)
    {
        return vector_back_ptr(vector_of_keys);
    }

    /**
     * The algorithm will work by taking the first 8 bytes of each key, which ever key has the largest first 8 bytes converted to a long
     * will win and the tie will be broken.
     */

    struct key *key_winner = NULL;
    vector_set_peek_pointer(vector_of_keys, 0);
    struct key *key = vector_peek_ptr(vector_of_keys);
    while (key)
    {
        if (key_winner)
        {
            if (magicnet_key_number(key) == magicnet_key_number(key_winner))
            {
                // We can't break this tie what incredibly circumstances..
                return NULL;
            }
            else if (magicnet_key_number(key) > magicnet_key_number(key_winner))
            {
                key_winner = key;
            }
        }
        if (!key_winner)
        {
            key_winner = key;
        }
        key = vector_peek_ptr(vector_of_keys);
    }

    return key_winner;
}
/**
 * @brief All peers vote on who should make the next block, this function returns the current winner whome should
 * make the next block. Only call this at the right time because it takes time for votes to sync around the network.
 *
 * @param server
 * @return struct key*
 */
struct key *magicnet_server_verifier_who_won(struct magicnet_server *server)
{
    struct key *winning_key = NULL;
    struct magicnet_vote_count *winning_key_vote_count = NULL;
    vector_set_peek_pointer(server->next_block.verifier_votes.vote_counts, 0);
    struct magicnet_vote_count *key_vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    struct vector *tied_voters = vector_create(sizeof(struct key *));
    while (key_vote_count)
    {

        if (winning_key_vote_count)
        {
            if (winning_key_vote_count->voters == key_vote_count->voters)
            {
                struct key *winning_key = &winning_key_vote_count->key;
                struct key *key_vote_count_key = &key_vote_count->key;
                vector_push(tied_voters, &winning_key);
                vector_push(tied_voters, &key_vote_count_key);
            }

            if (winning_key_vote_count->voters < key_vote_count->voters)
            {
                winning_key_vote_count = key_vote_count;
            }
        }

        if (!winning_key_vote_count)
        {
            winning_key_vote_count = key_vote_count;
        }

        key_vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    }

    if (winning_key_vote_count)
    {
        winning_key = &winning_key_vote_count->key;
    }

    // Let us see if their is a tie with the winning key
    bool was_tie = false;
    vector_set_peek_pointer(tied_voters, 0);
    struct key *tied_key = vector_peek_ptr(tied_voters);
    while (tied_key)
    {
        // If we have a tied key with the winning key then their can be no winner. This would allow the network to fork and divide.
        // we cant allow that where it can be stopped it will.
        if (key_cmp(winning_key, tied_key))
        {
            was_tie = true;
            break;
        }
        tied_key = vector_peek_ptr(tied_voters);
    }

    if (was_tie)
    {
        // Lets see if we can break the tie
        winning_key = magicnet_verifier_tie_breaker(tied_voters);
    }

    vector_free(tied_voters);
    return winning_key;
}

struct magicnet_vote_count *magicnet_vote_count_key_get(struct magicnet_server *server, struct key *voting_for_key)
{
    vector_set_peek_pointer(server->next_block.verifier_votes.vote_counts, 0);
    struct magicnet_vote_count *vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    while (vote_count)
    {
        if (key_cmp(&vote_count->key, voting_for_key))
        {
            return vote_count;
        }
        vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    }

    return NULL;
}
void magicnet_vote_count_create_or_increment(struct magicnet_server *server, struct key *voting_for_key)
{
    struct magicnet_vote_count *vote_count = magicnet_vote_count_key_get(server, voting_for_key);
    if (!vote_count)
    {
        vote_count = calloc(1, sizeof(struct magicnet_vote_count));
        vote_count->key = *voting_for_key;
        vote_count->voters = 0;
        vector_push(server->next_block.verifier_votes.vote_counts, &vote_count);
    }
    vote_count->voters++;
}
int magicnet_server_cast_verifier_vote(struct magicnet_server *server, struct key *voter_key, struct key *vote_for_key)
{
    if (magicnet_server_has_voted(server, voter_key))
    {
        // Cheeky trying to cast a vote twice! We dont allow change of votes all future votes REJECTED!
        return MAGICNET_ERROR_ALREADY_EXISTANT;
    }

    struct magicnet_key_vote *key_vote = calloc(1, sizeof(struct magicnet_key_vote));
    key_vote->vote_from = *voter_key;
    key_vote->voted_for = *vote_for_key;
    vector_push(server->next_block.verifier_votes.votes, &key_vote);

    magicnet_vote_count_create_or_increment(server, vote_for_key);

    magicnet_log("%s new verifier vote. Voter(%s) votes for (%s) to make the next block\n", __FUNCTION__, voter_key->key, vote_for_key->key);

    return 0;
}

void magicnet_client_set_max_bytes_to_send_per_second(struct magicnet_client *client, size_t total_bytes, int reset_in_seconds)
{
    client->max_bytes_send_per_second = total_bytes;
    client->reset_max_bytes_to_send_at = time(NULL) + reset_in_seconds;
}

void magicnet_client_set_max_bytes_to_recv_per_second(struct magicnet_client *client, size_t total_bytes, int reset_in_seconds)
{
    client->max_bytes_recv_per_second = total_bytes;
    client->reset_max_bytes_to_recv_at = time(NULL) + reset_in_seconds;
}

void magicnet_init_client(struct magicnet_client *client, struct magicnet_server *server, int connfd, struct sockaddr_in *addr_in)
{
    memset(client, 0, sizeof(struct magicnet_client));
    client->sock = connfd;
    client->server = server;
    client->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    client->connection_began = time(NULL);
    client->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    client->max_bytes_recv_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;

    memcpy(&client->client_info, addr_in, sizeof(&client->client_info));

    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        magicnet_signed_data(&client->awaiting_packets[i])->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
        magicnet_signed_data(&client->packets_for_client.packets[i])->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
    }
}

/**
 * Pushes all connected ip addresses to the output vector.
 *
 * Output vector should be sizeof(struct sockaddr_in)
 */
void magicnet_server_push_outgoing_connected_ips(struct magicnet_server *server, struct vector *vector_out)
{
    for (int i = 0; i < MAGICNET_MAX_OUTGOING_CONNECTIONS; i++)
    {
        if (magicnet_connected(&server->outgoing_clients[i]))
        {
            vector_push(vector_out, &server->outgoing_clients[i].client_info);
        }
    }
}

struct magicnet_client *magicnet_tcp_network_connect_for_ip_for_server(struct magicnet_server *server, const char *ip_address, int port, const char *program_name)
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

    int _true = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &_true, sizeof(int)) < 0)
    {
        magicnet_log("Failed to set socket reusable option\n");
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
        magicnet_server_unlock(server);
        return NULL;
    }
    magicnet_init_client(mclient, server, sockfd, &servaddr);
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    mclient->connection_began = time(NULL);
    strncpy(mclient->peer_info.ip_address, ip_address, sizeof(mclient->peer_info.ip_address));
    magicnet_server_unlock(server);

    if (program_name)
    {
        memcpy(mclient->program_name, program_name, sizeof(mclient->program_name));
    }

    int res = magicnet_client_preform_entry_protocol_write(mclient, program_name, 0);
    if (res < 0)
    {
        magicnet_server_lock(server);
        magicnet_close(mclient);
        magicnet_server_unlock(server);
        mclient = NULL;
    }

    // Let's find a free slot
    return mclient;
}

struct magicnet_client *magicnet_accept(struct magicnet_server *server)
{
    struct sockaddr_in client;
    int client_len = sizeof(client);
    bool server_is_shutting_down = false;
    magicnet_server_read_lock(server);
    if (server->shutdown)
    {
        server_is_shutting_down = true;
    }
    magicnet_server_unlock(server);

    // Refuse connections if we are shutting down.
    if (server_is_shutting_down)
    {
        return NULL;
    }

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
    int _true = 1;
    if (setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &_true, sizeof(int)) < 0)
    {
        magicnet_log("Failed to set socket reusable option\n");
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
    strncpy(mclient->peer_info.ip_address, inet_ntoa(client.sin_addr), sizeof(mclient->peer_info.ip_address));
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

    magicnet_important("%s client %p was closed, total bytes read=%i total bytes wrote=%i, average download speed=%i bps, average upload speed=%i bps, time elapsed=%i\n", __FUNCTION__, client, client->total_bytes_received, client->total_bytes_sent, magicnet_client_average_download_speed(client), magicnet_client_average_upload_speed(client), magicnet_client_time_elapsed(client));

    close(client->sock);
    client->flags &= ~MAGICNET_CLIENT_FLAG_CONNECTED;
    // Let's free all the packets
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        magicnet_free_packet_pointers(&client->packets_for_client.packets[i]);
        magicnet_free_packet_pointers(&client->awaiting_packets[i]);
    }

    // If we closed the connection of a client who was last to send the block then we must set it to NULL
    // on the server, since the client is no longer accessible.
    if (client->server && client->server->last_client_to_send_block == client)
    {
        client->server->last_client_to_send_block = NULL;
    }

    if (client->flags & MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE)
    {
        free(client);
    }
}

void magicnet_close_and_free(struct magicnet_client *client)
{
    close(client->sock);
    free(client);
}

void magicnet_client_readjust_download_speed(struct magicnet_client *client)
{
    if (time(NULL) > client->reset_max_bytes_to_send_at)
    {
        client->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    }
    if (magicnet_client_average_download_speed(client) > client->max_bytes_recv_per_second)
    {
        client->recv_delay += 10000;
    }
    else if (magicnet_client_average_download_speed(client) < client->max_bytes_recv_per_second)
    {
        client->recv_delay -= 1000;
    }
    if (client->recv_delay < 0)
    {
        client->recv_delay = 0;
    }
}

int magicnet_read_bytes(struct magicnet_client *client, void *ptr_out, size_t amount, struct buffer *store_in_buffer)
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
            buffer_write_bytes(store_in_buffer, ptr_out + amount_read, amount - amount_read);
        }

        client->total_bytes_received += res;
        amount_read += res;
        magicnet_client_readjust_download_speed(client);
        usleep(client->recv_delay);
    }
    client->last_contact = time(NULL);
    return res;
}

void magicnet_client_readjust_upload_speed(struct magicnet_client *client)
{
    if (time(NULL) > client->reset_max_bytes_to_send_at)
    {
        client->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    }
    if (magicnet_client_average_upload_speed(client) > client->max_bytes_send_per_second)
    {
        client->send_delay += 10000;
    }
    else if (magicnet_client_average_upload_speed(client) < client->max_bytes_send_per_second)
    {
        client->send_delay -= 1000;
    }
    if (client->send_delay < 0)
    {
        client->send_delay = 0;
    }
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
            buffer_write_bytes(store_in_buffer, ptr_out + amount_written, amount - amount_written);
        }

        magicnet_client_readjust_upload_speed(client);

        amount_written += res;
        client->total_bytes_sent += res;
        usleep(client->send_delay);
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

long magicnet_read_long(struct magicnet_client *client, struct buffer *store_in_buffer)
{
    long result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result), store_in_buffer) < 0)
    {
        return -1;
    }

    // Preform bit manipulation depending on big-endianness.... for later..
    return result;
}

int magicnet_read_int(struct magicnet_client *client, struct buffer *store_in_buffer)
{
    int result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result), store_in_buffer) < 0)
    {
        return -1;
    }

    // Preform bit manipulation for big-endianness todo later...
    return result;
}

short magicnet_read_short(struct magicnet_client *client, struct buffer *store_in_buffer)
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
        magicnet_log("%s the signature was not signed with the public key provided\n", __FUNCTION__);
        return -1;
    }

    // Okay the signature signed the datahash, so as long as the data hash of the buffer network stream equals the same hash
    // as the one in the packet, we are golden. They signed the payload!
    char tmp_buf[SHA256_STRING_LENGTH];
    sha256_data(buffer_ptr(packet->not_sent.tmp_buf), tmp_buf, packet->not_sent.tmp_buf->len);
    if (strncmp(tmp_buf, packet->datahash, sizeof(tmp_buf)) != 0)
    {
        magicnet_log("%s the signature signed the hash but the hash is not the hash of the data provided\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

int magicnet_client_read_vote_for_verifier_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    // Let us read the key we are voting for
    res = magicnet_read_bytes(client, &magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_key, sizeof(struct key), packet->not_sent.tmp_buf);
    if (res < 0)
    {
        magicnet_log("%s could not read key for verifier packet\n", __FUNCTION__);
    }
    return res;
}

int magicnet_read_transaction(struct magicnet_client *client, struct block_transaction *transaction_out, struct buffer *store_in_buffer)
{
    int res = 0;

    res = magicnet_read_bytes(client, transaction_out->hash, sizeof(transaction_out->hash), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read transaction hash \n", __FUNCTION__);
        goto out;
    }

    transaction_out->data.time = magicnet_read_long(client, store_in_buffer);
    if (transaction_out->data.time < 0)
    {
        res = transaction_out->data.time;
        magicnet_log("%s failed to read datatime \n", __FUNCTION__);
        goto out;
    }

    res = magicnet_read_bytes(client, transaction_out->data.program_name, sizeof(transaction_out->data.program_name), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read program name \n", __FUNCTION__);
        goto out;
    }

    transaction_out->data.size = magicnet_read_int(client, store_in_buffer);
    if (transaction_out->data.size < 0)
    {
        res = transaction_out->data.size;
        magicnet_log("%s failed to read integer \n", __FUNCTION__);

        goto out;
    }

    if (transaction_out->data.size > MAGICNET_MAX_SIZE_FOR_TRANSACTION_DATA)
    {
        res = -1;
        magicnet_log("%s the transaction sent to us has too much data for this client version\n", __FUNCTION__);
        goto out;
    }

    transaction_out->data.ptr = malloc(transaction_out->data.size);
    res = magicnet_read_bytes(client, transaction_out->data.ptr, transaction_out->data.size, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read data \n", __FUNCTION__);
        goto out;
    }

    res = magicnet_read_bytes(client, &transaction_out->signature, sizeof(transaction_out->signature), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read signature \n", __FUNCTION__);

        goto out;
    }
    res = magicnet_read_bytes(client, &transaction_out->key, sizeof(transaction_out->key), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read key \n", __FUNCTION__);

        goto out;
    }

    // Let's verify the transaction sent is correct
    // Only check if the transaction is valid if this is not a localhost client
    // localhost clients can send us data that is not signed with our keys because they dont know what our keys are
    // its our responsibility to take it then sign it.
    // If we fail to sign it then we know not to pass it to others. This is all done in the packet processing stage.
    if (!(client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST))
    {
        if (block_transaction_valid(transaction_out) < 0)
        {
            res = -1;
            magicnet_log("%s the transaction sent to us is invalid\n", __FUNCTION__);
            goto out;
        }
    }

out:
    return res;
}

int magicnet_client_read_block_send_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    int total_transactions = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (total_transactions < 0)
    {
        res = total_transactions;
        goto out;
    }

    struct block_transaction_group *transaction_group = block_transaction_group_new();
    magicnet_signed_data(packet_out)->payload.block_send.transaction_group = transaction_group;
    for (int i = 0; i < total_transactions; i++)
    {
        struct block_transaction *transaction = block_transaction_new();
        res = magicnet_read_transaction(client, transaction, packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            block_transaction_free(transaction);
            goto out;
        }

        block_transaction_add(transaction_group, transaction);
    }
    block_transaction_group_hash_create(transaction_group, transaction_group->hash);
    magicnet_signed_data(packet_out)->payload.block_send.blocks = vector_create(sizeof(struct block *));

    int total_blocks = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (total_blocks < 0)
    {
        res = total_blocks;
        goto out;
    }

    for (int i = 0; i < total_blocks; i++)
    {
        char hash[SHA256_STRING_LENGTH];
        char prev_hash[SHA256_STRING_LENGTH];
        char transaction_group_hash[SHA256_STRING_LENGTH];
        struct key key;
        struct signature signature;
        res = magicnet_read_bytes(client, hash, sizeof(hash), packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }
        res = magicnet_read_bytes(client, prev_hash, sizeof(prev_hash), packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }
        res = magicnet_read_bytes(client, transaction_group_hash, sizeof(transaction_group_hash), packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }

        if (memcmp(transaction_group_hash, transaction_group->hash, sizeof(transaction_group_hash)) != 0)
        {
            magicnet_log("%s the transaction group hash does not match the one in the block sent to us\n", __FUNCTION__);
            res = MAGICNET_ERROR_SECURITY_RISK;
            break;
        }

        res = magicnet_read_bytes(client, &key, sizeof(key), packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }

        res = magicnet_read_bytes(client, &signature, sizeof(signature), packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }

        struct block *block = block_create_with_group(hash, prev_hash, block_transaction_group_clone(transaction_group));
        if (!block)
        {
            res = MAGICNET_ERROR_UNKNOWN;
            break;
        }

        block->key = key;
        block->signature = signature;

        res = block_verify(block);
        if (res < 0)
        {
            magicnet_log("%s issue verifying the received block\n", __FUNCTION__);
            block_free(block);
            break;
        }
        // Add the block
        vector_push(magicnet_signed_data(packet_out)->payload.block_send.blocks, &block);
    }
out:
    return res;
}

int magicnet_client_read_tansaction_send_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    magicnet_signed_data(packet_out)->payload.transaction_send.transaction = block_transaction_new();
    res = magicnet_read_transaction(client, magicnet_signed_data(packet_out)->payload.transaction_send.transaction, packet_out->not_sent.tmp_buf);
    return res;
}

int magicnet_client_read_request_block_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = magicnet_read_bytes(client, magicnet_signed_data(packet_out)->payload.request_block.request_hash, sizeof(magicnet_signed_data(packet_out)->payload.request_block.request_hash), packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        magicnet_log("%s failed to read previous hash for request block packet\n", __FUNCTION__);
        goto out;
    }

out:
    return res;
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
        if (res < 0)
        {
            magicnet_log("%s read empty packet failed\n", __FUNCTION__);
        }
        break;
    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_read_user_defined_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s user defined packet failed\n", __FUNCTION__);
        }
        break;

    case MAGICNET_PACKET_TYPE_POLL_PACKETS:
        res = magicnet_client_read_poll_packets_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s poll packets failed", __FUNCTION__);
        }
        break;

    case MAGICNET_PACKET_TYPE_SERVER_SYNC:
        res = magicnet_client_read_server_sync_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s sync packet failed\n", __FUNCTION__);
        }
        break;

    case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        res = magicnet_client_read_verifier_signup_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s read signup packet failed\n", __FUNCTION__);
        }
        break;

    case MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER:
        res = magicnet_client_read_vote_for_verifier_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s read verifier packet failed\n", __FUNCTION__);
        }
        break;

    case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
        res = magicnet_client_read_tansaction_send_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s read transaction send packet failed\n", __FUNCTION__);
        }
        break;

    case MAGICNET_PACKET_TYPE_REQUEST_BLOCK:
        res = magicnet_client_read_request_block_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s failed to read block request packet\n", __FUNCTION__);
        }
        break;
    case MAGICNET_PACKET_TYPE_BLOCK_SEND:
        res = magicnet_client_read_block_send_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s read block send packet failed\n", __FUNCTION__);
        }
        break;
    case MAGICNET_PACKET_TYPE_NOT_FOUND:
        res = magicnet_client_read_not_found_packet(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s read not found packet failed\n", __FUNCTION__);
        }
        break;
    default:
        magicnet_log("%s unexpected packet was provided %i\n", __FUNCTION__, packet_type);
        res = -1;
        break;
    }

    // Has the packet failed to be read?
    if (res < 0)
    {
        goto out;
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

    /**
     * @brief Here unsigned packets provided by a LOCALHOST connection will be signed with our local key
     * this is okay because this is the local machine therefore it is the authority of this server instance
     * to sign all packets
     */
    if (!has_signature)
    {
        assert((client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST));
        // Since we have no signature let us create our own this is allowed since we have confimed
        // that we are localhost and by default localhost packets have no signatures.

        // Let's start by rehashing the data so we have an accurate hash. Just in case they provided us with a NULL hash entry
        // perfectly valid from a localhost client.
        char tmp_buf[SHA256_STRING_LENGTH];
        sha256_data(buffer_ptr(packet_out->not_sent.tmp_buf), tmp_buf, packet_out->not_sent.tmp_buf->len);
        strncpy(packet_out->datahash, tmp_buf, sizeof(packet_out->datahash));

        // Now let us craft a signature
        packet_out->pub_key = *MAGICNET_public_key();
        res = private_sign(packet_out->datahash, sizeof(packet_out->datahash), &packet_out->signature);
        if (res < 0)
        {
            magicnet_log("%s Failed to sign data with signature\n", __FUNCTION__);
            return -1;
        }

        magicnet_log("%s unsigned packet from localhost has now been signed with our signature\n", __FUNCTION__);
        has_signature = true;
    }

    // Now the packet is constructed lets verify its contents if it has been signed.
    res = magicnet_client_verify_packet_was_signed(packet_out);
    if (res < 0)
    {
        magicnet_log("%s packet was signed incorrectly\n", __FUNCTION__);
        return res;
    }

out:
    buffer_free(packet_out->not_sent.tmp_buf);
    packet_out->not_sent.tmp_buf = NULL;

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
        // Packet might not be signed if its not we need to sign it

        int flags = 0;
        struct magicnet_packet *sync_packet = magicnet_signed_data(packet)->payload.sync.packet;
        if (MAGICNET_nulled_signature(&sync_packet->signature) && magicnet_signed_data(sync_packet)->flags & MAGICNET_PACKET_FLAG_MUST_BE_SIGNED)
        {
            // We have been instructed to sign this packet we have to do this for it to work on the network.
            flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
        }
        res = magicnet_client_write_packet(client, magicnet_signed_data(packet)->payload.sync.packet, flags);
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

int magicnet_client_write_packet_vote_for_verifier(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_bytes(client, &magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_key, sizeof(struct key), packet->not_sent.tmp_buf);

    return res;
}

int magicnet_write_transaction(struct magicnet_client *client, struct block_transaction *transaction, struct buffer *store_in_buffer)
{
    int res = 0;
    if (transaction->data.size > MAGICNET_MAX_SIZE_FOR_TRANSACTION_DATA)
    {
        return MAGICNET_ERROR_TOO_LARGE;
    }

    // Let's verify some things before we send this but only if we are not local host.
    // If we are a localhost client its impossible for us to know our keypair
    // so nothing has been signed.
    if (!(client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST))
    {
        res = block_transaction_valid(transaction);
        if (res < 0)
        {
            magicnet_log("%s the transaction to write is invalid\n", __FUNCTION__);
            goto out;
        }
    }
    res = magicnet_write_bytes(client, transaction->hash, sizeof(transaction->hash), store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_long(client, transaction->data.time, store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, transaction->data.program_name, sizeof(transaction->data.program_name), store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_int(client, transaction->data.size, store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, transaction->data.ptr, transaction->data.size, store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, &transaction->signature, sizeof(transaction->signature), store_in_buffer);
    if (res < 0)
    {
        goto out;
    }
    res = magicnet_write_bytes(client, &transaction->key, sizeof(transaction->key), store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_packet_block_send(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct vector *blocks_to_send = magicnet_signed_data(packet)->payload.block_send.blocks;
    struct block_transaction_group *transaction_group = magicnet_signed_data(packet)->payload.block_send.transaction_group;
    res = magicnet_write_int(client, transaction_group->total_transactions, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    for (int i = 0; i < transaction_group->total_transactions; i++)
    {
        res = magicnet_write_transaction(client, transaction_group->transactions[i], packet->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }
    }

    res = magicnet_write_int(client, vector_count(blocks_to_send), packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    vector_set_peek_pointer(blocks_to_send, 0);
    struct block *block = vector_peek_ptr(blocks_to_send);
    while (block)
    {
        res = magicnet_write_bytes(client, block->hash, sizeof(block->hash), packet->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }
        res = magicnet_write_bytes(client, block->prev_hash, sizeof(block->prev_hash), packet->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }

        res = magicnet_write_bytes(client, block->transaction_group->hash, sizeof(block->transaction_group->hash), packet->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }

        res = magicnet_write_bytes(client, &block->key, sizeof(block->key), packet->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }

        res = magicnet_write_bytes(client, &block->signature, sizeof(block->signature), packet->not_sent.tmp_buf);
        if (res < 0)
        {
            break;
        }

        block = vector_peek_ptr(blocks_to_send);
    }
out:
    return res;
}

int magicnet_client_write_packet_transaction_send(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_transaction(client, magicnet_signed_data(packet)->payload.transaction_send.transaction, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_packet_request_block(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_bytes(client, magicnet_signed_data(packet)->payload.request_block.request_hash, sizeof(magicnet_signed_data(packet)->payload.request_block.request_hash), packet->not_sent.tmp_buf);

    return res;
}
int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet, int flags)
{
    int res = 0;
    packet->not_sent.tmp_buf = buffer_create();
    res = magicnet_write_int(client, magicnet_signed_data(packet)->id, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_int(client, magicnet_signed_data(packet)->type, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
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

    case MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER:
        res = magicnet_client_write_packet_vote_for_verifier(client, packet);
        break;
    case MAGICNET_PACKET_TYPE_SERVER_SYNC:
        res = magicnet_client_write_packet_server_poll(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
        res = magicnet_client_write_packet_transaction_send(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_REQUEST_BLOCK:
        res = magicnet_client_write_packet_request_block(client, packet);
        break;
    case MAGICNET_PACKET_TYPE_BLOCK_SEND:
        res = magicnet_client_write_packet_block_send(client, packet);
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
            goto out;
        }

        packet->pub_key = *MAGICNET_public_key();
        res = private_sign(packet->datahash, sizeof(packet->datahash), &packet->signature);
        if (res < 0)
        {
            magicnet_log("%s Failed to sign data with signature\n", __FUNCTION__);
            goto out;
        }
    }

    // Its possible packet was already signed
    bool has_signature = !MAGICNET_nulled_signature(&packet->signature);
    if (!has_signature)
    {
        magicnet_log("%s attempting to send unsigned packet\n", __FUNCTION__);
    }
    res = magicnet_write_int(client, has_signature, NULL);
    if (res < 0)
    {
        goto out;
    }

    // Send the key and signature if their is any
    if (has_signature)
    {
        res = magicnet_write_bytes(client, &packet->pub_key, sizeof(packet->pub_key), NULL);
        if (res < 0)
        {
            goto out;
        }

        res = magicnet_write_bytes(client, &packet->signature, sizeof(packet->signature), NULL);
        if (res < 0)
        {
            goto out;
        }
    }

    // Send the data hash
    res = magicnet_write_bytes(client, packet->datahash, sizeof(packet->datahash), NULL);
    if (res < 0)
    {
        goto out;
    }

out:
    if (res < 0)
    {
        magicnet_log("%s invalid response for write, to avoid a desync of the protocol we have to close the connection\n", __FUNCTION__);
        // Invalid res? We need to kill this client connection as we
        // just broke the protocol, receiver is waiting on data from us we didnt send.
        // Its too late to send more data we will be out of sync
        close(client->sock);
    }
    buffer_free(packet->not_sent.tmp_buf);
    packet->not_sent.tmp_buf = NULL;

    // // We expect to receive a response byte
    // res = magicnet_read_int(client, NULL);
    // // If the respponse is a critical error then we will change it to unknown
    // // since its illegal in our protocol to transmit critical error codes to prevent abuses to terminate connections
    // if (res == MAGICNET_ERROR_CRITICAL_ERROR)
    // {
    //     res = MAGICNET_ERROR_UNKNOWN;
    // }

    return res;
}

bool magicnet_connected(struct magicnet_client *client)
{
    return client && client->flags & MAGICNET_CLIENT_FLAG_CONNECTED;
}

struct magicnet_client *magicnet_tcp_network_connect(struct sockaddr_in addr, int flags, int communication_flags, const char *program_name)
{
    int sockfd;
    // socket create and varification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        return NULL;
    }

    struct timeval timeout;
    timeout.tv_sec = MAGICNET_CLIENT_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        // magicnet_log("Failed to set socket timeout\n");
        return NULL;
    }
    int _true = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &_true, sizeof(int)) < 0)
    {
        magicnet_log("Failed to set socket reusable option\n");
        return NULL;
    }

    // connect the client socket to server socket
    if (connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        return NULL;
    }

    struct magicnet_client *mclient = magicnet_client_new();
    mclient->sock = sockfd;
    mclient->server = NULL;
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    mclient->connection_began = time(NULL);
    mclient->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    mclient->max_bytes_recv_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;

    mclient->communication_flags = communication_flags;

    // Bit crappy, convert to integer then test...
    // CHECK FOR INTEGER HERE
    // if (strcmp(ip_address, "127.0.0.1") == 0)
    // {
    //     mclient->flags |= MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST;
    // }

    if (program_name)
    {
        memcpy(mclient->program_name, program_name, sizeof(mclient->program_name));
    }

    char *ip_address = inet_ntoa(addr.sin_addr);
    strncpy(mclient->peer_info.ip_address, ip_address, sizeof(mclient->peer_info.ip_address));
    if (flags & MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE)
    {
        mclient->flags |= MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE;
    }
    int res = magicnet_client_preform_entry_protocol_write(mclient, program_name, communication_flags);
    if (res < 0)
    {
        magicnet_close(mclient);
        mclient = NULL;
    }
    return mclient;
}
struct magicnet_client *magicnet_tcp_network_connect_for_ip(const char *ip_address, int port, int flags, const char *program_name)
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

    int _true = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &_true, sizeof(int)) < 0)
    {
        magicnet_log("Failed to set socket reusable option\n");
        return NULL;
    }

    // connect the client socket to server socket
    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        return NULL;
    }

    struct magicnet_client *mclient = magicnet_client_new();
    mclient->sock = sockfd;
    mclient->server = NULL;
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    mclient->connection_began = time(NULL);
    mclient->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    mclient->max_bytes_recv_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;

    // Bit crappy, convert to integer then test...
    if (strcmp(ip_address, "127.0.0.1") == 0)
    {
        mclient->flags |= MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST;
    }

    if (program_name)
    {
        memcpy(mclient->program_name, program_name, sizeof(mclient->program_name));
    }

    if (flags & MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE)
    {
        mclient->flags |= MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE;
    }
    int res = magicnet_client_preform_entry_protocol_write(mclient, program_name, 0);
    if (res < 0)
    {
        magicnet_close(mclient);
        mclient = NULL;
    }
    return mclient;
}

struct magicnet_packet *magicnet_recv_next_packet(struct magicnet_client *client, int *res_out)
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

void magicnet_copy_packet_block_send(struct magicnet_packet *packet_out, struct magicnet_packet *packet_in)
{
    struct magicnet_block_send *block_send_packet_in = &magicnet_signed_data(packet_in)->payload.block_send;
    struct magicnet_block_send *block_send_packet_out = &magicnet_signed_data(packet_out)->payload.block_send;
    struct vector *block_vector_out = vector_create(sizeof(struct block *));

    vector_set_peek_pointer(block_send_packet_in->blocks, 0);
    struct block *block = vector_peek_ptr(block_send_packet_in->blocks);
    while (block)
    {
        struct block *cloned_block = block_clone(block);
        vector_push(block_vector_out, &cloned_block);
        block = vector_peek_ptr(block_send_packet_in->blocks);
    }
    block_send_packet_out->transaction_group = block_transaction_group_clone(block_send_packet_in->transaction_group);
    block_send_packet_out->blocks = block_vector_out;
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
        magicnet_signed_data(packet_out)->payload.user_defined.data = calloc(1, magicnet_signed_data(packet_in)->payload.user_defined.data_len);
        memcpy(magicnet_signed_data(packet_out)->payload.user_defined.data, magicnet_signed_data(packet_in)->payload.user_defined.data, magicnet_signed_data(packet_out)->payload.user_defined.data_len);
        break;

    case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
        magicnet_signed_data(packet_out)->payload.transaction_send.transaction = block_transaction_clone(magicnet_signed_data(packet_in)->payload.transaction_send.transaction);
        break;
    case MAGICNET_PACKET_TYPE_BLOCK_SEND:
        magicnet_copy_packet_block_send(packet_out, packet_in);
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

    if (MAGICNET_nulled_signature(&packet->signature))
    {
        magicnet_log("%s you may not add an awaiting packet that has not been signed with a key. We need to know whos sending data on the network. Refused\n", __FUNCTION__);
        return MAGICNET_ERROR_SECURITY_RISK;
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

struct magicnet_packet *magicnet_client_next_packet_to_relay(struct magicnet_client *client)
{
    if (!client->server)
    {
        return NULL;
    }

    struct magicnet_server *server = client->server;

    // First we must check if theirs any packets for relay just for this client. If their isnt then we will choose the global relay
    struct magicnet_packet *packet = &client->packets_for_client.packets[client->packets_for_client.pos_read % MAGICNET_MAX_AWAITING_PACKETS];
    if (!(magicnet_signed_data(packet)->flags & MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE))
    {
        // Yes we have a packet.. lets return
        client->packets_for_client.pos_read++;
        return packet;
    }

    return NULL;
}

void magicnet_client_relay_packet_finished(struct magicnet_client *client, struct magicnet_packet *packet)
{
    magicnet_free_packet_pointers(packet);
    memset(packet, 0, sizeof(struct magicnet_packet));
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
}

int magicnet_relay_packet_to_client(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct magicnet_packet *packet_out = &client->packets_for_client.packets[client->packets_for_client.pos_write % MAGICNET_MAX_AWAITING_PACKETS];
    if (!(magicnet_signed_data(packet_out)->flags & MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE))
    {
        // Okay we looped back around and overflowed.. This is fine but we must discard this packet to make way
        // for the new packet we want to add.

        magicnet_free_packet_pointers(packet_out);
        memset(packet_out, 0, sizeof(struct magicnet_packet));
    }
    magicnet_copy_packet(packet_out, packet);
    magicnet_signed_data(packet_out)->flags &= ~MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
    client->packets_for_client.pos_write++;
    return res;
}

int magicnet_server_add_packet_to_relay(struct magicnet_server *server, struct magicnet_packet *packet)
{
    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        if (magicnet_client_in_use(&server->clients[i]))
        {
            magicnet_relay_packet_to_client(&server->clients[i], packet);
        }
    }

    for (int i = 0; i < MAGICNET_MAX_OUTGOING_CONNECTIONS; i++)
    {
        if (magicnet_client_in_use(&server->outgoing_clients[i]))
        {
            magicnet_relay_packet_to_client(&server->outgoing_clients[i], packet);
        }
    }

    return 0;
}

int magicnet_server_relay_packet_to_client_key(struct magicnet_server *server, struct key *key, struct magicnet_packet *packet)
{
    struct magicnet_client *client = magicnet_server_get_client_with_key(server, key);
    if (!client)
    {
        return -1;
    }

    return magicnet_relay_packet_to_client(client, packet);
}

struct magicnet_client *magicnet_server_get_client_with_key(struct magicnet_server *server, struct key *key)
{
    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        if (magicnet_client_in_use(&server->clients[i]) && key_cmp(&server->clients[i].peer_info.key, key))
        {
            return &server->clients[i];
        }
    }

    for (int i = 0; i < MAGICNET_MAX_OUTGOING_CONNECTIONS; i++)
    {
        if (magicnet_client_in_use(&server->outgoing_clients[i]) && key_cmp(&server->outgoing_clients[i].peer_info.key, key))
        {
            return &server->outgoing_clients[i];
        }
    }

    return NULL;
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
    magicnet_server_read_lock(client->server);
    packet_to_process = magicnet_client_get_next_packet_to_process(client);
    magicnet_server_unlock(client->server);

    if (!packet_to_process)
    {
        packet_to_send = magicnet_packet_new();
        magicnet_signed_data(packet_to_send)->type = MAGICNET_PACKET_TYPE_EMPTY_PACKET;
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
    bool has_packet_to_relay = false;
    // We got to lock this server
    magicnet_server_read_lock(client->server);
    struct magicnet_packet *tmp_packet = magicnet_client_next_packet_to_relay(client);
    if (tmp_packet)
    {
        magicnet_copy_packet(packet_to_relay, tmp_packet);
        has_packet_to_relay = true;
    }
    magicnet_server_unlock(client->server);

    if (has_packet_to_relay)
    {
        // We have a packet lets send to the client
        int flags = 0;
        if (MAGICNET_nulled_signature(&packet_to_relay->signature) &&
            magicnet_signed_data(packet_to_relay)->flags & MAGICNET_PACKET_FLAG_MUST_BE_SIGNED)
        {
            // We got to sign this packet we are about to relay.
            flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
        }
        res = magicnet_client_write_packet(client, packet_to_relay, flags);
        if (res < 0)
        {
            goto out;
        }
    }
    else
    {
        // No packet to relay? Then we need to send back a not found packet
        magicnet_signed_data(packet_to_relay)->type = MAGICNET_PACKET_TYPE_NOT_FOUND;
        // Since this is a packet of our creation it also must be signed.. We aren't relaying
        // anything new here.
        res = magicnet_client_write_packet(client, packet_to_relay, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
        if (res < 0)
        {
            goto out;
        }
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

int magicnet_client_process_transaction_send_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    magicnet_server_lock(client->server);
    // We must sign the transaction in the packet
    res = block_transaction_hash_and_sign(magicnet_signed_data(packet)->payload.transaction_send.transaction);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_packet_resign_on_send(packet);
    if (res < 0)
    {
        goto out;
    }

    // Now we signed the transaction we must resign the packet.
    // All we do with a packet like this is add it to the relay so the server can relay to all other peers.
    res = magicnet_server_add_packet_to_relay(client->server, packet);
    if (res < 0)
    {
        goto out;
    }
    // Oh and we add the transaction to our own queue as well.
    res = magicnet_server_awaiting_transaction_add(client->server, magicnet_signed_data(packet)->payload.transaction_send.transaction);
    if (res < 0)
    {
        goto out;
    }

    magicnet_log("%s Processed our self-signed transaction packet. RELAYING\n", __FUNCTION__);

out:
    magicnet_server_unlock(client->server);
    return res;
}

int magicnet_client_process_request_block_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_log("%s request block packet initiated. Request for block with hash %s\n", __FUNCTION__, magicnet_signed_data(packet)->payload.request_block.request_hash);
    struct magicnet_packet *packet_out = magicnet_packet_new();

    magicnet_signed_data(packet_out)->flags = MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;

    struct block *block = block_load(magicnet_signed_data(packet)->payload.request_block.request_hash);
    if (!block)
    {
        goto out;
    }
    struct vector *block_vec = vector_create(sizeof(struct block *));
    struct block *cloned_block = block_clone(block);
    vector_push(block_vec, &cloned_block);
    magicnet_signed_data(packet_out)->payload.block_send.blocks = block_vec;
    magicnet_signed_data(packet_out)->payload.block_send.transaction_group = block_transaction_group_clone(cloned_block->transaction_group);
    magicnet_signed_data(packet_out)->type = MAGICNET_PACKET_TYPE_BLOCK_SEND;

    magicnet_server_relay_packet_to_client_key(client->server, &packet->pub_key, packet_out);

    block_free(block);
out:
    magicnet_free_packet(packet_out);
    return res;
}
int magicnet_client_process_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    assert(client->server);
    int res = 0;

    if (!(client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST))
    {
        // Non local host clients have access to only one packet type
        switch (magicnet_signed_data(packet)->type)
        {
        case MAGICNET_PACKET_TYPE_SERVER_SYNC:
            res = magicnet_client_process_server_sync_packet(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_EMPTY_PACKET:
            // empty..
            res = 0;
            break;

        default:
            res = -1;
            magicnet_log("%s invalid packet type of %i please note as this is not a localhost client the commands it can access are limited\n", __FUNCTION__, magicnet_signed_data(packet)->type);
        }
    }
    else
    {

        switch (magicnet_signed_data(packet)->type)
        {
        case MAGICNET_PACKET_TYPE_POLL_PACKETS:
            res = magicnet_client_process_packet_poll_packets(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_USER_DEFINED:
            res = magicnet_client_process_user_defined_packet(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_SERVER_SYNC:
            res = magicnet_client_process_server_sync_packet(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
            res = magicnet_client_process_transaction_send_packet(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_EMPTY_PACKET:
            // empty..
            res = 0;
            break;
        default:
            magicnet_log("%s Illegal packet provided\n", __FUNCTION__);
            res = -1;
        }
    }

    // We have seen this packet now.
    magicnet_server_lock(client->server);
    magicnet_server_add_seen_packet(client->server, packet);
    magicnet_server_unlock(client->server);
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

int magicnet_client_entry_protocol_read_known_clients(struct magicnet_client *client)
{

    int res = 0;
    // Lets read all the IPS until we get a NULL.
    size_t total_peers = magicnet_read_int(client, NULL);
    if (total_peers < 0)
    {
        res = total_peers;
        goto out;
    }

    for (int i = 0; i < total_peers; i++)
    {
        struct in_addr s_addr;
        res = magicnet_read_bytes(client, &s_addr, sizeof(s_addr), NULL);
        if (res < 0)
        {
            goto out;
        }

        struct key key;
        res = magicnet_read_bytes(client, &key, sizeof(key), NULL);
        if (res < 0)
        {
            goto out;
        }
    }

out:
    return res;
}

int magicnet_save_peer_info(struct magicnet_peer_information *peer_info)
{
    int res = 0;
    res = magicnet_database_peer_update_or_create(peer_info);
    return res;
}
int magicnet_read_peer_info(struct magicnet_client *client, int *peer_info_state_out)
{
    int res = 0;
    struct buffer *recv_buffer = buffer_create();
    res = magicnet_read_int(client, NULL);
    *peer_info_state_out = res;
    // If theres no peer info provided then leave.
    if (res < 0 || res == MAGICNET_ENTRY_PROTOCOL_NO_PEER_INFO_PROVIDED)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, &client->peer_info.key, sizeof(client->peer_info.key), NULL);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, &client->peer_info.name, sizeof(client->peer_info.name), recv_buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, &client->peer_info.email, sizeof(client->peer_info.email), recv_buffer);
    if (res < 0)
    {
        goto out;
    }

    // Now lets read the hash of the data and the signature. Then we will verify it was sent by the key holder.
    char hash_of_data[SHA256_STRING_LENGTH];
    struct signature signature;
    res = magicnet_read_bytes(client, hash_of_data, sizeof(hash_of_data), NULL);
    if (res < 0)
    {
        goto out;
    }

    char our_hash_of_data[SHA256_STRING_LENGTH];
    sha256_data(buffer_ptr(recv_buffer), our_hash_of_data, buffer_len(recv_buffer));
    if (memcmp(hash_of_data, our_hash_of_data, sizeof(hash_of_data)) != 0)
    {
        magicnet_log("%s the hash provided does not match the hash we calculated\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    res = magicnet_read_bytes(client, &signature, sizeof(signature), NULL);
    if (res < 0)
    {
        goto out;
    }

    res = public_verify(&client->peer_info.key, hash_of_data, sizeof(hash_of_data), &signature);
    if (res < 0)
    {
        magicnet_log("%s the data provided was not signed by the public key given to us.\n", __FUNCTION__);
        goto out;
    }
out:
    if (strlen(client->peer_info.name) == 0)
    {
        // No name provided then this peer is anonymous.
        strncpy(client->peer_info.name, "Anonymous", sizeof(client->peer_info.name));
    }

    if (res < 0)
    {
        magicnet_log("%s issue with entry protocol for client\n", __FUNCTION__);
    }
    else
    {
        magicnet_log("%s peer %s has completed peer exchange\n", __FUNCTION__, client->peer_info.name);
    }
    buffer_free(recv_buffer);
    return res;
}

int magicnet_write_peer_info(struct magicnet_client *client)
{
    int res = 0;
    struct key key = {0};
    char name[MAGICNET_MAX_NAME_SIZE] = {0};
    char email[MAGICNET_MAX_EMAIL_SIZE] = {0};
    struct buffer *send_buf = buffer_create();
    if (!client->server)
    {
        res = magicnet_write_int(client, MAGICNET_ENTRY_PROTOCOL_NO_PEER_INFO_PROVIDED, NULL);
        goto out;
    }

    res = magicnet_write_int(client, MAGICNET_ENTRY_PROTOCOL_PEER_INFO_PROVIDED, NULL);
    if (res < 0)
    {
        goto out;
    }
    memcpy(&key, MAGICNET_public_key(), sizeof(struct key));

    struct magicnet_peer_information peer = {0};
    res = magicnet_database_peer_load_by_key(&key, &peer);
    if (res >= 0)
    {
        strncpy(name, peer.name, sizeof(name));
        strncpy(email, peer.email, sizeof(email));
    }

    if (strlen(name) == 0)
    {
        strncpy(name, "Anonymous", sizeof(name));
    }

    res = magicnet_write_bytes(client, &key, sizeof(struct key), NULL);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, name, sizeof(name), send_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, email, sizeof(email), send_buf);
    if (res < 0)
    {
        goto out;
    }

    char hash_of_data[SHA256_STRING_LENGTH] = {0};
    sha256_data(buffer_ptr(send_buf), hash_of_data, buffer_len(send_buf));

    struct signature signature = {0};
    res = private_sign(hash_of_data, sizeof(hash_of_data), &signature);
    if (res < 0)
    {
        magicnet_log("%s could not sign data with our private key\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_write_bytes(client, hash_of_data, sizeof(hash_of_data), NULL);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, &signature, sizeof(signature), NULL);
    if (res < 0)
    {
        goto out;
    }

out:
    buffer_free(send_buf);
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
        goto out;
    }

    int communication_flags = magicnet_read_int(client, NULL);
    if (communication_flags < 0)
    {
        magicnet_log("%s failed to read  valid comminciation flags\n", __FUNCTION__);
        goto out;
    }

    // We need to find out what they are listening too before we can accept them.
    // What is the program they are subscribing too, lets read it.
    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
    res = magicnet_read_bytes(client, program_name, sizeof(program_name), NULL);
    if (res < 0)
    {
        goto out;
    }

    memcpy(client->program_name, program_name, sizeof(client->program_name));
    res = magicnet_write_int(client, MAGICNET_ENTRY_SIGNATURE, NULL);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, &client->my_ip_address_to_client, sizeof(client->my_ip_address_to_client), NULL);
    if (res < 0)
    {
        magicnet_log("%s failed to read my ip address from the client peer\n", __FUNCTION__);
        goto out;
    }

    const char *client_ip = inet_ntoa(client->client_info.sin_addr);
    char client_ip_buf[MAGICNET_MAX_IP_STRING_SIZE];
    strncpy(client_ip_buf, client_ip, sizeof(client_ip_buf));
    // Lets tell the client what his IP is
    res = magicnet_write_bytes(client, client_ip_buf, sizeof(client_ip_buf), NULL);
    if (res < 0)
    {
        goto out;
    }

    int peer_info_state = -1;
    res = magicnet_read_peer_info(client, &peer_info_state);
    if (res < 0)
    {
        goto out;
    }

    if (peer_info_state == MAGICNET_ENTRY_PROTOCOL_PEER_INFO_PROVIDED)
    {
        res = magicnet_save_peer_info(&client->peer_info);
        if (res < 0)
        {
            goto out;
        }
    }
    res = magicnet_write_peer_info(client);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_client_entry_protocol_read_known_clients(client);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_client_entry_protocol_write_known_clients(client);
    if (res < 0)
    {
        goto out;
    }

    client->communication_flags = communication_flags;
out:
    return res;
}

int magicnet_server_get_all_connected_clients(struct magicnet_server *server, struct vector *vector_out)
{
    int res = 0;
    struct magicnet_connection_exchange_peer_data data;
    for (int i = 0; i < MAGICNET_MAX_OUTGOING_CONNECTIONS; i++)
    {
        struct magicnet_client *client = &server->outgoing_clients[i];
        if (client->flags & MAGICNET_CLIENT_FLAG_CONNECTED)
        {
            bzero(&data, sizeof(data));
            data.sin_addr = client->client_info.sin_addr;
            data.public_key = client->peer_info.key;
            vector_push(vector_out, &data);
        }
    }

    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        struct magicnet_client *client = &server->clients[i];
        if (client->flags & MAGICNET_CLIENT_FLAG_CONNECTED)
        {
            bzero(&data, sizeof(data));
            data.sin_addr = client->client_info.sin_addr;
            data.public_key = client->peer_info.key;
            vector_push(vector_out, &data);
        }
    }

    return res;
}

int magicnet_client_entry_protocol_write_known_clients(struct magicnet_client *client)
{
    int res = 0;
    struct vector *connected_client_vec = NULL;
    if (!client->server)
    {
        // No server instance ? Then nothing to send.
        res = magicnet_write_int(client, 0, NULL);
        if (res < 0)
        {
            goto out;
        }
    }
    else
    {
        magicnet_server_read_lock(client->server);
        connected_client_vec = vector_create(sizeof(struct magicnet_connection_exchange_peer_data));
        magicnet_server_get_all_connected_clients(client->server, connected_client_vec);
        magicnet_server_unlock(client->server);
        res = magicnet_write_int(client, vector_count(connected_client_vec), NULL);
        if (res < 0)
        {
            goto out;
        }
        vector_set_peek_pointer(connected_client_vec, 0);
        struct magicnet_connection_exchange_peer_data *data_to_send = vector_peek(connected_client_vec);
        for (int i = 0; i < vector_count(connected_client_vec); i++)
        {
            res = magicnet_write_bytes(client, &data_to_send->sin_addr, sizeof(data_to_send->sin_addr), NULL);
            if (res < 0)
            {
                break;
            }

            res = magicnet_write_bytes(client, &data_to_send->public_key, sizeof(data_to_send->public_key), NULL);
            if (res < 0)
            {
                break;
            }
            data_to_send = vector_peek(connected_client_vec);
        }
        if (res < 0)
        {
            goto out;
        }
    }

out:
    if (connected_client_vec)
    {
        vector_free(connected_client_vec);
    }
    return res;
}
int magicnet_client_preform_entry_protocol_write(struct magicnet_client *client, const char *program_name, int communication_flags)
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

    res = magicnet_write_int(client, communication_flags, NULL);
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

    const char *client_ip = inet_ntoa(client->client_info.sin_addr);
    char client_ip_buf[MAGICNET_MAX_IP_STRING_SIZE];
    strncpy(client_ip_buf, client_ip, sizeof(client_ip_buf));
    // Lets tell the client what his IP is
    res = magicnet_write_bytes(client, client_ip_buf, sizeof(client_ip_buf), NULL);
    if (res < 0)
    {
        goto out;
    }

    // Lets read what the client says our ip address is.
    res = magicnet_read_bytes(client, &client->my_ip_address_to_client, sizeof(client->my_ip_address_to_client), NULL);
    if (res < 0)
    {
        goto out;
    }

    // Write our client key
    res = magicnet_write_peer_info(client);
    if (res < 0)
    {
        goto out;
    }

    int peer_info_state = -1;
    res = magicnet_read_peer_info(client, &peer_info_state);
    if (res < 0)
    {
        goto out;
    }

    if (peer_info_state == MAGICNET_ENTRY_PROTOCOL_PEER_INFO_PROVIDED)
    {
        res = magicnet_save_peer_info(&client->peer_info);
        if (res < 0)
        {
            goto out;
        }
    }

    // // Okay let us send the ip addresses we are aware of
    res = magicnet_client_entry_protocol_write_known_clients(client);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_client_entry_protocol_read_known_clients(client);
    if (res < 0)
    {
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

bool magicnet_server_verifier_is_signed_up(struct magicnet_server *server, struct key *key)
{
    vector_set_peek_pointer(server->next_block.signed_up_verifiers, 0);
    struct key *key_in_vec = vector_peek_ptr(server->next_block.signed_up_verifiers);
    while (key_in_vec)
    {
        if (key_cmp(key_in_vec, key))
        {
            return true;
        }
        key_in_vec = vector_peek_ptr(server->next_block.signed_up_verifiers);
    }

    return false;
}

int magicnet_server_verifier_signup(struct magicnet_server *server, struct key *pub_key)
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
    struct key *cloned_key = calloc(1, sizeof(struct key));
    memcpy(cloned_key, pub_key, sizeof(struct key));
    vector_push(server->next_block.signed_up_verifiers, &cloned_key);

    magicnet_log("%s new verifier signup %s\n", __FUNCTION__, pub_key->key);
out:
    return res;
}

int magicnet_server_poll_process_verifier_signup_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_log("%s client has asked to signup as a verifier for the next block: %s\n", __FUNCTION__, inet_ntoa(client->client_info.sin_addr));
    magicnet_server_lock(client->server);
    res = magicnet_server_verifier_signup(client->server, &packet->pub_key);
    magicnet_server_add_packet_to_relay(client->server, packet);

    magicnet_server_unlock(client->server);
    return res;
}

int magicnet_server_process_vote_for_verifier_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    struct key *voteing_for_key = &magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_key;
    magicnet_server_lock(client->server);
    int res = magicnet_server_cast_verifier_vote(client->server, &packet->pub_key, voteing_for_key);
    magicnet_server_unlock(client->server);
    if (res < 0)
    {
        magicnet_log("%s Failed to cast vote from key = %s voting for key %s\n", __FUNCTION__, &packet->pub_key.key, voteing_for_key->key);
    }

    magicnet_server_add_packet_to_relay(client->server, packet);
    return res;
}

int magicnet_server_process_block_send_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    bool hash_is_requested = false;
    magicnet_log("%s block send packet discovered\n", __FUNCTION__);
    if (vector_count(magicnet_signed_data(packet)->payload.block_send.blocks) > 1)
    {
        magicnet_log("%s this version of the protocol does not allow multiple blocks to be sent. Blocks ignored\n", __FUNCTION__);
        return 0;
    }

    vector_set_peek_pointer(magicnet_signed_data(packet)->payload.block_send.blocks, 0);
    struct block *block = vector_peek_ptr(magicnet_signed_data(packet)->payload.block_send.blocks);
    while (block)
    {
        hash_is_requested = magicnet_default_downloader_is_hash_queued(block->hash);
        block_save(block);
        magicnet_database_blockchain_update_last_hash(block->blockchain_id, block->hash);
        magicnet_database_blockchain_increment_proven_verified_blocks(block->blockchain_id);

        struct block *previous_block = block_load(block->prev_hash);
        if (!previous_block)
        {
            // No previous block? Then we should initiate a download for all blocks with no chain
            magicnet_chain_downloader_queue_for_block_download(block->prev_hash);
        }
        block_free(previous_block);
        block = vector_peek_ptr(magicnet_signed_data(packet)->payload.block_send.blocks);
    }

    // We don't relay if this was a block we requested.
    if (!hash_is_requested)
    {
        magicnet_server_lock(client->server);
        magicnet_server_add_packet_to_relay(client->server, packet);
        magicnet_server_unlock(client->server);
    }

    return 0;
}

int magicnet_server_process_transaction_send_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_server_lock(client->server);
    // Oh and we add the transaction to our own queue as well.
    res = magicnet_server_awaiting_transaction_add(client->server, magicnet_signed_data(packet)->payload.transaction_send.transaction);
    if (res < 0)
    {
        goto out;
    }

    magicnet_log("%s added new transaction from %s\n", __FUNCTION__, packet->pub_key.key);

    // Relay to others.
    res = magicnet_server_add_packet_to_relay(client->server, packet);
    if (res < 0)
    {
        goto out;
    }

out:
    magicnet_server_unlock(client->server);
    return res;
}
int magicnet_server_poll_process(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_server_read_lock(client->server);
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

    case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        res = magicnet_server_poll_process_verifier_signup_packet(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER:
        res = magicnet_server_process_vote_for_verifier_packet(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_BLOCK_SEND:
        res = magicnet_server_process_block_send_packet(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
        res = magicnet_server_process_transaction_send_packet(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_REQUEST_BLOCK:
        res = magicnet_client_process_request_block_packet(client, packet);
        break;
    };

    magicnet_server_lock(client->server);
    res = magicnet_server_add_seen_packet(client->server, packet);
    magicnet_server_unlock(client->server);

    // Since we processed something lets for the next 10 seconds increase the bandwidth just in case theres more to send
    magicnet_client_set_max_bytes_to_send_per_second(client, MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_WHEN_PROCESSING_PACKETS, 10);
    magicnet_client_set_max_bytes_to_recv_per_second(client, MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_WHEN_PROCESSING_PACKETS, 10);

    return res;
}
int magicnet_server_poll(struct magicnet_client *client)
{
    int res = 0;

    bool should_sleep = false;
    // We also want to send a packet of our own
    int flags = 0;

    struct magicnet_packet *packet_to_send = magicnet_packet_new();
    struct magicnet_packet *packet_to_relay = magicnet_packet_new();
    magicnet_signed_data(packet_to_relay)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    struct magicnet_packet *packet = NULL;
    magicnet_server_read_lock(client->server);
    struct magicnet_packet *tmp_packet = magicnet_client_next_packet_to_relay(client);
    if (tmp_packet)
    {
        magicnet_copy_packet(packet_to_relay, tmp_packet);
    }
    magicnet_server_unlock(client->server);

    if (tmp_packet)
    {
        flags |= MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET;
        magicnet_server_lock(client->server);
        magicnet_client_relay_packet_finished(client, tmp_packet);
        magicnet_server_unlock(client->server);
    }
    if (magicnet_signed_data(packet_to_relay)->type != MAGICNET_PACKET_TYPE_EMPTY_PACKET)
    {
        magicnet_log("non empty packet to send\n");
    }

    magicnet_signed_data(packet_to_send)->type = MAGICNET_PACKET_TYPE_SERVER_SYNC;
    if (flags & MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET)
    {
        magicnet_signed_data(packet_to_send)->payload.sync.flags = flags;
        magicnet_signed_data(packet_to_send)->payload.sync.packet = packet_to_relay;
    }

    res = magicnet_client_write_packet(client, packet_to_send, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        goto out;
    }
    packet = magicnet_recv_next_packet(client, &res);
    if (packet == NULL)
    {
        should_sleep = false;
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

    // We don't really want to over whelm the thread... This would be better in the loop however.
    if (should_sleep)
    {
        //   usleep(2000000);
    }
    return res;
}
void *magicnet_client_thread(void *_client)
{
    int res = 0;
    bool server_shutting_down = false;
    struct magicnet_client *client = _client;

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    if (client->server)
    {
        magicnet_server_lock(client->server);
        magicnet_server_add_thread(client->server, pthread_self());
        magicnet_server_unlock(client->server);
    }

    res = magicnet_client_preform_entry_protocol_read(client);
    if (res < 0)
    {
        // entry protocol failed.. illegal client!
        goto out;
    }

    if (client->server)
    {
        magicnet_server_lock(client->server);
        magicnet_server_recalculate_my_ip(client->server);
        magicnet_server_unlock(client->server);
    }

    while (res != MAGICNET_ERROR_CRITICAL_ERROR && !server_shutting_down)
    {
        res = magicnet_client_manage_next_packet(client);
        if (client->server)
        {
            magicnet_server_lock(client->server);
            server_shutting_down = client->server->shutdown;
            if (server_shutting_down)
            {
                magicnet_log("%s the server is shutting down suspending client\n", __FUNCTION__);
            }
            magicnet_server_unlock(client->server);
        }
    }
out:
    if (client->server)
    {
        magicnet_server_lock(client->server);
        magicnet_close(client);
        magicnet_server_remove_thread(client->server, pthread_self());
        magicnet_server_unlock(client->server);
    }
    else
    {
        magicnet_close(client);
    }
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

int magicnet_server_get_next_ip_to_connect_to(struct magicnet_server *server, char *ip_out)
{

    int res = magicnet_database_peer_get_random_ip(ip_out);
    bool found_ip = false;
    if (res < 0)
    {
        goto out;
    }
    magicnet_server_lock(server);
    // 10 attempts at finding a random ip we havent connected too yet.
    for (int i = 0; i < 10; i++)
    {
        if (!magicnet_server_is_ip_connected(server, ip_out))
        {
            found_ip = true;
            break;
        }

        res = magicnet_database_peer_get_random_ip(ip_out);
        if (res < 0)
        {
            break;
        }
    }
    magicnet_server_unlock(server);

    if (!found_ip)
    {
        res = -1;
    }
out:
    return res;
}

void *magicnet_server_client_thread(void *_client)
{
    struct magicnet_client *client = _client;
    bool shutdown = false;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    magicnet_log("%s new outbound connection created\n", __FUNCTION__);
    magicnet_server_lock(client->server);
    magicnet_server_add_thread(client->server, pthread_self());
    magicnet_server_recalculate_my_ip(client->server);
    magicnet_server_unlock(client->server);

    int res = 0;
    while (res >= 0 && !shutdown)
    {
        // We must ask the server to relay packets to us
        res = magicnet_server_poll(client);
        magicnet_server_read_lock(client->server);
        shutdown = client->server->shutdown;
        magicnet_server_unlock(client->server);
    }
    magicnet_server_lock(client->server);
    magicnet_close(client);
    magicnet_server_remove_thread(client->server, pthread_self());
    magicnet_server_unlock(client->server);
}

void magicnet_server_attempt_new_connections(struct magicnet_server *server)
{
    char ip[MAGICNET_MAX_IP_STRING_SIZE];
    int res = magicnet_server_get_next_ip_to_connect_to(server, ip);
    if (res < 0)
    {
        return;
    }

    struct magicnet_client *client = magicnet_tcp_network_connect_for_ip_for_server(server, ip, MAGICNET_SERVER_PORT, MAGICNET_LISTEN_ALL_PROGRAM);
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

void magicnet_server_client_signup_as_verifier(struct magicnet_server *server)
{

    // Lets create verifier signups for the block
    // peers can ask to be elected to make the next block

    struct magicnet_packet *packet = magicnet_packet_new();
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP;
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;

    // Let's add this packet to the server relay so all connected hosts will find it and relay it
    // to millions
    int res = magicnet_server_add_packet_to_relay(server, packet);
    if (res < 0)
    {
        magicnet_error("%s failed to signup as a verifier.. Issue with relaying the packet\n", __FUNCTION__);
    }

    magicnet_free_packet(packet);
}

struct key *magicnet_server_get_random_block_verifier(struct magicnet_server *server)
{
    if (vector_count(server->next_block.signed_up_verifiers) == 0)
    {
        return NULL;
    }

    int random_key_index = rand() % vector_count(server->next_block.signed_up_verifiers);
    return vector_peek_ptr_at(server->next_block.signed_up_verifiers, random_key_index);
}

void magicnet_server_client_vote_for_verifier(struct magicnet_server *server)
{
    struct key *verifier_key = magicnet_server_get_random_block_verifier(server);
    if (!verifier_key)
    {
        magicnet_error("%s we went to cast a vote for a verifier but their isnt any verifiers available\n", __FUNCTION__);
        return;
    }

    int res = magicnet_server_cast_verifier_vote(server, MAGICNET_public_key(), verifier_key);
    if (res < 0)
    {
        magicnet_error("%s we failed to cast a vote on our local client\n", __FUNCTION__);
        return;
    }

    // Let us create a new vote packet to relay.
    struct magicnet_packet *packet = magicnet_packet_new();
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER;
    magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_key = *verifier_key;
    magicnet_server_add_packet_to_relay(server, packet);

    magicnet_free_packet(packet);
}

/**
 * @brief Resets the block sequence, clearing all signed up verifiers and votes for whome should make the next block
 * steps are all reset as well.
 *
 * @param server
 */
void magicnet_server_reset_block_sequence(struct magicnet_server *server)
{
    vector_set_peek_pointer(server->next_block.verifier_votes.votes, 0);
    struct magicnet_key_vote *key_vote = vector_peek_ptr(server->next_block.verifier_votes.votes);
    while (key_vote)
    {
        free(key_vote);
        key_vote = vector_peek_ptr(server->next_block.verifier_votes.votes);
    }

    vector_clear(server->next_block.verifier_votes.votes);

    vector_set_peek_pointer(server->next_block.verifier_votes.vote_counts, 0);
    struct magicnet_vote_count *vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    while (vote_count)
    {
        free(vote_count);
        vote_count = vector_peek_ptr(server->next_block.verifier_votes.votes);
    }

    vector_clear(server->next_block.verifier_votes.vote_counts);

    vector_set_peek_pointer(server->next_block.signed_up_verifiers, 0);
    struct key *verifier_key = vector_peek_ptr(server->next_block.signed_up_verifiers);
    while (verifier_key)
    {
        free(verifier_key);
        verifier_key = vector_peek_ptr(server->next_block.signed_up_verifiers);
    }

    vector_clear(server->next_block.signed_up_verifiers);

    vector_set_peek_pointer(server->next_block.block_transactions, 0);
    struct block_transaction *block_transaction = vector_peek_ptr(server->next_block.block_transactions);
    while (block_transaction)
    {
        block_transaction_free(block_transaction);
        block_transaction = vector_peek_ptr(server->next_block.block_transactions);
    }
    vector_clear(server->next_block.block_transactions);

    server->next_block.step = BLOCK_CREATION_SEQUENCE_SIGNUP_VERIFIERS;
}

int magicnet_server_create_block(struct magicnet_server *server, const char *prev_hash, struct block_transaction_group *transaction_group, struct block **block_out)
{

    struct block *block = block_create(transaction_group, prev_hash);
    block->key = *MAGICNET_public_key();

    if (block_hash_sign_verify(block) < 0)
    {
        magicnet_error("%s could not hash sign and verify the block\n", __FUNCTION__);
        block_free(block);
        return -1;
    }

    if (block_verify(block) < 0)
    {
        magicnet_error("%s failed to verify the block we created. We did something wrong\n");
        return -1;
    }

    // Save the block
    block_save(block);
    magicnet_database_blockchain_update_last_hash(block->blockchain_id, block->hash);
    magicnet_database_blockchain_increment_proven_verified_blocks(block->blockchain_id);

    *block_out = block;
    return 0;
}

void magicnet_server_create_and_send_block(struct magicnet_server *server)
{
    int res = 0;
    magicnet_important("%s block creation sequence for this peer. Peer will make block\n", __FUNCTION__);

    struct vector *blockchains = vector_create(sizeof(struct blockchain *));
    struct vector *block_vector = vector_create(sizeof(struct block *));
    struct block_transaction_group *transaction_group = block_transaction_group_new();
    struct magicnet_packet *packet = magicnet_packet_new();
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_BLOCK_SEND;
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet)->payload.block_send.blocks = block_vector;
    magicnet_signed_data(packet)->payload.block_send.transaction_group = transaction_group;

    // Let's loop through all of the block transactions that we are aware of and add them to the block
    vector_set_peek_pointer(server->next_block.block_transactions, 0);
    struct block_transaction *transaction = vector_peek_ptr(server->next_block.block_transactions);
    while (transaction)
    {
        block_transaction_add(transaction_group, block_transaction_clone(transaction));
        transaction = vector_peek_ptr(server->next_block.block_transactions);
    }

    struct blockchain *active_chain = NULL;
    res = magicnet_database_blockchain_get_active(&active_chain);
    if (res < 0)
    {
        magicnet_log("%s issue getting active blockchain\n", __FUNCTION__);
    }
    struct block *block = NULL;
    if (!active_chain)
    {
        res = magicnet_server_create_block(server, NULL, transaction_group, &block);
        if (res >= 0)
        {
            vector_push(block_vector, &block);
        }
    }
    else
    {
        res = magicnet_server_create_block(server, active_chain->last_hash, transaction_group, &block);
        if (res >= 0)
        {
            vector_push(block_vector, &block);
        }
    }
    magicnet_server_add_packet_to_relay(server, packet);

out:
    magicnet_free_packet(packet);
}

/**
 * @brief Block creation is always happening every second, there is a special block sequence where certain steps
 * need to be followed over a period of a few minutes. The total seconds to make a block is split into four
 * operations, each will run within each quarter of the total seconds to make a block
 *
 * First quarter: Verifiers are signed up and received
 * Second quarter: Everybody casts a random vote for the verifier they want to make the next block
 * Third quarter: We wait to receive the signed block
 * Fourth quarter: We reset all block rules, clear all verifiers and votes ready for the next block.
 *
 * Then the process repeats forever.
 * @param server
 */
void magicnet_server_block_creation_sequence(struct magicnet_server *server)
{
    // Lets say we create a block every 256 seconds
    // the first quarter of that time we will be signing up as a verifier and receving new verifiers
    // the second quarter we will be casting votes
    // third quarter we wait to receive the block
    // final quarter we reset the block creation rules, clearing all the verifiers and votes wether
    // we receive a block or not this will happen
    time_t one_quarter_seconds = MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS / 4;
    time_t block_time_first_quarter_start = 0;
    time_t block_time_second_quarter_start = one_quarter_seconds * 1;
    time_t block_time_third_quarter_start = one_quarter_seconds * 2;
    time_t block_time_fourth_quarter_start = one_quarter_seconds * 3;
    time_t block_cycle_end = one_quarter_seconds * 4;

    // This gives us what second into the sequence we are I.e 15 seconds into the block sequence
    // it cannot be greater than the MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS
    time_t current_block_sequence_time = time(NULL) % MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS;

    magicnet_server_lock(server);

    // First quarter, signup as a verifier. (Note we check that the step is correct for clients that came online too late.. or did not complete a vital step on time)
    int step = server->next_block.step;
    if (current_block_sequence_time >= block_time_first_quarter_start && current_block_sequence_time < block_time_second_quarter_start && step == BLOCK_CREATION_SEQUENCE_SIGNUP_VERIFIERS)
    {
        // Alright lets deal with this
        magicnet_server_client_signup_as_verifier(server);
        server->next_block.step = BLOCK_CREATION_SEQUENCE_CAST_VOTES;
    }
    else if (current_block_sequence_time >= block_time_second_quarter_start && current_block_sequence_time < block_time_third_quarter_start && step == BLOCK_CREATION_SEQUENCE_CAST_VOTES)
    {
        magicnet_important("%s second quarter in the block sequence, lets create a random vote\n", __FUNCTION__);
        magicnet_server_client_vote_for_verifier(server);
        server->next_block.step = BLOCK_CREATION_SEQUENCE_AWAIT_NEW_BLOCK;
    }
    else if (current_block_sequence_time >= block_time_third_quarter_start && current_block_sequence_time < block_time_fourth_quarter_start && step == BLOCK_CREATION_SEQUENCE_AWAIT_NEW_BLOCK)
    {
        // We must select a verifier who won the vote.
        struct key *key_who_won = magicnet_server_verifier_who_won(server);
        if (!key_who_won)
        {
            magicnet_important("%s no verifier key won the vote.\n", __FUNCTION__);
        }
        else
        {
            magicnet_important("%s awaiting for new block from voted verifier: %s \n", __FUNCTION__, key_who_won->key);
        }
        if (key_cmp(key_who_won, MAGICNET_public_key()))
        {
            // What do you know we won the vote! Lets create this block
            magicnet_server_create_and_send_block(server);
        }
        server->next_block.step = BLOCK_CREATION_SEQUENCE_CLEAR_EXISTING_SEQUENCE;
    }
    else if (current_block_sequence_time >= block_time_fourth_quarter_start && current_block_sequence_time < block_cycle_end)
    {
        // We dont check for the step in this IF statement, just in case a peer doesnt keep up
        // we dont want them stuck forever out of being able to make block sequences, therefore we allow this one to always run
        // yes it will run every few seconds for ages but its fine as then we can reject people
        // sending verifier packets when they shouldnt be since they will be discarded.
        magicnet_server_reset_block_sequence(server);
    }

    magicnet_server_unlock(server);
}
bool magicnet_server_alive_for_at_least_one_block_cycle(struct magicnet_server *server)
{
    return time(NULL) >= server->first_block_cycle;
}

int magicnet_server_process(struct magicnet_server *server)
{
    int res = 0;
    if (magicnet_server_should_make_new_connections(server))
    {
        magicnet_server_attempt_new_connections(server);
        server->last_new_connection_attempt = time(NULL);
    }

    // We can only work with a block creation sequence if we have existed longer than one sequence
    // this is to prevent abuse such as clients starting mid way through a sequence, voting with very little informaton
    // and so on.
    if (magicnet_server_alive_for_at_least_one_block_cycle(server))
    {
        magicnet_server_block_creation_sequence(server);
    }

    return res;
}
void *magicnet_server_thread(void *_server)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    bool server_shutting_down = false;
    struct magicnet_server *server = _server;
    magicnet_server_lock(server);
    magicnet_server_add_thread(server, pthread_self());
    magicnet_server_unlock(server);

    while (!server_shutting_down)
    {
        magicnet_server_process(server);
        magicnet_server_read_lock(server);
        server_shutting_down = server->shutdown;
        if (server_shutting_down)
        {
            magicnet_log("%s suspending server thread\n", __FUNCTION__);
        }
        magicnet_server_unlock(server);
        sleep(5);
    }

    magicnet_server_lock(server);
    magicnet_server_remove_thread(server, pthread_self());
    magicnet_server_unlock(server);
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