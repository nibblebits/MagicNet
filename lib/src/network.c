#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
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
#include "magicnet/signaling.h"
#include "magicnet/database.h"
#include "magicnet/config.h"
#include "magicnet/magicnet.h"
#include "magicnet/nthread.h"
#include "magicnet/log.h"
#include "magicnet/buffer.h"
#include "key.h"
#include "misc.h"

int magicnet_init_client(struct magicnet_client *client, struct magicnet_server *server, int connfd, struct sockaddr_in *addr_in);
int magicnet_client_preform_entry_protocol_read(struct magicnet_client *client, struct magicnet_packet *packet);

// not the same as free, the memory of client isnt freed.
// only its internals.
void magicnet_client_destruct(struct magicnet_client *client);

int magicnet_send_pong(struct magicnet_client *client);
void magicnet_close(struct magicnet_client *client);
int magicnet_client_process_user_defined_packet(struct magicnet_client *client, struct magicnet_packet *packet);
int magicnet_server_poll_process(struct magicnet_client *client, struct magicnet_packet *packet);
void magicnet_server_reset_block_sequence(struct magicnet_server *server);
int magicnet_client_process_block_super_download_request_packet(struct magicnet_client *client, struct magicnet_packet *packet);
int magicnet_server_awaiting_transaction_add(struct magicnet_server *server, struct block_transaction *transaction);
void magicnet_server_set_created_block(struct magicnet_server *server, struct block *block);
void *magicnet_client_thread(void *_client);
void magicnet_server_update_our_transaction_states(struct magicnet_server *server, struct block *block);
int magicnet_server_push_event(struct magicnet_server *server, struct magicnet_event *event);
int magicnet_client_write_council_certificate(struct magicnet_client *client, struct magicnet_council_certificate *certificate, struct buffer *write_buf);
int magicnet_client_read_council_certificate(struct magicnet_client *client, struct magicnet_council_certificate *certificate_out, struct buffer *write_buf);
int magicnet_client_unread_bytes_count(struct magicnet_client *client);
int magicnet_client_insert_bytes(struct magicnet_client *client, void *ptr_in, size_t amount, size_t offset_index);

// WE WILL RULE OUT THE MULTITHREADING ISSUE WITH A TEMPORARY MUTEX.
pthread_mutex_t tmp_mutex;


size_t magicnet_client_unflushed_bytes(struct magicnet_client *client);


// flags in future but this is fool proof for debugging.
bool magicnet_packet_hashed(struct magicnet_packet* packet)
{
    char tmp_hash[SHA256_STRING_LENGTH] = {0};
    return memcmp(packet->datahash, tmp_hash, sizeof(tmp_hash)) != 0;
}

void magicnet_packet_hash(struct magicnet_packet* packet_out)
{
    char tmp_buf[SHA256_STRING_LENGTH];
    if (!packet_out->not_sent.tmp_buf)
    {
        magicnet_log("%s BUG with hashing null sending buffer\n", __FUNCTION__);
        return;
    }

    sha256_data(buffer_ptr(packet_out->not_sent.tmp_buf), tmp_buf, packet_out->not_sent.tmp_buf->len);
    strncpy(packet_out->datahash, tmp_buf, sizeof(packet_out->datahash));
}
struct buffer *magicnet_client_unflushed_bytes_buffer(struct magicnet_client *client)
{
    return client->unflushed_data;
}

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

bool magicnet_packet_ready_for_processing(struct magicnet_packet *packet)
{
    return (magicnet_signed_data(packet)->flags & MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING);
}

void magicnet_packet_make_new_id(struct magicnet_packet *packet)
{
    // change this to secure random terrible...
    // TODO
    magicnet_signed_data(packet)->id = rand() % 999999999;
}

struct magicnet_packet *magicnet_packet_new()
{
    struct magicnet_packet *packet = calloc(1, sizeof(struct magicnet_packet));
    magicnet_packet_make_new_id(packet);
    return packet;
}

struct magicnet_packet *magicnet_packet_new_init(int packet_type)
{
    struct magicnet_packet *packet = magicnet_packet_new();
    if (!packet)
        return NULL;

    magicnet_signed_data(packet)->type = packet_type;
    return packet;
}

int magicnet_client_packet_strip_private_flags(const struct magicnet_packet *packet)
{
    int flags = packet->signed_data.flags;
    return flags & ~MAGICNET_PACKET_PRIVATE_FLAGS;
}

bool magicnet_client_packet_flags_are_private(int flags)
{
    return flags & MAGICNET_PACKET_PRIVATE_FLAGS;
}

bool magicnet_client_packet_has_private_flags(struct magicnet_packet *packet)
{
    return magicnet_client_packet_flags_are_private(magicnet_signed_data(packet)->flags);
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

void magicnet_client_destruct(struct magicnet_client *client)
{
    client->flags &= ~MAGICNET_CLIENT_FLAG_CONNECTED;

    memset(&client->packets_for_client, 0, sizeof(client->packets_for_client));
    ;

    if (client->events)
    {
        magicnet_events_vector_free(client->events);
        client->events = NULL;
    }

    // If we closed the connection of a client who was last to send the block then we must set it to NULL
    // on the server, since the client is no longer accessible.
    if (client->server && client->server->last_client_to_send_block == client)
    {
        client->server->last_client_to_send_block = NULL;
    }

    if (client->unflushed_data)
    {
        buffer_free(client->unflushed_data);
        client->unflushed_data = NULL;
    }
}

struct magicnet_client *magicnet_client_new()
{
    struct magicnet_client *client = calloc(1, sizeof(struct magicnet_client));
    if (!client)
    {
        return NULL;
    }

    magicnet_init_client(client, NULL, 0, NULL);
    return client;
}
void magicnet_client_free(struct magicnet_client *client)
{
    if (client->unflushed_data)
    {
        magicnet_client_destruct(client);
        client->unflushed_data = NULL;
    }
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
    // TODO free the waiting transactions

    // Free all the signed up verifiers
    vector_set_peek_pointer(server->next_block.signed_up_verifiers, 0);
    struct magicnet_council_certificate *council_cert = vector_peek_ptr(server->next_block.signed_up_verifiers);
    while (council_cert)
    {
        magicnet_council_certificate_free(council_cert);
        council_cert = vector_peek(server->next_block.signed_up_verifiers);
    }

    // Free the vector
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
        bool different_ip = strncmp(server->our_ip, dominant_ip, sizeof(server->our_ip)) != 0;
        strncpy(server->our_ip, dominant_ip, sizeof(server->our_ip));
        if (different_ip)
        {
            magicnet_log("%s our ip address has been detected as %s\n", __FUNCTION__, dominant_ip);
        }
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

    server->next_block.verifier_votes.votes = vector_create(sizeof(struct magicnet_certificate_vote *));
    server->next_block.verifier_votes.vote_counts = vector_create(sizeof(struct magicnet_vote_count *));
    server->next_block.signed_up_verifiers = vector_create(sizeof(struct magicnet_council_certificate **));
    server->next_block.block_transactions = vector_create(sizeof(struct block_transaction *));
    server->our_waiting_transactions = vector_create(sizeof(struct self_block_transaction *));
    server->server_started = time(NULL);
    server->first_block_cycle = server->server_started + (MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS - (server->server_started % MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS));
    server->thread_ids = vector_create(sizeof(pthread_t));

    return server;
}

bool magicnet_server_has_seen_packet_with_id(struct magicnet_server *server, int packet_id)
{
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        if (server->seen_packets.packet_ids[i] == packet_id)
            return true;
    }

    return false;
}

bool magicnet_server_has_seen_packet(struct magicnet_server *server, struct magicnet_packet *packet)
{
    return magicnet_server_has_seen_packet_with_id(server, magicnet_signed_data(packet)->id);
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

size_t magicnet_client_seconds_since_last_contact(struct magicnet_client *client)
{
    return time(NULL) - client->last_packet_received;
}

/**
 * Returns true if we haven't received any data from this client in a while
 */
bool magicnet_client_inactive(struct magicnet_client *client)
{
    return magicnet_client_seconds_since_last_contact(client) > MAGICNET_CLIENT_TIMEOUT_SECONDS;
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

/**
 * This function checks if the block transaction is already added to the awaiting transactions
 */
bool magicnet_server_awaiting_transaction_exists(struct magicnet_server *server, struct block_transaction *transaction)
{
    vector_set_peek_pointer(server->our_waiting_transactions, 0);
    struct self_block_transaction *current = vector_peek_ptr(server->our_waiting_transactions);
    while (current)
    {
        if (strncmp(current->transaction->hash, transaction->hash, sizeof(current->transaction->hash)) == 0)
        {
            return true;
        }
        current = vector_peek_ptr(server->our_waiting_transactions);
    }

    return false;
}

/**
 * This function adds an awaiting transaction to the server
 */
int magicnet_server_awaiting_transaction_add(struct magicnet_server *server, struct block_transaction *transaction)
{
    int res = 0;
    // Check if the transaction already exists
    if (magicnet_server_awaiting_transaction_exists(server, transaction))
    {
        return 0;
    }

    // Make sure the transaction is not signed already
    if (block_transaction_is_signed(transaction))
    {
        magicnet_log("%s Transaction is already signed, cannot add to awaiting transactions. This queue is only for transactions that should be signed and sent to the network\n", __FUNCTION__);
        return MAGICNET_ERROR_SECURITY_RISK;
    }

    // Create a self transaction
    struct self_block_transaction *self_transaction = block_self_transaction_new(transaction);
    vector_push(server->our_waiting_transactions, &self_transaction);

    // Write to log that its been added
    magicnet_log("%s Added transaction to awaiting transactions: %s  (The transaction will be processed then eventually signed and relayed to the network)\n", __FUNCTION__, transaction->hash);
    return res;
}

struct self_block_transaction *magicnet_server_awaiting_transaction_find(struct magicnet_server *server, struct block_transaction *transaction)
{
    struct self_block_transaction *self_transaction = NULL;
    vector_set_peek_pointer(server->our_waiting_transactions, 0);
    struct self_block_transaction *current_trans = vector_peek_ptr(server->our_waiting_transactions);
    while (current_trans)
    {
        if (memcmp(current_trans->transaction->hash, transaction->hash, sizeof(current_trans->transaction->hash)) == 0)
        {
            // Yea we found this good
            self_transaction = current_trans;
            break;
        }
        current_trans = vector_peek_ptr(server->our_waiting_transactions);
    }
    return self_transaction;
}

int magicnet_server_awaiting_transaction_update_state(struct magicnet_server *server, struct self_block_transaction *transaction, int state, const char *message)
{
    int res = 0;

    transaction->state = state;
    strncpy(transaction->status_message, message, sizeof(transaction->status_message));
    return res;
}

bool magicnet_server_next_block_transaction_exists(struct magicnet_server *server, struct block_transaction *transaction)
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

int magicnet_server_next_block_transaction_add(struct magicnet_server *server, struct block_transaction *transaction)
{
    int res = 0;
    if (vector_count(server->next_block.block_transactions) > MAGICNET_MAX_TOTAL_TRANSACTIONS_IN_BLOCK)
    {
        res = MAGICNET_ERROR_QUEUE_FULL;
        goto out;
    }

    // Security precaution we need to make sure any transaction added is valid..
    // I.e we cant allow transactions where someone is sending someone millions that they dont have..
    if (block_transaction_valid(transaction) < 0)
    {
        res = MAGICNET_ERROR_SECURITY_RISK;
        magicnet_log("%s the transaction is invalid so wont be added \n", __FUNCTION__);
        goto out;
    }

    struct blockchain *active_chain = magicnet_blockchain_get_active();
    if (!active_chain)
    {
        magicnet_log("%s issue getting active blockchain, we will not be able to add transactions in this case. We may have a working chain later on..\n", __FUNCTION__);
        res = MAGICNET_ERROR_INCOMPATIBLE;
        goto out;
    }

    // Let's just check the transactions previous hash is equal to the last block hash on the active chain
    // Since we only want to add transactions that are on the active blockchain.
    if (magicnet_server_next_block_transaction_exists(server, transaction))
    {
        res = MAGICNET_ERROR_ALREADY_EXISTANT;
        magicnet_log("%s already existant, possibly a loop back via localhost might not have to worry\n", __FUNCTION__);
        goto out;
    }

    // Let us clone the transaction because we aren't responsible for the memory of the one passed to us.
    // the clone will be deleted when the block sequence completes
    struct block_transaction *cloned_transaction = block_transaction_clone(transaction);
    vector_push(server->next_block.block_transactions, &cloned_transaction);
    magicnet_log("%s added to transaction queue\n", __FUNCTION__);
out:
    return res;
}

bool magicnet_server_has_voted(struct magicnet_server *server, struct magicnet_council_certificate *voting_cert)
{
    vector_set_peek_pointer(server->next_block.verifier_votes.votes, 0);
    struct magicnet_certificate_vote *key_vote = vector_peek_ptr(server->next_block.verifier_votes.votes);
    while (key_vote)
    {
        if (memcmp(key_vote->vote_from_cert->hash, voting_cert->hash, sizeof(key_vote->vote_from_cert->hash)) == 0)
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
 * @param vector_of_votes
 * @return struct magicnet_vote_count*
 */
struct magicnet_vote_count *magicnet_verifier_tie_breaker(struct vector *vector_of_votes)
{
    if (vector_empty(vector_of_votes))
    {
        return NULL;
    }

    if (vector_count(vector_of_votes) == 1)
    {
        return vector_back_ptr(vector_of_votes);
    }

    /**
     * The algorithm will work by taking the first 8 bytes of each key, which ever key has the largest first 8 bytes converted to a long
     * will win and the tie will be broken.
     */

    struct magicnet_vote_count *vote_count_winner = NULL;
    vector_set_peek_pointer(vector_of_votes, 0);
    struct magicnet_vote_count *vote_count = vector_peek_ptr(vector_of_votes);
    while (vote_count)
    {
        if (vote_count_winner)
        {
            if (hash_number(vote_count->vote_for_cert_hash) == hash_number(vote_count_winner->vote_for_cert_hash))
            {
                // We can't break this tie what incredibly circumstances..
                return NULL;
            }
            else if (hash_number(vote_count->vote_for_cert_hash) > hash_number(vote_count_winner->vote_for_cert_hash))
            {
                vote_count_winner = vote_count;
            }
        }
        if (!vote_count_winner)
        {
            vote_count_winner = vote_count;
        }
        vote_count = vector_peek_ptr(vector_of_votes);
    }

    return vote_count_winner;
}
/**
 * @brief All peers vote on who should make the next block, this function returns the current winner whome should
 * make the next block. Only call this at the right time because it takes time for votes to sync around the network.
 *
 * @param server
 * @return struct magicnet_vote_count*
 */
struct magicnet_vote_count *magicnet_server_verifier_who_won(struct magicnet_server *server)
{
    struct magicnet_vote_count *winning_vote_count = NULL;
    struct magicnet_vote_count *winning_cert_vote_count = NULL;
    vector_set_peek_pointer(server->next_block.verifier_votes.vote_counts, 0);
    struct magicnet_vote_count *vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    struct vector *tied_voters = vector_create(sizeof(struct magicnet_vote_count *));
    while (vote_count)
    {

        if (winning_cert_vote_count)
        {
            if (winning_cert_vote_count->voters == vote_count->voters)
            {
                vector_push(tied_voters, &winning_cert_vote_count);
                vector_push(tied_voters, &vote_count);
            }

            if (winning_cert_vote_count->voters < vote_count->voters)
            {
                winning_cert_vote_count = vote_count;
            }
        }

        if (!winning_cert_vote_count)
        {
            winning_cert_vote_count = vote_count;
        }

        vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    }

    if (winning_cert_vote_count)
    {
        winning_vote_count = winning_cert_vote_count;
    }

    // Let us see if their is a tie with the winning key
    bool was_tie = false;
    vector_set_peek_pointer(tied_voters, 0);
    struct magicnet_vote_count *tied_vote_count = vector_peek_ptr(tied_voters);
    while (tied_vote_count)
    {
        // If we have a tied certificate with the winning certificate then their can be no winner. This would allow the network to fork and divide.
        // we cant allow that where it can be stopped it will.
        if (memcmp(winning_vote_count->vote_for_cert_hash, tied_vote_count->vote_for_cert_hash, sizeof(winning_vote_count->vote_for_cert_hash)) == 0)
        {
            was_tie = true;
            break;
        }

        tied_vote_count = vector_peek_ptr(tied_voters);
    }

    if (was_tie)
    {
        // Lets see if we can break the tie
        winning_vote_count = magicnet_verifier_tie_breaker(tied_voters);
    }

    vector_free(tied_voters);
    return winning_vote_count;
}

struct magicnet_vote_count *magicnet_cert_vote_count_get(struct magicnet_server *server, const char *cert_hash)
{
    vector_set_peek_pointer(server->next_block.verifier_votes.vote_counts, 0);
    struct magicnet_vote_count *vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    while (vote_count)
    {
        if (memcmp(vote_count->vote_for_cert_hash, cert_hash, sizeof(vote_count->vote_for_cert_hash)) == 0)
        {
            return vote_count;
        }

        vote_count = vector_peek_ptr(server->next_block.verifier_votes.vote_counts);
    }

    return NULL;
}
void magicnet_vote_count_create_or_increment(struct magicnet_server *server, const char *voting_for_cert_hash)
{
    struct magicnet_vote_count *vote_count = magicnet_cert_vote_count_get(server, voting_for_cert_hash);
    if (!vote_count)
    {
        vote_count = calloc(1, sizeof(struct magicnet_vote_count));
        memcpy(vote_count->vote_for_cert_hash, voting_for_cert_hash, sizeof(vote_count->vote_for_cert_hash));
        vote_count->voters = 0;
        vector_push(server->next_block.verifier_votes.vote_counts, &vote_count);
    }
    vote_count->voters++;
}
int magicnet_server_cast_verifier_vote(struct magicnet_server *server, struct magicnet_council_certificate *voting_cert, const char *vote_for_cert_hash)
{
    if (magicnet_server_has_voted(server, voting_cert))
    {
        // Cheeky trying to cast a vote twice! We dont allow change of votes all future votes REJECTED!
        return MAGICNET_ERROR_ALREADY_EXISTANT;
    }

    struct magicnet_certificate_vote *cert_vote = calloc(1, sizeof(struct magicnet_certificate_vote));
    cert_vote->vote_from_cert = magicnet_council_certificate_clone(voting_cert);
    memcpy(cert_vote->vote_for_cert_hash, vote_for_cert_hash, sizeof(cert_vote->vote_for_cert_hash));
    vector_push(server->next_block.verifier_votes.votes, &cert_vote);

    magicnet_vote_count_create_or_increment(server, vote_for_cert_hash);

    magicnet_log("%s new verifier vote. Voter cert(%s) votes for certificate (%s) to make the next block\n", __FUNCTION__, voting_cert->hash, vote_for_cert_hash);

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

void magicnet_client_lock(struct magicnet_client *client)
{
    pthread_mutex_lock(&client->mutex);
}

void magicnet_client_unlock(struct magicnet_client *client)
{
    pthread_mutex_unlock(&client->mutex);
}

int magicnet_init_client(struct magicnet_client *client, struct magicnet_server *server, int connfd, struct sockaddr_in *addr_in)
{
    int res = 0;
    memset(client, 0, sizeof(struct magicnet_client));
    client->sock = connfd;
    client->server = server;
    client->flags |= MAGICNET_CLIENT_FLAG_CONNECTED;
    client->connection_began = time(NULL);
    client->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    client->max_bytes_recv_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    client->events = vector_create(sizeof(struct magicnet_event *));
    // We lied we haven't got a packet yet but we need to be sure the connection isnt booted right away.
    client->last_packet_received = time(NULL);

    // Mutex only used for data thats shared outside of the
    // thread action
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&client->mutex, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);

    // todo add the free stuff later on...
    client->packet_monitoring.packets = vector_create(sizeof(struct magicnet_packet *));
    if (!client->packet_monitoring.packets)
    {
        // res = -ENOMEM; ADD STATUS CODES...
        res = -1;
        goto out;
    }

    client->packet_monitoring.type_ids = vector_create(sizeof(int));
    if (!client->packet_monitoring.type_ids)
    {
        res = -1; // impl -ENOMEM
        goto out;
    }

    if (addr_in)
    {
        memcpy(&client->client_info, addr_in, sizeof(&client->client_info));
    }
    for (int i = 0; i < MAGICNET_MAX_AWAITING_PACKETS; i++)
    {
        magicnet_signed_data(&client->packets_for_client.packets[i])->flags |= MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE;
    }

    client->unflushed_data = buffer_create();

out:
    if (res < 0)
    {
        if (client->packet_monitoring.packets)
        {
            vector_free(client->packet_monitoring.packets);
        }

        if (client->packet_monitoring.type_ids)
        {
            vector_free(client->packet_monitoring.type_ids);
        }

        if (client->unflushed_data)
        {
            buffer_free(client->unflushed_data);
        }
    }
    return res;
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

/**
 * Connects to an IP address and returns a client.
 */
struct magicnet_client *magicnet_tcp_network_connect_for_ip_for_server(struct magicnet_server *server, const char *ip_address, int port, const char *program_name, int signal_id, int flags)
{
    int sockfd, res;
    struct sockaddr_in servaddr;
    struct timeval timeout;
    fd_set fdset;

    // Packet will be used for authentication with the peer its connecting too.
    struct magicnet_packet *auth_packet = NULL;

    // Initialize server address structure
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_address, &servaddr.sin_addr) <= 0)
    {
        return NULL;
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        return NULL;
    }

    if (!(flags & MAGICNET_CLIENT_FLAG_MUST_BLOCK))
    {
        // Make socket non-blocking
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    }

    // Start connect
    res = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (res < 0 && errno != EINPROGRESS)
    {
        close(sockfd);
        return NULL;
    }

    // Connection attempt is in progress
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    timeout.tv_sec = MAGICNET_CLIENT_TIMEOUT_SECONDS; // Ensure this macro is defined
    timeout.tv_usec = 0;

    // Use select to wait for the socket to be writable
    res = select(sockfd + 1, NULL, &fdset, NULL, &timeout);
    if (res == 0)
    {
        close(sockfd); // Timeout
        return NULL;
    }
    else if (res < 0)
    {
        close(sockfd); // select() error
        return NULL;
    }

    // Check socket error
    int so_error;
    socklen_t len = sizeof so_error;
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0)
    {
        close(sockfd);
        return NULL;
    }

    // We wont restore the flag to blocking mode as each client is no longer
    // on a seperate thread.

    // Proceed with initialization if connection succeeded
    magicnet_server_lock(server);
    struct magicnet_client *mclient = magicnet_find_free_outgoing_client(server);
    if (!mclient)
    {
        magicnet_server_unlock(server);
        close(sockfd);
        return NULL;
    }
    magicnet_init_client(mclient, server, sockfd, &servaddr);
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED | MAGICNET_CLIENT_FLAG_IS_OUTGOING_CONNECTION;
    if (flags & MAGICNET_CLIENT_FLAG_MUST_BLOCK)
    {
        mclient->flags |= MAGICNET_CLIENT_FLAG_MUST_BLOCK;
    }
    mclient->connection_began = time(NULL);
    strncpy(mclient->peer_info.ip_address, ip_address, sizeof(mclient->peer_info.ip_address));
    magicnet_server_unlock(server);

    if (program_name)
    {
        memcpy(mclient->program_name, program_name, sizeof(mclient->program_name));
    }

    // Let's prepare the authentication packet
    auth_packet = magicnet_packet_new();
    if (!auth_packet)
    {
        res = -ENOMEM;
        goto out;
    }

    // New protocol authentication is handled on its own thread.
out:

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

    int flags = fcntl(connfd, F_GETFL, 0);
    if (flags == -1)
    {
        magicnet_log("%s issue getting flags of socket\n", __FUNCTION__);
        close(connfd);
        return NULL;
    }

#warning "TOO MUCH REPETITION MAKE A CLEANUP LABEL FURTHER DOWN AND MOVE THE LOGIC TODO"

    // Let's make sure it remains non-blocking, for server sockets we never block
    // the whole protocol is a state based protocol.
    if (fcntl(connfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        magicnet_log("%s issue setting sockedt to non-blocking\n", __FUNCTION__);
        close(connfd);
        return NULL;
    }

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

    magicnet_client_push_event(mclient, &(struct magicnet_event){.type = MAGICNET_EVENT_TYPE_TEST});
    magicnet_server_unlock(server);

    return mclient;
}

void magicnet_close(struct magicnet_client *client)
{

    magicnet_important("%s client %p was closed, total bytes read=%i total bytes wrote=%i, average download speed=%i bps, average upload speed=%i bps, time elapsed=%i\n", __FUNCTION__, client, client->total_bytes_received, client->total_bytes_sent, magicnet_client_average_download_speed(client), magicnet_client_average_upload_speed(client), magicnet_client_time_elapsed(client));

    close(client->sock);
    magicnet_client_destruct(client);

    if (client->flags & MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE)
    {
        free(client);
    }
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

/**
 * Total amount of bytes on the network buffer waiting to be read
 *
 */
int magicnet_client_unread_bytes_count(struct magicnet_client *client)
{
    int bytes_available = 0;
    if (ioctl(client->sock, FIONREAD, &bytes_available) == -1)
    {
        return -1;
    }

    return bytes_available;
}
int magicnet_read_bytes(struct magicnet_client *client, void *ptr_out, size_t amount, struct buffer *store_in_buffer)
{
    int res = 0;

    // NO MULTITHREADING ISSUES IWTH READ.
    // test multit-hreading problem to determine if its an issue or not
    pthread_mutex_lock(&tmp_mutex);
    size_t amount_read = 0;
    while (amount_read < amount)
    {
        res = recv(client->sock, ptr_out + amount_read, amount - amount_read, 0);
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

    pthread_mutex_unlock(&tmp_mutex);
    return res;
}

/**
 * This handler can be hooked by people creating buffers to effectively stream over the network when writing/reading
 * for a particular buffer.
 */
int magicnet_network_read_bytes_buffer_handler(struct buffer *buffer, void *data, size_t amount)
{
    struct magicnet_buffer_stream_private_data *private_data = buffer_private_get(buffer);
    return magicnet_read_bytes(private_data->client, data, amount, private_data->write_buf);
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

int magicnet_client_flush(struct magicnet_client *client)
{
    int res = 0;

    pthread_mutex_lock(&tmp_mutex);
    // CORRECT!!!
    struct buffer *unflushed_data_buf = magicnet_client_unflushed_bytes_buffer(client);
    int total_bytes = magicnet_client_unflushed_bytes(client);

    void *ptr_in = buffer_ptr(unflushed_data_buf);
    int amount_written = 0;
    while (amount_written < total_bytes)
    {
        // Socket flush looks correct to me
        // possibly multi-trhreading issues on the socket.
        // Flush directly to the socket
        // NOT A MULTI-THREADING ISSUE TESTED
        // theres an overflow with the  ptr_in+amount_written, valgrind,
        // NOT OVERFLOW UNINITIALIZED BYTES
        // i believe to be a false positive come back to check.
        res = write(client->sock, ptr_in + amount_written, total_bytes - amount_written);
        if (res <= 0)
        {
            res = -1;
            goto out;
        }

        amount_written += res;
        client->total_bytes_sent += res;
    }

    // now we must clear the buffer
    buffer_empty(unflushed_data_buf);

out:
    pthread_mutex_unlock(&tmp_mutex);
    return res;
}

size_t magicnet_client_unflushed_bytes(struct magicnet_client *client)
{
    return buffer_len(client->unflushed_data);
}

int magicnet_client_insert_bytes(struct magicnet_client *client, void *ptr_in, size_t amount, size_t offset_index)
{
    int res = 0;
    res = buffer_insert(client->unflushed_data, offset_index, ptr_in, amount);
    return res;
}

int magicnet_write_bytes(struct magicnet_client *client, void *ptr_in, size_t amount, struct buffer *store_in_buffer)
{
    int res = 0;
    size_t amount_written = 0;

    // New design no longer flushes directly to the socket
    // now we store it in memory incase we need to count it later on ;)
    buffer_write_bytes(client->unflushed_data, ptr_in, amount);
    // Sometimes we are to store the result in a buffer for debugging and validation purposes..
    if (store_in_buffer)
    {
        buffer_write_bytes(store_in_buffer, ptr_in, amount);
    }
    return res;
}

/**
 * This function creates the private stream data for a buffer in the network
 */
struct magicnet_buffer_stream_private_data *magicnet_buffer_stream_private_data_create(struct buffer *write_buffer, struct magicnet_client *client)
{
    struct magicnet_buffer_stream_private_data *private_data = calloc(1, sizeof(struct magicnet_buffer_stream_private_data));
    private_data->client = client;
    private_data->write_buf = write_buffer;
    return private_data;
}

/**
 * This function frees the private data for a buffer in the network
 */
void magicnet_buffer_stream_private_data_free(struct magicnet_buffer_stream_private_data *buffer_data)
{
    free(buffer_data);
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

/**
 * Writes a signed integer
 */
int magicnet_write_signed_int(struct magicnet_client *client, int value, struct buffer *store_in_buffer)
{
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

/**
 * Returns zero on success, int_out is populated with the read integer.
 * Returns a negative number if theirs a problem.
 */
int magicnet_read_signed_int(struct magicnet_client *client, struct buffer *store_in_buffer, int *int_out)
{
    int result = 0;
    if (magicnet_read_bytes(client, &result, sizeof(result), store_in_buffer) < 0)
    {
        return -1;
    }
    *int_out = result;

    return 0;
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

int magicnet_write_short(struct magicnet_client *client, short value, struct buffer *store_in_buffer)
{
    // Preform bit manipulation for big-endianness todo later...
    if (magicnet_write_bytes(client, &value, sizeof(value), store_in_buffer) < 0)
    {
        return -1;
    }
    return 0;
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

    // TODO CHECK THEY CANT JUST DECLARE MASSIVE PAKCET SIZES, HAVE SOME LIMITS
    long data_size = magicnet_read_long(client, packet_out->not_sent.tmp_buf);
    data = calloc(1, data_size);
    if (!data)
    {
        res = -1;
        goto out;
    }

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
    int res = 0;
    magicnet_signed_data(packet_out)->payload.verifier_signup.certificate = magicnet_council_certificate_create();
    // Read the certificate
    res = magicnet_client_read_council_certificate(client, magicnet_signed_data(packet_out)->payload.verifier_signup.certificate, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        magicnet_log("%s failed to read certificate\n", __FUNCTION__);
        goto out;
    }
out:
    if (res < 0)
    {
        if (magicnet_signed_data(packet_out)->payload.verifier_signup.certificate)
        {
            magicnet_council_certificate_free(magicnet_signed_data(packet_out)->payload.verifier_signup.certificate);
        }
    }
    return 0;
}

int magicnet_client_verify_packet_was_signed(struct magicnet_packet *packet)
{
    if (!packet->not_sent.tmp_buf)
    {
        magicnet_log("%s cannot verify if packet was signed when no temporary buffer was set\n", __FUNCTION__);
        return -1;
    }

    magicnet_log("%s key=%s, hash=%s, sig1=%s, sig2=%s\n", __FUNCTION__, packet->pub_key.key, packet->datahash, packet->signature.pr_sig, packet->signature.ps_sig);
    // Let's ensure that they signed the hash that was given to us
    int res = public_verify(&packet->pub_key, packet->datahash, sizeof(packet->datahash), &packet->signature);
    if (res < 0)
    {
        magicnet_log("%s the signature was not signed with the public key provided, hash=%s\n", __FUNCTION__, packet->datahash);
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

    // Let us read the certificate hash we are voting for
    res = magicnet_read_bytes(client, &magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_cert, sizeof(magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_cert), packet->not_sent.tmp_buf);
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

    // Read the transaction type.
    res = magicnet_read_int(client, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read the transaction type\n", __FUNCTION__);
        goto out;
    }

    transaction_out->type = res;

    // Read the target key
    res = magicnet_read_bytes(client, &transaction_out->target_key, sizeof(transaction_out->target_key), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read the target key\n", __FUNCTION__);
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

    // Read the previous block hash
    res = magicnet_read_bytes(client, transaction_out->data.prev_block_hash, sizeof(transaction_out->data.prev_block_hash), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read previous block hash \n", __FUNCTION__);
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
    if (!(client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST) && !(client->flags & MAGICNET_CLIENT_FLAG_IGNORE_TRANSACTION_AND_BLOCK_VALIDATION))
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

/**
 * This handler can be hooked by people creating buffers to effectively stream over the network when writing/reading
 * for a particular buffer.
 */
int magicnet_network_write_bytes_buffer_handler(struct buffer *buffer, void *data, size_t amount)
{
    struct magicnet_buffer_stream_private_data *private_data = buffer_private_get(buffer);
    return magicnet_write_bytes(private_data->client, data, amount, private_data->write_buf);
}

int magicnet_network_buffer_clone_handler(struct buffer* buffer_in, struct buffer* buffer_out)
{
    struct magicnet_buffer_stream_private_data* buffer_in_private = (struct magicnet_buffer_stream_private_data*) buffer_in->private_data;
    // We are required to clone our private data
    buffer_out->private_data = magicnet_buffer_stream_private_data_create(buffer_in_private->write_buf, buffer_in_private->client);
    if (!buffer_out->private_data)
    {
        return -1;
    }
    return 0;
}

int magicnet_client_read_council_certificate(struct magicnet_client *client, struct magicnet_council_certificate *certificate_out, struct buffer *write_buf)
{
    int res = 0;
    struct magicnet_buffer_stream_private_data *private_data = NULL;
    struct buffer *buffer = buffer_create_with_handler(magicnet_network_write_bytes_buffer_handler, magicnet_network_read_bytes_buffer_handler, magicnet_network_buffer_clone_handler);
    if (!buffer)
    {
        goto out;
    }

    private_data = magicnet_buffer_stream_private_data_create(write_buf, client);
    buffer_private_set(buffer, private_data);

    res = magicnet_council_stream_read_certificate(buffer, certificate_out);
    if (res < 0)
    {
        goto out;
    }

out:
    if (private_data)
    {
        magicnet_buffer_stream_private_data_free(private_data);
    }
    buffer_free(buffer);
    return res;
}

int magicnet_client_read_block(struct magicnet_client *client, struct block **block_out, struct buffer *write_buf)
{
    int res = 0;
    char hash[SHA256_STRING_LENGTH];
    char prev_hash[SHA256_STRING_LENGTH];
    char transaction_group_hash[SHA256_STRING_LENGTH];
    time_t block_time;
    struct signature signature;
    struct block *block = NULL;
    int total_transactions = magicnet_read_int(client, write_buf);
    if (total_transactions < 0)
    {
        res = total_transactions;
        goto out;
    }

    struct block_transaction_group *transaction_group = block_transaction_group_new();
    for (int i = 0; i < total_transactions; i++)
    {
        struct block_transaction *transaction = block_transaction_new();
        res = magicnet_read_transaction(client, transaction, write_buf);
        if (res < 0)
        {
            block_transaction_free(transaction);
            goto out;
        }

        block_transaction_add(transaction_group, transaction);
    }
    block_transaction_group_hash_create(transaction_group, transaction_group->hash);

    res = magicnet_read_bytes(client, hash, sizeof(hash), write_buf);
    if (res < 0)
    {
        goto out;
    }
    res = magicnet_read_bytes(client, prev_hash, sizeof(prev_hash), write_buf);
    if (res < 0)
    {
        goto out;
    }
    res = magicnet_read_bytes(client, transaction_group_hash, sizeof(transaction_group_hash), write_buf);
    if (res < 0)
    {
        goto out;
    }

    block_time = magicnet_read_long(client, write_buf);
    if (block_time < 0)
    {
        res = block_time;
        goto out;
    }

    if (memcmp(transaction_group_hash, transaction_group->hash, sizeof(transaction_group_hash)) != 0)
    {
        magicnet_log("%s the transaction group hash does not match the one in the block sent to us\n", __FUNCTION__);
        res = MAGICNET_ERROR_SECURITY_RISK;
        goto out;
    }

    block = block_create_with_group(hash, prev_hash, block_transaction_group_clone(transaction_group));
    if (!block)
    {
        res = MAGICNET_ERROR_UNKNOWN;
        goto out;
    }

    // Council certificates seem okay for the new implementation.. no io issue..
    block->certificate = magicnet_council_certificate_create();
    res = magicnet_client_read_council_certificate(client, block->certificate, write_buf);
    if (res < 0)
    {
        magicnet_log("%s failed to read the certificate for the block\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_read_bytes(client, &signature, sizeof(signature), write_buf);
    if (res < 0)
    {
        goto out;
    }

    block->signature = signature;
    block->time = block_time;

    if (!(client->flags & MAGICNET_CLIENT_FLAG_IGNORE_TRANSACTION_AND_BLOCK_VALIDATION))
    {
        res = block_verify(block);
        if (res < 0)
        {
            magicnet_log("%s issue verifying the received block\n", __FUNCTION__);
            block_free(block);
            block = NULL;
            goto out;
        }
    }

    *block_out = block;
out:
    return res;
}

int magicnet_client_read_block_send_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;

    magicnet_signed_data(packet_out)->payload.block_send.blocks = vector_create(sizeof(struct block *));

    int total_blocks = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (total_blocks < 0)
    {
        res = total_blocks;
        goto out;
    }

    for (int i = 0; i < total_blocks; i++)
    {
        // Add the block
        struct block *block = NULL;
        res = magicnet_client_read_block(client, &block, packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            goto out;
        }

        // Add it to the block array
        vector_push(magicnet_signed_data(packet_out)->payload.block_send.blocks, &block);
    }
out:
    return res;
}

int magicnet_client_read_make_new_connection_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    res = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
    magicnet_signed_data(packet_out)->payload.new_connection.entry_id = res;
    res = magicnet_read_bytes(client, magicnet_signed_data(packet_out)->payload.new_connection.program_name, sizeof(magicnet_signed_data(packet_out)->payload.new_connection.program_name), packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

/**
 * Function that reads the magicnet_block_super_download packet from the client
 * @param client the client to read from
 * @param packet_out the packet to fill
 * @return 0 on success, negative on error
 *
 * Reads the request hash and then the total blocks requested
 */
int magicnet_client_read_block_super_download_request_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    res = magicnet_read_bytes(client, magicnet_signed_data(packet_out)->payload.block_super_download.begin_hash, sizeof(magicnet_signed_data(packet_out)->payload.block_super_download.begin_hash), packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
    res = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
    magicnet_signed_data(packet_out)->payload.block_super_download.total_blocks_to_request = res;
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

    res = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
    magicnet_signed_data(packet_out)->payload.request_block.signal_id = res;

out:
    return res;
}

int magicnet_client_read_request_block_response_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = magicnet_read_bytes(client, magicnet_signed_data(packet_out)->payload.request_block_response.request_hash, sizeof(magicnet_signed_data(packet_out)->payload.request_block_response.request_hash), packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        magicnet_log("%s failed to read previous hash for request block response packet\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
    magicnet_signed_data(packet_out)->payload.request_block_response.signal_id = res;

out:
    return res;
}

int magicnet_client_read_transaction_request(struct magicnet_client *client, struct magicnet_transactions_request *request_out, struct buffer *store_in_buffer)
{
    int res = 0;
    res = magicnet_read_int(client, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read the transaction flags\n", __FUNCTION__);
        goto out;
    }

    request_out->flags = res;

    // Read the key
    res = magicnet_read_bytes(client, &request_out->key, sizeof(request_out->key), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read the key\n", __FUNCTION__);
        goto out;
    }

    // Read the target key
    res = magicnet_read_bytes(client, &request_out->target_key, sizeof(request_out->target_key), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read the target key\n", __FUNCTION__);
        goto out;
    }

    // Read the transaction group hash
    res = magicnet_read_bytes(client, &request_out->transaction_group_hash, sizeof(request_out->transaction_group_hash), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read the transaction group hash\n", __FUNCTION__);
        goto out;
    }

    // Read the type
    res = magicnet_read_signed_int(client, store_in_buffer, &request_out->type);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_int(client, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read total per page\n", __FUNCTION__);
        goto out;
    }

    request_out->total_per_page = res;

    res = magicnet_read_int(client, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to read the current page\n", __FUNCTION__);
        goto out;
    }

    request_out->page = res;

out:
    return res;
}

int magicnet_client_write_transaction_request(struct magicnet_client *client, struct magicnet_transactions_request *request_in, struct buffer *store_in_buffer)
{
    int res = 0;

    // Lets write the flags
    res = magicnet_write_int(client, request_in->flags, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to write the flags\n", __FUNCTION__);
        goto out;
    }

    // Now the key
    res = magicnet_write_bytes(client, &request_in->key, sizeof(request_in->key), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to write the key\n", __FUNCTION__);
        goto out;
    }

    // Now the target key
    res = magicnet_write_bytes(client, &request_in->target_key, sizeof(request_in->target_key), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to write the target key\n", __FUNCTION__);
        goto out;
    }

    // Write the transaction group hash
    res = magicnet_write_bytes(client, request_in->transaction_group_hash, sizeof(request_in->transaction_group_hash), store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to write the transaction group hash\n", __FUNCTION__);
        goto out;
    }

    // Write the type
    res = magicnet_write_int(client, request_in->type, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to write the type\n", __FUNCTION__);
        goto out;
    }

    // Write the total per page
    res = magicnet_write_int(client, request_in->total_per_page, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to write the total per page\n", __FUNCTION__);
        goto out;
    }

    // Write the page
    res = magicnet_write_int(client, request_in->page, store_in_buffer);
    if (res < 0)
    {
        magicnet_log("%s failed to write the page\n", __FUNCTION__);
        goto out;
    }
out:
    return res;
}

int magicnet_client_read_transaction_list_request_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    res = magicnet_client_read_transaction_request(client,
                                                   &magicnet_signed_data(packet_out)->payload.transaction_list_request.req,
                                                   packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        magicnet_log("%s issue reading the transaction request\n", __FUNCTION__);
        goto out;
    }

out:
    return res;
}

int magicnet_client_read_transaction_list_response_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    int total_transactions = 0;
    struct vector *transactions = vector_create(sizeof(struct block_transaction *));
    res = magicnet_client_read_transaction_request(client,
                                                   &magicnet_signed_data(packet_out)->payload.transaction_list_response.req,
                                                   packet_out->not_sent.tmp_buf);

    if (res < 0)
    {
        magicnet_log("%s failed to read the transactions request\n", __FUNCTION__);
        goto out;
    }

    // Read the total transactions
    total_transactions = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (total_transactions < 0)
    {
        res = total_transactions;
        goto out;
    }

    // Read the transactions
    for (int i = 0; i < total_transactions; i++)
    {
        struct block_transaction *transaction = block_transaction_new();
        res = magicnet_read_transaction(client, transaction, packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            goto out;
        }
        vector_push(transactions, &transaction);
    }

    // Set the packet output
    magicnet_signed_data(packet_out)->payload.transaction_list_response.total_transactions = total_transactions;
    magicnet_signed_data(packet_out)->payload.transaction_list_response.transactions = transactions;

out:
    if (res < 0)
    {
        vector_free(transactions);
    }
    return res;
}

int magicnet_client_read_event_new_block(struct magicnet_client *client, struct magicnet_event *event, struct buffer *write_buf)
{
    int res = 0;
    struct block *block = NULL;
    res = magicnet_client_read_block(client, &block, write_buf);
    if (res < 0)
    {
        goto out;
    }

    event->data.new_block_event.block = block;
out:
    return res;
}

int magicnet_client_read_event(struct magicnet_client *client, struct magicnet_event *event, struct buffer *write_buf)
{
    int res = 0;
    res = magicnet_read_int(client, write_buf);
    if (res < 0)
    {
        goto out;
    }

    event->type = res;

    // Read the event ID
    event->id = magicnet_read_int(client, write_buf);
    if (event->id < 0)
    {
        res = event->id;
        goto out;
    }

    switch (event->type)
    {
    case MAGICNET_EVENT_TYPE_NEW_BLOCK:
        res = magicnet_client_read_event_new_block(client, event, write_buf);
        break;

    case MAGICNET_EVENT_TYPE_TEST:
        // Test events do nothing special..
        break;

    default:
        res = -1;
        magicnet_log("%s Unexpected event type of %i I dont know what that is.\n", __FUNCTION__, event->type);
    }
out:
    return res;
}
int magicnet_client_read_events_poll_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    long total_events = magicnet_read_long(client, packet_out->not_sent.tmp_buf);
    if (total_events < 0)
    {
        res = total_events;
        goto out;
    }

    magicnet_signed_data(packet_out)->payload.events_poll.total = total_events;

out:
    return res;
}

int magicnet_client_read_events_res_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;

    long total_events = magicnet_read_long(client, packet_out->not_sent.tmp_buf);
    if (total_events < 0)
    {
        res = total_events;
        goto out;
    }

    magicnet_signed_data(packet_out)->payload.events_poll_res.total = total_events;
    magicnet_signed_data(packet_out)->payload.events_poll_res.events = vector_create(sizeof(struct magicnet_event *));

    for (size_t i = 0; i < total_events; i++)
    {
        struct magicnet_event *event = magicnet_event_new(NULL);
        res = magicnet_client_read_event(client, event, packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            magicnet_event_release(event);
            goto out;
        }

        vector_push(magicnet_signed_data(packet_out)->payload.events_poll_res.events, &event);
    }

out:
    return res;
}

bool magicnet_client_buffer_overflow(size_t amount)
{
    return amount > MAGICNET_REQUEST_AND_RESPOND_INPUT_DATA_MAXIMUM_SIZE;
}

/**
 * Reads an unknown amount of bytes from the client allowing no more than max_size of bytes to be read
 * stores the result in data_out and stores the data size in data_size_out
 *
 * \param client The magicnet client instance
 * \param data_out The pointer to your variable for us to set to the pointer of allocated memory
 * \param data_size The pointer to your variable where we should store the size of the data read
 * \param write_to_buf Should be a pointer to a buffer that you want us to write the network data that we have read too. NULL if you are not interested
 * \return 0 on success, negative on error
 */
int magicnet_client_read_unknown_bytes(struct magicnet_client *client, char **data_out, size_t *data_size_out, size_t max_size, struct buffer *write_to_buf)
{
    int res = 0;
    size_t data_size = 0;
    char *data = NULL;
    *data_out = NULL;
    *data_size_out = 0;
    res = magicnet_read_int(client, write_to_buf);
    if (res < 0)
    {
        goto out;
    }

    data_size = res;
    if (data_size > max_size)
    {
        magicnet_log("%s the data size is too large\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    data = calloc(1, data_size);
    res = magicnet_read_bytes(client, (void *)data, data_size, write_to_buf);
    if (res < 0)
    {
        goto out;
    }

    *data_out = data;
    *data_size_out = data_size;
out:
    if (res < 0)
    {
        if (data)
        {
            free(data);
        }
    }
    return res;
}
int magicnet_client_read_request_and_respond_output_data(struct magicnet_client *client, struct request_and_respond_output_data **output_data_out, struct buffer *store_in_buf)
{
    int res = 0;
    struct request_and_respond_output_data *req_res_output_data = NULL;
    char *output_data_ptr = NULL;
    size_t output_len = 0;
    *output_data_out = NULL;
    res = magicnet_client_read_unknown_bytes(client, &output_data_ptr, &output_len, MAGICNET_REQUEST_AND_RESPOND_OUTPUT_DATA_MAXIMUM_SIZE, store_in_buf);
    if (res < 0)
    {
        goto out;
    }

    req_res_output_data = magicnet_reqres_output_data_create((void *)output_data_ptr, output_len);
    *output_data_out = req_res_output_data;
out:
    return res;
}

int magicnet_client_read_request_and_respond_input_data(struct magicnet_client *client, struct request_and_respond_input_data **input_data_out, struct buffer *store_in_buf)
{
    int res = 0;
    struct request_and_respond_input_data *req_res_input_data = NULL;
    char *input_data_ptr = NULL;
    size_t input_data_len = 0;
    *input_data_out = NULL;
    res = magicnet_client_read_unknown_bytes(client, &input_data_ptr, &input_data_len, MAGICNET_REQUEST_AND_RESPOND_INPUT_DATA_MAXIMUM_SIZE, store_in_buf);
    if (res < 0)
    {
        goto out;
    }

    req_res_input_data = magicnet_reqres_input_data_create((void *)input_data_ptr, input_data_len);
    *input_data_out = req_res_input_data;
out:
    if (input_data_ptr)
    {
        free(input_data_ptr);
    }
    return res;
}
int magicnet_client_read_request_and_respond_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    // Read the request type
    int type = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (type < 0)
    {
        res = type;
        goto out;
    }

    // Read the flags
    int flags = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (flags < 0)
    {
        res = flags;
        goto out;
    }

    // Read the input data
    struct request_and_respond_input_data *input_data = NULL;
    res = magicnet_client_read_request_and_respond_input_data(client, &input_data, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // We have read the packet correctly lets construct it
    magicnet_signed_data(packet_out)->payload.request_and_respond.type = type;
    magicnet_signed_data(packet_out)->payload.request_and_respond.flags = flags;
    magicnet_signed_data(packet_out)->payload.request_and_respond.input_data = input_data;

out:
    return res;
}

int magicnet_client_read_request_and_respond_response_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    struct request_and_respond_input_data *input_data = NULL;
    struct request_and_respond_output_data *output_data = NULL;

    // Read the request type
    int type = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (type < 0)
    {
        res = type;
        goto out;
    }

    // Read the flags
    int flags = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (flags < 0)
    {
        res = flags;
        goto out;
    }

    // Read the input data
    res = magicnet_client_read_request_and_respond_input_data(client, &input_data, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Read the output data
    res = magicnet_client_read_request_and_respond_output_data(client, &output_data, packet_out->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // We have read the packet correctly lets construct it
    magicnet_signed_data(packet_out)->payload.request_and_respond.type = type;
    magicnet_signed_data(packet_out)->payload.request_and_respond.flags = flags;
    magicnet_signed_data(packet_out)->payload.request_and_respond.input_data = input_data;
    magicnet_signed_data(packet_out)->payload.request_and_respond_response.output_data = output_data;
out:
    return res;
}

int magicnet_client_should_start_reading_new_packet(struct magicnet_client *client)
{
    int unread_stream_bytes = magicnet_client_unread_bytes_count(client);
    if (!magicnet_client_no_packet_loading(client))
    {
        return MAGICNET_ERROR_ALREADY_EXISTANT;
    }

    if (unread_stream_bytes <= 0)
        return MAGICNET_ERROR_END_OF_STREAM;
    return 0;
}

int magicnet_client_read_new_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;

    magicnet_log("%s reading a new packet\n", __FUNCTION__);

    int total_size = 0;
    packet_out->not_sent.tmp_buf = buffer_create();

    // DO we have at least FOUR bytes? it is required
    int unread_stream_bytes = magicnet_client_unread_bytes_count(client);

    // NOT A BUG!
    if (unread_stream_bytes < PACKET_PACKET_SIZE_FIELD_SIZE)
    {
        // our peer SHould come back later and try again
        res = MAGICNET_ERROR_TRY_AGAIN;
        goto out;
    }

    total_size = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (total_size < 0)
    {
        res = total_size;
        goto out;
    }

    magicnet_signed_data(packet_out)->expected_size = total_size;
    client->packet_in_loading = packet_out;

    magicnet_log("%s received expected packet size %i\n", __FUNCTION__, (int)total_size);
out:
    return res;
}

bool magicnet_client_has_incomplete_packet(struct magicnet_client *client)
{
    return client->packet_in_loading != NULL;
}

bool magicnet_client_no_packet_loading(struct magicnet_client *client)
{
    return !magicnet_client_has_incomplete_packet(client);
}
bool magicnet_client_packet_loaded(struct magicnet_packet *packet)
{
    return packet->not_sent.total_read_bytes >= magicnet_signed_data(packet)->expected_size;
}

int magicnet_client_read_packet_login_protocol_identification(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    magicnet_log("%s .\n");
    res = magicnet_client_preform_entry_protocol_read(client, packet_out);
    return res;
}

int magicnet_client_read_packet_ping(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    magicnet_log("%s received ping\n", __FUNCTION__);
    // Packet ping does not read anything.
    return res;
}

int magicnet_client_read_packet_open_door(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    int door_key = 0;
    magicnet_log("%s open door received\n", __FUNCTION__);
    door_key = magicnet_read_int(client, NULL);
    if (door_key < 0)
    {
        res = door_key;
        goto out;
    }
    magicnet_signed_data(packet_out)->payload.open_door.door_key = door_key;
out:
    return res;
}

int magicnet_client_read_packet_open_door_ack(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    int door_key = magicnet_read_int(client, NULL);
    if (door_key < 0)
    {
        res = door_key;
        goto out;
    }

    magicnet_signed_data(packet_out)->payload.open_door_ack.door_key = door_key;
out:
    return res;
}

int magicnet_client_read_incomplete_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    magicnet_log("%s ...\n", __FUNCTION__);
    int res = 0;
    int packet_id = 0;
    int packet_type = 0;
    int packet_flags = 0;

    if (!packet_out)
    {
        res = MAGICNET_ERROR_CRITICAL_ERROR;
        goto out;
    }

    // Do we have enough bytes to read the incomplete packet?
    int total_unread_stream_bytes = magicnet_client_unread_bytes_count(client);
    if (total_unread_stream_bytes < magicnet_signed_data(packet_out)->expected_size)
    {
        // Yes we dont have enough bytes we will fail the function and come back later
        res = MAGICNET_ERROR_TRY_AGAIN;
        goto out;
    }

    // somewhere between here and the caller we lose the true packet id
    // a bug, packet id becomes type, breaks the entire data flow... NO BUG ANYORE..

    packet_id = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (packet_id < 0)
    {
        res = packet_id;
        goto out;
    }

    if (client->server)
    {
        magicnet_log("%s lock aquired\n", __FUNCTION__);
        magicnet_server_lock(client->server);
        bool seen_packet = magicnet_server_has_seen_packet_with_id(client->server, packet_id);
        magicnet_server_unlock(client->server);
        magicnet_log("%s lock released\n", __FUNCTION__);
        if (seen_packet)
        {
            // magicnet_signed_data(packet_out)->id = packet_id;
            // magicnet_signed_data(packet_out)->type = MAGICNET_PACKET_TYPE_EMPTY_PACKET;
            // //  magicnet_log("%s we received a packet that we already saw so we aren't going to read it further. ID=%i", __FUNCTION__, packet_id);
            // res = magicnet_write_int(client, MAGICNET_ERROR_RECEIVED_PACKET_BEFORE, packet_out->not_sent.tmp_buf);
            // goto out;
        }
    }

    packet_type = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (packet_type < 0)
    {
        res = packet_type;
        goto out;
    }

    // THIS DOESNT GET HIT
    // THIS SUGGESTS A READING ERROR LEADING TO THE PACKET TYPE
    // BENIG ZERO UPPER IN READING..
    if (packet_type == 0x00)
    {
        magicnet_log("%s sending null packet type illegal\n", __FUNCTION__);
        goto out;
    }

    packet_flags = magicnet_read_int(client, packet_out->not_sent.tmp_buf);
    if (packet_flags < 0)
    {
        res = packet_flags;
        goto out;
    }

#warning "YOU MUST COME BACK AND RE-ENABLE THIS FOR SECURITY PURPOSES, ITS DISABLED FOR NOW DUE TO FALSE POSITIVE"
    // if (magicnet_client_packet_flags_are_private(packet_flags))
    // {
    //     magicnet_log("%s some flags designed for local use only have been sent down the network, the packet has been rejected.\n", __FUNCTION__);
    //     res = -1;
    //     goto out;
    // }

    if (packet_flags & MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE)
    {
        magicnet_signed_data(packet_out)->my_certificate = magicnet_council_certificate_create();
        res = magicnet_client_read_council_certificate(client, magicnet_signed_data(packet_out)->my_certificate, packet_out->not_sent.tmp_buf);
        if (res < 0)
        {
            magicnet_log("%s failed to read the council certificate\n", __FUNCTION__);
            magicnet_council_certificate_free(magicnet_signed_data(packet_out)->my_certificate);
            magicnet_signed_data(packet_out)->my_certificate = NULL;
            goto out;
        }
    }

    switch (packet_type)
    {
    case MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET:
        res = magicnet_client_read_packet_login_protocol_identification(client, packet_out);
        if (res < 0)
        {
            magicnet_log("%s failerd to read the login protocol identification packet\n", __FUNCTION__);
        }
        break;
    case MAGICNET_PACKET_TYPE_PING:
        res = magicnet_client_read_packet_ping(client, packet_out);
        break;

    case MAGICNET_PACKET_TYPE_OPEN_DOOR:
        res = magicnet_client_read_packet_open_door(client, packet_out);
        break;

    case MAGICNET_PACKET_TYPE_OPEN_DOOR_ACK:
        res = magicnet_client_read_packet_open_door_ack(client, packet_out);
        break;

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

    default:
        magicnet_log("%s unimplemented packet type=%x\n", __FUNCTION__, magicnet_signed_data(packet_out)->type);
    }

#warning "disabled most of the packets we will re-enable them individually and test each one"

    // case MAGICNET_PACKET_TYPE_EVENTS_POLL:
    //     res = magicnet_client_read_events_poll_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s event poll packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND:
    //     res = magicnet_client_read_request_and_respond_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s request and respond packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND_RESPONSE:
    //     res = magicnet_client_read_request_and_respond_response_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s request and respond response packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_EVENTS_RES:
    //     res = magicnet_client_read_events_res_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s events res packet failed\n", __FUNCTION__);
    //     }
    //     break;
    // case MAGICNET_PACKET_TYPE_POLL_PACKETS:
    //     res = magicnet_client_read_poll_packets_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s poll packets failed", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_SERVER_SYNC:
    //     res = magicnet_client_read_server_sync_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s sync packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
    //     res = magicnet_client_read_verifier_signup_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s read signup packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER:
    //     res = magicnet_client_read_vote_for_verifier_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s read verifier packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
    //     res = magicnet_client_read_tansaction_send_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s read transaction send packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_BLOCK:
    //     res = magicnet_client_read_request_block_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s failed to read block request packet\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_BLOCK_RESPONSE:
    //     res = magicnet_client_read_request_block_response_packet(client, packet_out);
    //     break;

    // case MAGICNET_PACKET_TYPE_BLOCK_SEND:
    //     res = magicnet_client_read_block_send_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s read block send packet failed\n", __FUNCTION__);
    //     }
    //     break;

    // case MAGICNET_PACKET_TYPE_MAKE_NEW_CONNECTION:
    //     res = magicnet_client_read_make_new_connection_packet(client, packet_out);
    //     break;

    // case MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_REQUEST:
    //     res = magicnet_client_read_block_super_download_request_packet(client, packet_out);
    //     break;

    // case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_REQUEST:
    //     res = magicnet_client_read_transaction_list_request_packet(client, packet_out);
    //     break;

    // case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_RESPONSE:
    //     res = magicnet_client_read_transaction_list_response_packet(client, packet_out);
    //     break;

    // case MAGICNET_PACKET_TYPE_NOT_FOUND:
    //     res = magicnet_client_read_not_found_packet(client, packet_out);
    //     if (res < 0)
    //     {
    //         magicnet_log("%s read not found packet failed\n", __FUNCTION__);
    //     }
    //     break;
    // default:
    //     magicnet_log("%s unexpected packet was provided %i\n", __FUNCTION__, packet_type);
    //     res = -1;
    //     break;
    // }

    // Has the packet failed to be read?
    if (res < 0)
    {
        goto out;
    }
    magicnet_signed_data(packet_out)->id = packet_id;
    magicnet_signed_data(packet_out)->type = packet_type;
    magicnet_signed_data(packet_out)->flags = packet_flags;

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

    res = magicnet_read_bytes(client, packet_out->datahash, sizeof(packet_out->datahash), NULL);
    if (res < 0)
    {
        return -1;
    }

    if (magicnet_signed_data(packet_out)->type == MAGICNET_PACKET_TYPE_USER_DEFINED)
    {
        // BRAK HERE
        magicnet_log("%s break here\n", __FUNCTION__);
    }
    /**
     * @brief Here unsigned packets provided by a LOCALHOST connection will be signed with our local key
     * this is okay because this is the local machine therefore it is the authority of this server instance
     * to sign all packets. Still only if we have a server instance on the client can we sign because
     * the server is responsible for the keys. So local clients outside of the server cannot sign their own packets.
     */
    if (!has_signature && client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST && client->server)
    {
        // Since we have no signature let us create our own this is allowed since we have confimed
        // that we are localhost and by default localhost packets have no signatures.

        // Let's start by rehashing the data so we have an accurate hash. Just in case they provided us with a NULL hash entry
        // perfectly valid from a localhost client.
        magicnet_packet_hash(packet_out);

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

    if (has_signature)
    {
        // Now the packet is constructed lets verify its contents if it has been signed.
        res = magicnet_client_verify_packet_was_signed(packet_out);
        if (res < 0)
        {
            magicnet_log("%s packet was signed incorrectly\n", __FUNCTION__);
            return res;
        }
    }

    // Change this so it works in real time or remove and deprecate it..
    packet_out->not_sent.total_read_bytes = magicnet_signed_data(packet_out)->expected_size;

    // We have seen this packet now.
    if (client->server)
    {
        magicnet_server_lock(client->server);
        magicnet_server_add_seen_packet(client->server, packet_out);
        magicnet_server_unlock(client->server);
    }

out:

    // Now the packet has been loaded or (failed to load) we can remove it from the loading packet
    // in the client.
    client->packet_in_loading = NULL;

    buffer_free(packet_out->not_sent.tmp_buf);
    packet_out->not_sent.tmp_buf = NULL;

    return res;
}
int magicnet_client_read_packet(struct magicnet_client *client, struct magicnet_packet *packet_out)
{
    int res = 0;
    magicnet_client_lock(client);

    /**
     * Is there no packet currently waiting to be finished laoding?
     * then this is a fresh packet, lets begin reading its size..
     */
    if (magicnet_client_no_packet_loading(client))
    {

        res = magicnet_client_read_new_packet(client, packet_out);
        if (res < 0)
        {
            // problem
            goto out;
        }
    }

    int unread_bytes = magicnet_client_unread_bytes_count(client);
    if (unread_bytes < magicnet_signed_data(packet_out)->expected_size)
    {
        magicnet_log("%s not enough bytes on stream\n", __FUNCTION__);
        // Yes we don't have enough data on stream to load the packet
        // we will need to try again later, this is a non blockijng protocol
        res = MAGICNET_ERROR_TRY_AGAIN;
        goto out;
    }

    // Alright we have enough lets finish loading that packet
    res = magicnet_client_read_incomplete_packet(client, packet_out);
    if (res < 0)
    {
        goto out;
    }
    // Packet has finished loading and can be processed later..
    magicnet_log("%s finished reading packet\n", __FUNCTION__);
out:
    magicnet_client_unlock(client);
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
int magicnet_network_write_bytes_buffer_clone_handler(struct buffer* buffer_in, struct buffer* buffer_out)
{
    struct magicnet_buffer_stream_private_data* private_data = (struct magicnet_buffer_stream_private_data*) buffer_in->private_data;
    if (private_data)
    {
        buffer_out->private_data = magicnet_buffer_stream_private_data_create(private_data->write_buf, private_data->client);
        if (!buffer_out->private_data)
        {
            return -1;
        }
    }
    return 0;
}

int magicnet_client_write_council_certificate(struct magicnet_client *client, struct magicnet_council_certificate *certificate, struct buffer *write_buf)
{
    int res = 0;
    struct magicnet_buffer_stream_private_data *private_data = NULL;
    // We will create the buffer so that it streams directly to the network
    struct buffer *buffer = buffer_create_with_handler(magicnet_network_write_bytes_buffer_handler, NULL, magicnet_network_write_bytes_buffer_clone_handler);
    if (!buffer)
    {
        return -1;
    }

    // The private data will be setup to hold the write_buf and current client so that the stream
    // knows which client to write the data too, additionally it will store all it writes in the write_buf
    // for hashing and signature reasons.
    private_data = magicnet_buffer_stream_private_data_create(write_buf, client);
    buffer_private_set(buffer, private_data);

    res = magicnet_council_stream_write_certificate(buffer, certificate);
    if (res < 0)
    {
        goto out;
    }

out:
    if (private_data)
    {
        magicnet_buffer_stream_private_data_free(private_data);
    }
    buffer_free(buffer);
    return res;
}
int magicnet_client_write_packet_verifier_signup(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    if (!magicnet_signed_data(packet)->payload.verifier_signup.certificate)
    {
        magicnet_log("%s no certificate provided\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    res = magicnet_client_write_council_certificate(client, magicnet_signed_data(packet)->payload.verifier_signup.certificate, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_packet_vote_for_verifier(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_bytes(client, &magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_cert, sizeof(magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_cert), packet->not_sent.tmp_buf);

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
        // It is possible that the state of the blockchain is greater than it was
        // for when the transaction we are writing was created. For that reason we dont want to verify transaction data
        // THis isnt an issue as the receiver of this transaction will ensure the transaction is valid.
        // We dont care what we are writing as we already know this transaction is valid as we have it.
        // We will just to a basic validation of this transaction to ensure its error free. But it will not
        // verify the validility of the transaction.
        res = block_transaction_valid_specified(transaction, MAGICNET_BLOCK_VERIFICATION_VERIFY_WITHOUT_TRANSACTION_DATA);
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

    // Write the  transaction type
    res = magicnet_write_int(client, transaction->type, store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

    // Write the transaction target key
    res = magicnet_write_bytes(client, &transaction->target_key, sizeof(transaction->target_key), store_in_buffer);
    if (res < 0)
    {
        goto out;
    }

    // Write the time.
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

    // Write the previous block hash
    res = magicnet_write_bytes(client, transaction->data.prev_block_hash, sizeof(transaction->data.prev_block_hash), store_in_buffer);
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

int magicnet_client_write_block(struct magicnet_client *client, struct buffer *buffer, struct block *block)
{
    int res = 0;
    struct block_transaction_group *transaction_group = block->transaction_group;
    res = magicnet_write_int(client, transaction_group->total_transactions, buffer);
    if (res < 0)
    {
        goto out;
    }

    for (int i = 0; i < transaction_group->total_transactions; i++)
    {
        res = magicnet_write_transaction(client, transaction_group->transactions[i], buffer);
        if (res < 0)
        {
            goto out;
        }
    }

    res = magicnet_write_bytes(client, block->hash, sizeof(block->hash), buffer);
    if (res < 0)
    {
        goto out;
    }
    res = magicnet_write_bytes(client, block->prev_hash, sizeof(block->prev_hash), buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, block->transaction_group->hash, sizeof(block->transaction_group->hash), buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_long(client, block->time, buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_client_write_council_certificate(client, block->certificate, buffer);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, &block->signature, sizeof(block->signature), buffer);
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

    res = magicnet_write_int(client, vector_count(blocks_to_send), packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    vector_set_peek_pointer(blocks_to_send, 0);
    struct block *block = vector_peek_ptr(blocks_to_send);
    while (block)
    {
        res = magicnet_client_write_block(client, packet->not_sent.tmp_buf, block);
        if (res < 0)
        {
            goto out;
        }
        block = vector_peek_ptr(blocks_to_send);
    }
out:
    return res;
}

int magicnet_client_write_packet_make_new_connection(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.new_connection.entry_id, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, magicnet_signed_data(packet)->payload.new_connection.program_name, sizeof(magicnet_signed_data(packet)->payload.new_connection.program_name), packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

int magicnet_client_write_packet_block_super_download_request(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_bytes(client, magicnet_signed_data(packet)->payload.block_super_download.begin_hash, sizeof(magicnet_signed_data(packet)->payload.block_super_download.begin_hash), packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.block_super_download.total_blocks_to_request, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
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
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.request_block.signal_id, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

int magicnet_client_write_packet_request_block_response(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_bytes(client, magicnet_signed_data(packet)->payload.request_block_response.request_hash, sizeof(magicnet_signed_data(packet)->payload.request_block.request_hash), packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.request_block_response.signal_id, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

int magicnet_client_write_packet_transaction_list_request(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    res = magicnet_client_write_transaction_request(client, &magicnet_signed_data(packet)->payload.transaction_list_request.req, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        magicnet_log("%s failed to write packet transaction list request\n", __FUNCTION__);
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_packet_transaction_list_response(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    // Check the total transactions equals the count of the transactions vector
    if (magicnet_signed_data(packet)->payload.transaction_list_response.total_transactions != vector_count(magicnet_signed_data(packet)->payload.transaction_list_response.transactions))
    {
        // Show size mismatch message
        magicnet_error("Transaction list response total transactions does not match the count of the transactions vector (%d != %d)", magicnet_signed_data(packet)->payload.transaction_list_response.total_transactions, vector_count(magicnet_signed_data(packet)->payload.transaction_list_response.transactions));
        res = -1;
        goto out;
    }

    // Write the actual request
    res = magicnet_client_write_transaction_request(client, &magicnet_signed_data(packet)->payload.transaction_list_response.req, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        magicnet_log("%s failed to write the transaction request data\n", __FUNCTION__);
        goto out;
    }

    // Write the total transactions
    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.transaction_list_response.total_transactions, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Set the peek pointer of transactions to zero
    vector_set_peek_pointer(magicnet_signed_data(packet)->payload.transaction_list_response.transactions, 0);
    // Write the transactions
    struct block_transaction *transaction = vector_peek_ptr(magicnet_signed_data(packet)->payload.transaction_list_response.transactions);
    while (transaction)
    {
        res = magicnet_write_transaction(client, transaction, packet->not_sent.tmp_buf);
        if (res < 0)
        {
            goto out;
        }
        transaction = vector_peek_ptr(magicnet_signed_data(packet)->payload.transaction_list_response.transactions);
    }
out:
    return res;
}

int magicnet_client_write_packet_events_poll(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    res = magicnet_write_long(client, magicnet_signed_data(packet)->payload.events_poll.total, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_event_new_block(struct magicnet_client *client, struct magicnet_event *event, struct buffer *write_buf)
{
    int res = 0;
    struct block *block = event->data.new_block_event.block;
    res = magicnet_client_write_block(client, write_buf, block);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_event(struct magicnet_client *client, struct magicnet_event *event, struct buffer *write_buf)
{
    int res = 0;
    res = magicnet_write_int(client, event->type, write_buf);
    if (res < 0)
    {
        goto out;
    }

    // Write the event ID
    res = magicnet_write_int(client, event->id, write_buf);
    if (res < 0)
    {
        goto out;
    }

    switch (event->type)
    {
    case MAGICNET_EVENT_TYPE_NEW_BLOCK:
        res = magicnet_client_write_event_new_block(client, event, write_buf);
        break;

    case MAGICNET_EVENT_TYPE_TEST:
        // Nothing to write
        break;
    default:
        res = -1;
        magicnet_log("%s Unexpected event type of %i I dont know what that is.\n", __FUNCTION__, event->type);
    }
out:
    return res;
}

int magicnet_client_write_packet_events_res(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct signed_data *signed_data = magicnet_signed_data(packet);
    res = magicnet_write_long(client, signed_data->payload.events_poll_res.total, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    if (vector_count(signed_data->payload.events_poll_res.events) != signed_data->payload.events_poll_res.total)
    {
        magicnet_error("%s invalid packet event counts do not match\n", __FUNCTION__);
        goto out;
    }

    vector_set_peek_pointer(signed_data->payload.events_poll_res.events, 0);
    struct magicnet_event *event = vector_peek_ptr(signed_data->payload.events_poll_res.events);
    while (event)
    {
        res = magicnet_client_write_event(client, event, packet->not_sent.tmp_buf);
        if (res < 0)
        {
            goto out;
        }
        event = vector_peek_ptr(signed_data->payload.events_poll_res.events);
    }
out:
    return res;
}

int magicnet_client_write_known_bytes(struct magicnet_client *client, const char *data_in, size_t data_size, struct buffer *write_to_buf)
{
    int res = 0;
    res = magicnet_write_int(client, (int)data_size, write_to_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_bytes(client, (void *)data_in, data_size, write_to_buf);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

int magicnet_client_write_request_and_respond_output_data(struct magicnet_client *client, struct request_and_respond_output_data *output_data, struct buffer *store_in_buf)
{
    int res = 0;

    res = magicnet_client_write_known_bytes(client, output_data->output, output_data->size, store_in_buf);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

int magicnet_client_write_request_and_respond_input_data(struct magicnet_client *client, struct request_and_respond_input_data *input_data, struct buffer *store_in_buf)
{
    int res = 0;

    res = magicnet_client_write_known_bytes(client, input_data->input, input_data->size, store_in_buf);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_packet_request_and_respond(struct magicnet_client *client, struct magicnet_packet *packet_in)
{
    int res = 0;

    // Lets check theirs an input data to send
    if (!magicnet_signed_data(packet_in)->payload.request_and_respond.input_data)
    {
        magicnet_log("%s no input data provided\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Write the request type
    res = magicnet_write_int(client, magicnet_signed_data(packet_in)->payload.request_and_respond.type, packet_in->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Write the flags
    res = magicnet_write_int(client, magicnet_signed_data(packet_in)->payload.request_and_respond.flags, packet_in->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Write the input data
    res = magicnet_client_write_request_and_respond_input_data(client, magicnet_signed_data(packet_in)->payload.request_and_respond.input_data, packet_in->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_packet_request_and_respond_response(struct magicnet_client *client, struct magicnet_packet *packet_in)
{
    int res = 0;
    // First things first lets validate that theirs an actual request input and output to send
    if (!magicnet_signed_data(packet_in)->payload.request_and_respond_response.input_data || !magicnet_signed_data(packet_in)->payload.request_and_respond_response.output_data)
    {
        magicnet_log("%s no input or output data provided\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Write the request type
    res = magicnet_write_int(client, magicnet_signed_data(packet_in)->payload.request_and_respond_response.type, packet_in->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Write the flags
    res = magicnet_write_int(client, magicnet_signed_data(packet_in)->payload.request_and_respond_response.flags, packet_in->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Write input data
    res = magicnet_client_write_request_and_respond_input_data(client, magicnet_signed_data(packet_in)->payload.request_and_respond_response.input_data, packet_in->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Write the output data
    res = magicnet_client_write_request_and_respond_output_data(client, magicnet_signed_data(packet_in)->payload.request_and_respond_response.output_data, packet_in->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_client_write_packet_ping(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    // Packet ping writes nothing more than its type which has been sent.
    return res;
}
/**
 * WARNING: NOT FOR PACKET RELAY, DO NOT RELAY SOMEONE ELSES IDENTIFICATION PACKET
 * FORBIDDEN!!!
 */
int magicnet_client_write_login_protocol_identification_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    const char *program_name = magicnet_signed_data(packet)->payload.login_protocol_iden.program_name;
    int communication_flags = magicnet_signed_data(packet)->payload.login_protocol_iden.communication_flags;
    int signal_id = magicnet_signed_data(packet)->payload.login_protocol_iden.signal_id;
    res = magicnet_client_preform_entry_protocol_write(client, program_name, communication_flags, signal_id);
    return res;
}

int magicnet_client_write_packet_open_door(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.open_door.door_key, NULL);
    return res;
}

int magicnet_client_write_packet_open_door_ack(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_write_int(client, magicnet_signed_data(packet)->payload.open_door_ack.door_key, NULL);
    return res;
}

int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet, int flags)
{
    int res = 0;
    magicnet_client_lock(client);

    if (magicnet_signed_data(packet)->type == 0x00)
    {
        magicnet_log("%s attempting to send a NULL packet, this suggests a memory error, no null type exists\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    packet->not_sent.tmp_buf = buffer_create();
    client->last_packet_sent = time(NULL);

    res = magicnet_write_int(client, magicnet_signed_data(packet)->id, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // CONFIRMED: THIS IS NOT A WRITING ERROR
    // no bug found... if statement never active.
    if (magicnet_signed_data(packet)->type == 0x00)
    {
        magicnet_log("%s caught\n ", __FUNCTION__);
    }

    res = magicnet_write_int(client, magicnet_signed_data(packet)->type, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    // Packet type is correct so the bug must be during flushing some how..
    magicnet_log("%s writing packet_type=%i\n", __FUNCTION__, magicnet_signed_data(packet)->type);

    // We need to strip any private localuse flags from the packet before we send it.
    // Only flags intended for public viewing should be sent.
    int stripped_flags = magicnet_client_packet_strip_private_flags(packet);
    res = magicnet_write_int(client, stripped_flags, packet->not_sent.tmp_buf);
    if (res < 0)
    {
        goto out;
    }

    if (stripped_flags & MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE)
    {
        magicnet_log("%s we have a council certificate to send with this packet, hash=%s\n", __FUNCTION__, magicnet_signed_data(packet)->my_certificate->hash);
        // We have a council certificate to send with this packet we will just send it
        // we dont know at this point if its valid or not. The receiver can decide.
        res = magicnet_client_write_council_certificate(client, magicnet_signed_data(packet)->my_certificate, packet->not_sent.tmp_buf);
        if (res < 0)
        {
            magicnet_log("%s failed to write council certificate\n", __FUNCTION__);
            goto out;
        }
    }

    // re-enabled packets 6 in read 6 in write valid.
    // these are only for when the door is closed.
    switch (magicnet_signed_data(packet)->type)
    {
    case MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET:
        res = magicnet_client_write_login_protocol_identification_packet(client, packet);
        break;
    case MAGICNET_PACKET_TYPE_PING:
        res = magicnet_client_write_packet_ping(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_OPEN_DOOR:
        res = magicnet_client_write_packet_open_door(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_OPEN_DOOR_ACK:
        res = magicnet_client_write_packet_open_door_ack(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_EMPTY_PACKET:
        res = magicnet_client_write_packet_empty(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_client_write_packet_user_defined(client, packet);
        break;

    default:
        magicnet_log("%s sending unimplemented packet type=%i", __FUNCTION__, magicnet_signed_data(packet)->type);
    }

#warning "most  packets are disabled for this significant change"
    // we will -renable them manually each one tested on its own

    // switch (magicnet_signed_data(packet)->type)
    // {

    // case MAGICNET_PACKET_TYPE_EMPTY_PACKET:
    //     res = magicnet_client_write_packet_empty(client, packet);

    //     break;
    // case MAGICNET_PACKET_TYPE_POLL_PACKETS:
    //     res = magicnet_client_write_packet_poll_packets(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND:
    //     res = magicnet_client_write_packet_request_and_respond(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND_RESPONSE:
    //     res = magicnet_client_write_packet_request_and_respond_response(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_EVENTS_POLL:
    //     res = magicnet_client_write_packet_events_poll(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_EVENTS_RES:
    //     res = magicnet_client_write_packet_events_res(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_USER_DEFINED:
    //     res = magicnet_client_write_packet_user_defined(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_NOT_FOUND:
    //     res = magicnet_client_write_packet_not_found(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
    //     res = magicnet_client_write_packet_verifier_signup(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER:
    //     res = magicnet_client_write_packet_vote_for_verifier(client, packet);
    //     break;
    // case MAGICNET_PACKET_TYPE_SERVER_SYNC:
    //     res = magicnet_client_write_packet_server_poll(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
    //     res = magicnet_client_write_packet_transaction_send(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_BLOCK:
    //     res = magicnet_client_write_packet_request_block(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_REQUEST_BLOCK_RESPONSE:
    //     res = magicnet_client_write_packet_request_block_response(client, packet);
    //     break;
    // case MAGICNET_PACKET_TYPE_BLOCK_SEND:
    //     res = magicnet_client_write_packet_block_send(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_MAKE_NEW_CONNECTION:
    //     res = magicnet_client_write_packet_make_new_connection(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_REQUEST:
    //     res = magicnet_client_write_packet_block_super_download_request(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_REQUEST:
    //     res = magicnet_client_write_packet_transaction_list_request(client, packet);
    //     break;

    // case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_RESPONSE:
    //     res = magicnet_client_write_packet_transaction_list_response(client, packet);
    //     break;
    // }

    // Okay we have a buffer of all the data we sent to the peer, lets get it and hash it so that
    // we can prove who signed this packet later on..

    if (flags & MAGICNET_PACKET_FLAG_MUST_BE_SIGNED)
    {
       magicnet_packet_hash(packet);

        magicnet_log("%s will sign packet\n", __FUNCTION__);  // not called...
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

        // One final check incase concurrency problems memory leaks or whatever threading problems
        // damaged the packet integrity.
        // AT THIS POINT THE VERIFY WORKS
        res = magicnet_client_verify_packet_was_signed(packet);
        if (res < 0)
        {
            magicnet_log("%s packet was signed incorrectly\n", __FUNCTION__);
            goto out;
        }

        // WE KNOW THAT THIS FUNCTION DOES NOT CORRUPT THE PACKET
        // BECAUSE BOTH PASS, WHICH MEANS THE PROBLEM IS FURTHER DOWN OR ON ANOTHER THREAD
        res = magicnet_client_verify_packet_was_signed(packet);
        if (res < 0)
        {
            magicnet_log("%s packet was signed incorrectly abc..\n", __FUNCTION__);
            goto out;
        }
    }

    if (magicnet_signed_data(packet)->type == MAGICNET_PACKET_TYPE_USER_DEFINED)
    {
        magicnet_log("%s server break here, hash=%s\n", __FUNCTION__, packet->datahash);
    }

    if (stripped_flags & MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE)
    {
        // Lets check that the key who signed the packet is the same as the key who signed the certificate
        if (!key_cmp(&packet->pub_key, &magicnet_signed_data(packet)->my_certificate->owner_key))
        {
            magicnet_log("%s the key who signed the packet is not the same as the key who signed the certificate.\n", __FUNCTION__);
            res = -1;
            goto out;
        }
    }

    // Its possible packet was already signed
    bool has_signature = !MAGICNET_nulled_signature(&packet->signature);
    if (!has_signature)
    {
        magicnet_log("%s attempting to send unsigned packet\n", __FUNCTION__);
    }

    // THE MEMORY CORRUPTION HAPPENS BELOW SUGGESTING THE BUFFER IS SOME HOW BROKEN
  //  if (magicnet_signed_data(packet)->type != MAGICNET_PACKET_TYPE_USER_DEFINED)
    {
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
    }

    if (has_signature)
    {
        // SOMEWHERE BETWEEN THIS CHECK AND ABOVE TO THE LAST CHECK THE DATA WAS DAMAGED.
        res = magicnet_client_verify_packet_was_signed(packet);
        if (res < 0)
        {
            magicnet_log("%s packet was signed incorrectly second check\n", __FUNCTION__);
            goto out;
        }
    }
    // Send the data hash
    res = magicnet_write_bytes(client, packet->datahash, sizeof(packet->datahash), NULL);
    if (res < 0)
    {
        goto out;
    }

    // We must write the size of the data of the packet
    // so the receving peer knows how much to listen for.
    // This will be checked on the peers end to ensure no manipulation is taking place
    // i.e no buffer overflows, or excessive sending wont be allowed.

    // lets insert it at the start of the buffer stream, this will be the size
    // then we can flush and its on the way to the peer
    int packet_size = (int)magicnet_client_unflushed_bytes(client);

    // Packet size must be decremented by the 4 byte integer size
    // because this is already accounted for by the receving client
    packet_size -= sizeof(packet_size);

    // We insert directly at the first byte of the stream
    // as the reading peer expects the first 4 bytes to be the total
    // size of the packet that is to be sent
    // NOTE: This writes the packet_size directly to the start of the stream
    res = magicnet_client_insert_bytes(client, &packet_size, sizeof(packet_size), 0);
    if (res < 0)
    {
        goto out;
    }

    // Finally flush it to the peer
    magicnet_client_flush(client);

    // data is on its way..

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

    magicnet_client_unlock(client);
    return res;
}

bool magicnet_connected(struct magicnet_client *client)
{
    return client && client->flags & MAGICNET_CLIENT_FLAG_CONNECTED;
}

bool magicnet_is_localhost(struct magicnet_client *client)
{
    return client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST;
}

int magicnet_client_connection_type(struct magicnet_client *client)
{
    if (client->flags & MAGICNET_CLIENT_FLAG_IS_OUTGOING_CONNECTION)
    {
        return MAGICNET_CONNECTION_TYPE_OUTGOING;
    }

    return MAGICNET_CONNECTION_TYPE_INCOMING;
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
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED | MAGICNET_CLIENT_FLAG_IS_OUTGOING_CONNECTION;
    mclient->connection_began = time(NULL);
    mclient->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    mclient->max_bytes_recv_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    mclient->communication_flags = communication_flags;
    mclient->events = vector_create(sizeof(struct magicnet_event *));

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

    // NEW PROTOCOL THE AUTHENTICATION HANDSHAKE IS HANDLED ON ITS OWN THREAD

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

#warning "This code is duplicated all over the place, use a common function..."
    struct magicnet_client *mclient = magicnet_client_new();
    if (!mclient)
    {
        return NULL;
    }
    mclient->sock = sockfd;
    mclient->server = NULL;
    mclient->flags |= MAGICNET_CLIENT_FLAG_CONNECTED | MAGICNET_CLIENT_FLAG_IS_OUTGOING_CONNECTION;
    mclient->connection_began = time(NULL);
    mclient->max_bytes_send_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    mclient->max_bytes_recv_per_second = MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND;
    mclient->events = vector_create(sizeof(struct magicnet_event *));

    // Bit crappy, convert to integer then test...
    // cAN'T always rely on 127.0.0.1 for loopback, check the system
    // for valid
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

// NEW PROTOCOL AUTHENTICATION IS HANDLED ON ITS OWN THREAD
#warning "LOTS OF FUNCTIONS LIKE THIS ABSTRACT INTO ONE FUNCTION"

    return mclient;
}

struct magicnet_client *magicnet_connect_again_outgoing(struct magicnet_client *client, const char *program_name)
{
    const char *client_ip = inet_ntoa(client->client_info.sin_addr);
    char client_ip_buf[MAGICNET_MAX_IP_STRING_SIZE];
    strncpy(client_ip_buf, client_ip, sizeof(client_ip_buf));

#warning "TODO MAINTAIN THE OLD FLAGS FROM PREVIOUS CONNECTION"
    int flags = 0;
    return magicnet_tcp_network_connect_for_ip_for_server(client->server, client_ip_buf, MAGICNET_SERVER_PORT, program_name, 0, flags);
}

// copilot write a function that sums to numbers

struct magicnet_client *magicnet_connect_again_incoming(struct magicnet_client *client, const char *program_name)
{
    // Connecting again to this client will be complicated in this respect because they are connected to us
    // their firewall likely wont allow us to connect to them since we accepted their initial connection
    // therefore we must send them a command to connect to us again then intercept the connection
    int res = 0;
    struct magicnet_client *client_out = NULL;
    struct magicnet_signal *signal = magicnet_signal_find_free("connect-again-signal");
    if (!signal)
    {
        return NULL;
    }

    // let's relay a packet to the client asking them to connect to us
    struct magicnet_packet *packet = magicnet_packet_new();
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_MAKE_NEW_CONNECTION;
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet)->payload.new_connection.entry_id = signal->id;
    strncpy(magicnet_signed_data(packet)->payload.new_connection.program_name, program_name, sizeof(magicnet_signed_data(packet)->payload.new_connection.program_name));
    res = magicnet_relay_packet_to_client(client, packet);
    if (res < 0)
    {
        goto out;
    }

    // Let us now wait for the incoming signal.
    res = magicnet_signal_wait_timed(signal, 30, (void **)&client_out);
    if (res < 0)
    {
        magicnet_log("%s nobody connected to us\n", __FUNCTION__);
        goto out;
    }

    magicnet_log("%s new incoming connection initiated\n", __FUNCTION__);
out:
    return client_out;
}

/*
 * This function will attempt to connect to the client again.
 * If the client is an incoming connection then we will send a packet to the client asking them to connect to us again
 * If the client is an outgoing connection then we will attempt to connect to the client again
 */
struct magicnet_client *magicnet_connect_again(struct magicnet_client *client, const char *program_name)
{
    if (!client->server)
    {
        return NULL;
    }

    struct magicnet_client *cloned_client = NULL;
    int conn_type = magicnet_client_connection_type(client);
    if (conn_type == MAGICNET_CONNECTION_TYPE_OUTGOING)
    {
        cloned_client = magicnet_connect_again_outgoing(client, program_name);
    }
    else if (conn_type == MAGICNET_CONNECTION_TYPE_INCOMING)
    {
        cloned_client = magicnet_connect_again_incoming(client, program_name);
    }
    else
    {
        magicnet_log("%s unsure how to connect to the client\n", __FUNCTION__);
    }

    return cloned_client;
}

struct magicnet_client *magicnet_connect_for_key(struct magicnet_server *server, struct key *key, const char *program_name)
{
    // Let's see if we can find someone whose already connected with us with that client key.
    struct magicnet_client *key_client = magicnet_server_get_client_with_key(server, key);
    if (!key_client)
    {
        magicnet_log("%s though someone responded with a key we aren't connected to them. TODO in the future: Make it search the database for potential IP address for this peer key\n", __FUNCTION__);
        return NULL;
    }

    // Client already connected? Then lets connect to them again
    return magicnet_connect_again(key_client, program_name);
}
struct magicnet_packet *magicnet_recv_next_packet(struct magicnet_client *client, int *res_out)
{
    struct magicnet_packet *packet = magicnet_packet_new();
    int res = magicnet_client_read_packet(client, packet);
    if (res < 0)
    {
        magicnet_packet_free(packet);
        packet = NULL;
    }

    *res_out = res;
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
    block_send_packet_out->blocks = block_vector_out;
}

void magicnet_copy_packet_transaction_list_response(struct magicnet_packet *packet_out, struct magicnet_packet *packet_in)
{
    vector_set_peek_pointer(magicnet_signed_data(packet_out)->payload.transaction_list_response.transactions, 0);
    struct block_transaction *transaction = vector_peek_ptr(magicnet_signed_data(packet_out)->payload.transaction_list_response.transactions);
    while (transaction)
    {
        struct block_transaction *cloned_transaction = block_transaction_clone(transaction);
        vector_push(magicnet_signed_data(packet_out)->payload.transaction_list_response.transactions, &cloned_transaction);
        transaction = vector_peek_ptr(magicnet_signed_data(packet_out)->payload.transaction_list_response.transactions);
    }
}

void magicnet_copy_packet_events_poll(struct magicnet_packet *packet_out, struct magicnet_packet *packet_in)
{
    // Nothing to do..
}

void magicnet_copy_packet_events_res(struct magicnet_packet *packet_out, struct magicnet_packet *packet_in)
{
    struct vector *events_vec_in = magicnet_signed_data(packet_in)->payload.events_poll_res.events;
    magicnet_signed_data(packet_out)->payload.events_poll_res.events = magicnet_copy_events(events_vec_in);
}

void magicnet_copy_packet_verifier_signup(struct magicnet_packet *packet_out, struct magicnet_packet *packet_in)
{
    assert(magicnet_signed_data(packet_in)->type == MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP);
    assert(magicnet_signed_data(packet_in)->payload.verifier_signup.certificate != NULL);
    magicnet_signed_data(packet_out)->payload.verifier_signup.certificate = magicnet_council_certificate_clone(magicnet_signed_data(packet_in)->payload.verifier_signup.certificate);
}

void magicnet_copy_packet_login_protocol_identification_packet(struct magicnet_packet *packet_out, struct magicnet_packet *packet_in)
{
    if (magicnet_signed_data(packet_in)->type != MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET)
    {
        // Not a login identification packet.
        magicnet_log("%s BUG YOU CALLED THIS FUNCTION YET ITS NOT THE CORRECT PACKET\n", __FUNCTION__);
        return;
    }

    // let's start with a simple memcpy and we will fill in the pointers later
    memcpy(&magicnet_signed_data(packet_out)->payload.login_protocol_iden, &magicnet_signed_data(packet_in)->payload.login_protocol_iden, sizeof(&magicnet_signed_data(packet_out)->payload.login_protocol_iden));

    // All has been copied except hte peers
    struct vector *known_peers_in = magicnet_signed_data(packet_in)->payload.login_protocol_iden.known_peers;
    struct vector *new_peer_vec = vector_create(sizeof(struct magicnet_peer_information *));
    if (!new_peer_vec)
    {
        magicnet_log("%s out of memory!\n", __FUNCTION__);
        return;
    }

    vector_set_peek_pointer(known_peers_in, 0);
    struct magicnet_peer_information *peer_in = vector_peek_ptr(known_peers_in);
    while (peer_in)
    {
        struct magicnet_peer_information *peer_out = calloc(1, sizeof(struct magicnet_peer_information));
        if (!peer_out)
        {
            magicnet_log("%s out of memory\n", __FUNCTION__);
            break;
        }
        // God the new peer? great overwrite it with the peer data and push to the new vector.
        memcpy(peer_out, peer_in, sizeof(*peer_out));
        // Push it to the new  vector.
        vector_push(new_peer_vec, &peer_out);
        peer_in = vector_peek_ptr(known_peers_in);
    }

    // Great we have the duplicate vector, lets assign to the packet out
    magicnet_signed_data(packet_out)->payload.login_protocol_iden.known_peers = new_peer_vec;

    // DONE!
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
    int res = 0;
    memcpy(packet_out, packet_in, sizeof(struct magicnet_packet));
    if (magicnet_signed_data(packet_in)->flags & MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE)
    {
        magicnet_signed_data(packet_out)->my_certificate = magicnet_council_certificate_clone(magicnet_signed_data(packet_in)->my_certificate);
    }

    // We must clone the not sent buffer
    if (packet_in->not_sent.tmp_buf)
    {
        packet_out->not_sent.tmp_buf = buffer_clone(packet_in->not_sent.tmp_buf);
    }
    switch (magicnet_signed_data(packet_in)->type)
    {

    case MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET:
        magicnet_copy_packet_login_protocol_identification_packet(packet_out, packet_in);
        break;
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

    case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        magicnet_copy_packet_verifier_signup(packet_out, packet_in);
        break;
    case MAGICNET_PACKET_TYPE_EVENTS_POLL:
        magicnet_copy_packet_events_poll(packet_out, packet_in);
        break;

    case MAGICNET_PACKET_TYPE_EVENTS_RES:
        magicnet_copy_packet_events_res(packet_out, packet_in);
        break;
    case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_RESPONSE:
        magicnet_copy_packet_transaction_list_response(packet_out, packet_in);
        break;
    }

    // Prove the integrity and nothing was damaged
    if (magicnet_packet_hashed(packet_in))
    {
        magicnet_packet_hash(packet_out);
        if (memcmp(packet_out->datahash, packet_in->datahash, sizeof(packet_out->datahash)) != 0)
        {
            magicnet_log("%s BUG: Fix copy_packet data integreity broken\n", __FUNCTION__);
            res = -1;
            goto out;
        }
        else
        {
            magicnet_log("%s cloned packet correctly\n", __FUNCTION__);
        }
    }
out:
    return res;
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
    client->packets_for_client.total++;
out:
    return res;
}

/**
 * Flushes all the packets to relay straight to the I/O stream of the client.
 *
 * NOTE: Theres clear signs of unsigned pakcets being flushed resulting in the peer
 * terminating the connection, look into this only localhost can accept such packets.
 *
 */
int magicnet_client_packets_for_client_flush(struct magicnet_client *client)
{
    int res = 0;

    for (int i = 0; i < client->packets_for_client.total; i++)
    {
        struct magicnet_packet *packet = magicnet_client_next_packet_to_relay(client);
        if (!packet)
        {
            // brak might be better but im not sure yet..
            // possibly the packets are scattered around the indexes.
            continue;
        }

        res = magicnet_client_write_packet(client, packet, 0);
        if (res < 0)
        {
            // I/O problem we are done.
            break;
        }

        // We are done with the packet itsprocessed..
        magicnet_client_relay_packet_finished(client, packet);
    }

    client->packets_for_client.pos_read = 0;
    client->packets_for_client.pos_write = 0;
    client->packets_for_client.total = 0;

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

// int magicnet_client_process_packet_poll_packets(struct magicnet_client *client, struct magicnet_packet *packet)
// {
//     int res = 0;
//     magicnet_log("%s polling packet request\n", __FUNCTION__);
//     struct magicnet_packet *packet_to_process = NULL;
//     struct magicnet_packet *packet_to_send = NULL;
//     magicnet_server_lock(client->server);
//     packet_to_process = magicnet_client_get_next_packet_to_process(client);
//     magicnet_server_unlock(client->server);

//     if (!packet_to_process)
//     {
//         packet_to_send = magicnet_packet_new();
//         magicnet_signed_data(packet_to_send)->type = MAGICNET_PACKET_TYPE_EMPTY_PACKET;
//         res = magicnet_client_write_packet(client, packet_to_send, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
//         magicnet_log("%s Not found\n", __FUNCTION__);
//         goto out;
//     }

//     magicnet_log("%s packet found\n", __FUNCTION__);
//     // We have a packet they could use.. Lets send it there way.. We wont sign it as it should already be signed.
//     res = magicnet_client_write_packet(client, packet_to_process, 0);
//     if (res < 0)
//     {
//         goto out;
//     }

// out:
//     // Free the internal pointers of this packet since we don't care about it anymore as its been sent.
//     // Note dont use packet_free as this packet is declared in an array its not a pointer. It will
//     // be reused for a different packet once marked as processed.
//     if (packet_to_process)
//     {
//         magicnet_free_packet_pointers(packet_to_process);
//         magicnet_client_mark_packet_processed(client, packet_to_process);
//     }
//     if (packet_to_send)
//     {
//         magicnet_packet_free(packet_to_send);
//     }
//     return res;
// }

int magicnet_client_process_user_defined_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    // We got to lock this server
    magicnet_server_lock(client->server);

    // We must find all the clients of the same program name
    // relay to our local connections..
    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        struct magicnet_client *cli = &client->server->clients[i];
        if (!magicnet_client_in_use(client))
        {
            continue;
        }

        // We relay to the local clients, they shall handle the rest.
        magicnet_relay_packet_to_client(client, packet);
    }

    // Relay to the internet
    magicnet_server_add_packet_to_relay(client->server, packet);

out:
    magicnet_server_unlock(client->server);
    return res;
}

/**
 * DEPRECATED REPLACED BY A NEW SYSTEM WHERE THE CLIENT THREAD ITS SELF
 * ATTEMPTS TO EXTRACT THOSE PACKETS AND WRITE TO ITS OWN SOCKET.
 */
// int magicnet_client_process_server_sync_packet(struct magicnet_client *client, struct magicnet_packet *packet)
// {
//     int res = 0;
//     struct magicnet_packet *packet_to_relay = magicnet_packet_new();
//     bool has_packet_to_relay = false;
//     // We got to lock this server
//     magicnet_server_lock(client->server);
//     struct magicnet_packet *tmp_packet = magicnet_client_next_packet_to_relay(client);
//     if (tmp_packet)
//     {
//         magicnet_copy_packet(packet_to_relay, tmp_packet);
//         has_packet_to_relay = true;
//         magicnet_client_relay_packet_finished(client, tmp_packet);
//     }
//     magicnet_server_unlock(client->server);

//     if (has_packet_to_relay)
//     {
//         // We have a packet lets send to the client
//         int flags = 0;
//         if (MAGICNET_nulled_signature(&packet_to_relay->signature) &&
//             magicnet_signed_data(packet_to_relay)->flags & MAGICNET_PACKET_FLAG_MUST_BE_SIGNED)
//         {
//             // We got to sign this packet we are about to relay.
//             flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
//         }
//         res = magicnet_client_write_packet(client, packet_to_relay, flags);
//         if (res < 0)
//         {
//             goto out;
//         }
//     }
//     else
//     {
//         // No packet to relay? Then we need to send back a not found packet
//         magicnet_signed_data(packet_to_relay)->type = MAGICNET_PACKET_TYPE_NOT_FOUND;
//         // Since this is a packet of our creation it also must be signed.. We aren't relaying
//         // anything new here.
//         res = magicnet_client_write_packet(client, packet_to_relay, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
//         if (res < 0)
//         {
//             goto out;
//         }
//     }

//     // Do we also have a packet from them?
//     if (magicnet_signed_data(packet)->payload.sync.flags & MAGICNET_TRANSMIT_FLAG_EXPECT_A_PACKET)
//     {
//         res = magicnet_server_poll_process(client, magicnet_signed_data(packet)->payload.sync.packet);
//         if (res < 0)
//         {
//             goto out;
//         }
//     }

// out:
//     magicnet_packet_free(packet_to_relay);
//     return res;
// }

/**
 * This function rebuilds coin send transactions
 */
int magicnet_transaction_packet_coin_send_rebuild(struct block_transaction *transaction)
{
    int res = 0;
    // Cast the transaction data to a coin send transaction
    struct block_transaction_money_transfer money_transfer_transaction;
    res = magicnet_money_transfer_data(transaction, &money_transfer_transaction);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_wallet_calculate_balance(&money_transfer_transaction.recipient_key, &money_transfer_transaction.new_balances.recipient_balance);
    if (res < 0)
    {
        magicnet_log("%s problem calculating balance for recipient", __FUNCTION__);
        goto out;
    }

    res = magicnet_wallet_calculate_balance(&transaction->key, &money_transfer_transaction.new_balances.sender_balance);
    if (res < 0)
    {
        magicnet_log("%s problem calculating balance for sender", __FUNCTION__);
        goto out;
    }

    money_transfer_transaction.new_balances.sender_balance -= money_transfer_transaction.amount;
    money_transfer_transaction.new_balances.recipient_balance += money_transfer_transaction.amount;

    // The target key of the transaction will be the recipient key of the money transfer transaction.
    memcpy(&transaction->target_key, &money_transfer_transaction.recipient_key, sizeof(transaction->target_key));

    // Write the changed data back to the transaction
    res = magicnet_money_transfer_data_write(transaction, &money_transfer_transaction);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_transaction_rebuild_certificate_transfer(struct block_transaction *transaction)
{
    int res = 0;

    // These two will be true later on if the certificate objects were provided by us rather than the transaction passed to this function
    bool built_our_certificate = false;
    bool built_our_unsigned_certificate = false;
    struct block_transaction_council_certificate_initiate_transfer_request council_certificate_transfer;
    magicnet_log("%s rebuilding certificate transfer transaction\n", __FUNCTION__);
    res = magicnet_read_transaction_council_certificate_initiate_transfer_data(transaction, &council_certificate_transfer);
    if (res < 0)
    {
        goto out;
    }

    if (!council_certificate_transfer.current_certificate)
    {
        magicnet_log("%s current certificate object to transfer was not provided so we will resolve it on our local server\n", __FUNCTION__);
        struct magicnet_council_certificate *certificate = magicnet_council_certificate_load(council_certificate_transfer.certificate_to_transfer_hash);
        if (!certificate)
        {
            magicnet_log("%s failed to load certificate to transfer\n", __FUNCTION__);
            res = -1;
            goto out;
        }
        council_certificate_transfer.current_certificate = certificate;
        built_our_certificate = true;
    }

    // DO we own the certificate
    if (!key_cmp(&council_certificate_transfer.current_certificate->owner_key, MAGICNET_public_key()))
    {
        magicnet_log("%s certificate to transfer is not owned by us\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (!council_certificate_transfer.new_unsigned_certificate)
    {
        magicnet_log("%s new unsigned certificate  was not provided so we will generate one \n", __FUNCTION__);
        struct magicnet_council_certificate *new_certificate = NULL;
        // We want to make a self transfer signed by us to transfer the certificate to the new owner
        res = magicnet_council_certificate_self_transfer(council_certificate_transfer.current_certificate, &new_certificate, &council_certificate_transfer.new_owner_key, time(NULL), time(NULL) + MAGICNET_DEFAULT_COUNCIL_CERTIFICATE_LIFETIME);
        if (res < 0)
        {
            magicnet_log("%s failed to generate new certificate\n", __FUNCTION__);
            goto out;
        }
        council_certificate_transfer.new_unsigned_certificate = new_certificate;
        built_our_unsigned_certificate = true;
    }

    // Let's write the data back to the transaction data
    res = magicnet_certificate_transfer_data_write(transaction, &council_certificate_transfer);
out:
    if (res < 0)
    {
        magicnet_log("%s failed to rebuild certificate transfer transaction\n", __FUNCTION__);
        // free the certificate objects if we provided them
        if (built_our_certificate &&
            council_certificate_transfer.current_certificate)
        {
            magicnet_council_certificate_free(council_certificate_transfer.current_certificate);
        }
        if (built_our_unsigned_certificate &&
            council_certificate_transfer.new_unsigned_certificate)
        {
            magicnet_council_certificate_free(council_certificate_transfer.new_unsigned_certificate);
        }
    }
    return res;
}
/**
 * This function rebuilds the transaction packet making changes where needed. It only rebuilds it
 * for built in transaction types built into the protocol such as money transfers.
 */
int magicnet_transaction_rebuild(struct block_transaction *transaction)
{
    int res = 0;
    transaction->key = *MAGICNET_public_key();
    switch (transaction->type)
    {
    case MAGICNET_TRANSACTION_TYPE_COIN_SEND:
        res = magicnet_transaction_packet_coin_send_rebuild(transaction);
        break;
    case MAGICNET_TRANSACTION_TYPE_INITIATE_CERTIFICATE_TRANSFER:
        res = magicnet_transaction_rebuild_certificate_transfer(transaction);
        break;
    }

out:
    return res;
}
/**
 * This function is only used for localhost clients who send transactions to their local server.
 * Hence why it is signed and sent to other peers. Since local programs arent aware of our private keys.
 */
int magicnet_client_process_transaction_send_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    magicnet_server_lock(client->server);

    // Add the transaction to the awaiting transactions vector
    res = magicnet_server_awaiting_transaction_add(client->server, magicnet_signed_data(packet)->payload.transaction_send.transaction);
    if (res < 0)
    {
        // show error message
        magicnet_log("%s failed to add transaction to awaiting transactions vector\n", __FUNCTION__);
        goto out;
    }

out:
    magicnet_server_unlock(client->server);
    return res;
}

int magicnet_client_process_request_block_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct magicnet_packet *packet_out = NULL;

    struct block *block = block_load(magicnet_signed_data(packet)->payload.request_block.request_hash);
    if (!block)
    {
        goto out;
    }

    // Let's load whatever is missing as the block is only lazily loaded
    res = block_load_fully(block);
    if (res < 0)
    {
        // Show error
        magicnet_log("%s failed to load block fully\n", __FUNCTION__);
        goto out;
    }

    magicnet_log("%s request block packet initiated. Request for block with hash %s\n", __FUNCTION__, magicnet_signed_data(packet)->payload.request_block.request_hash);
    packet_out = magicnet_packet_new();
    magicnet_signed_data(packet_out)->type = MAGICNET_PACKET_TYPE_REQUEST_BLOCK_RESPONSE;
    magicnet_signed_data(packet_out)->flags = MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    memcpy(magicnet_signed_data(packet_out)->payload.request_block_response.request_hash, magicnet_signed_data(packet)->payload.request_block.request_hash, sizeof(magicnet_signed_data(packet_out)->payload.request_block_response.request_hash));
    magicnet_signed_data(packet_out)->payload.request_block_response.signal_id = magicnet_signed_data(packet)->payload.request_block_response.signal_id;

    magicnet_server_relay_packet_to_client_key(client->server, &packet->pub_key, packet_out);
out:
    if (packet_out)
    {
        magicnet_packet_free(packet_out);
    }
    return res;
}

int magicnet_client_process_request_block_response_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    // Get the signal that is waiting on the request block response.
    struct magicnet_signal *signal = magicnet_signal_get_by_id_and_type("downloader-req-block-signal", magicnet_signed_data(packet)->payload.request_block_response.signal_id);
    if (!signal)
    {
        // todo ban the client for trying to request a fake signal.. Could be an attack attempt ban them.
        res = -1;
        goto out;
    }

    // Post the signal so that the downloader can continue at cdownloader.c
    magicnet_signal_post_for_signal(magicnet_signed_data(packet)->payload.request_block_response.signal_id, "downloader-req-block-signal", &packet->pub_key, sizeof(struct key), MAGICNET_SIGNAL_FLAG_CLONE_DATA_ON_POST);

out:
    return res;
}

int magicnet_client_process_transaction_list_request_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct block_transaction_group *transaction_group = block_transaction_group_new();
    struct magicnet_packet *packet_out = magicnet_packet_new();
    struct magicnet_transactions_request *request = &magicnet_signed_data(packet)->payload.transaction_list_request.req;
    size_t total_transactions = 0;
    struct vector *transactions_vec = vector_create(sizeof(struct block_transaction *));
    // Entry message
    magicnet_log("%s transaction list request\n", __FUNCTION__);

    // We want to go through all possible transactions
    while ((res = block_transactions_load(request, transaction_group)) >= 0)
    {
        // Fill the transactions in the packet
        total_transactions += transaction_group->total_transactions;
        for (int i = 0; i < transaction_group->total_transactions; i++)
        {
            struct block_transaction *transaction = block_transaction_clone(transaction_group->transactions[i]);
            vector_push(transactions_vec, &transaction);
        }

        block_transaction_group_free(transaction_group);
        transaction_group = block_transaction_group_new();
    }

    // Create a response packet
    magicnet_signed_data(packet_out)->type = MAGICNET_PACKET_TYPE_TRANSACTION_LIST_RESPONSE;
    magicnet_signed_data(packet_out)->flags = MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet_out)->payload.transaction_list_response.req = *request;
    magicnet_signed_data(packet_out)->payload.transaction_list_response.total_transactions = total_transactions;
    magicnet_signed_data(packet_out)->payload.transaction_list_response.transactions = transactions_vec;

    // Send the packet back to the client
    res = magicnet_client_write_packet(client, packet_out, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        // error message
        magicnet_log("%s failed to write packet\n", __FUNCTION__);
        goto out;
    }

out:

    block_transaction_group_free(transaction_group);
    magicnet_packet_free(packet_out);
    return res;
}

int magicnet_client_process_packet_events_poll(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct vector *events_vec = vector_create(sizeof(struct magicnet_event *));
    struct magicnet_packet *packet_out = magicnet_packet_new();
    // How many events does the requestor want?
    size_t total_events = magicnet_signed_data(packet)->payload.events_poll.total;
    magicnet_server_lock(client->server);
    size_t total_events_to_send = magicnet_client_total_known_events(client);
    if (total_events_to_send > total_events)
    {
        total_events_to_send = total_events;
    }
    magicnet_server_unlock(client->server);

    // Okay lets send any events they are waiting for
    for (size_t i = 0; i < total_events_to_send; i++)
    {
        struct magicnet_event *event_to_send = NULL;
        magicnet_server_lock(client->server);
        res = magicnet_client_pop_event(client, &event_to_send);
        if (res < 0)
        {
            magicnet_server_unlock(client->server);
            goto out;
        }
        magicnet_server_unlock(client->server);

        vector_push(events_vec, &event_to_send);
    }

    // Craft the packet ;)
    magicnet_signed_data(packet_out)->type = MAGICNET_PACKET_TYPE_EVENTS_RES;
    magicnet_signed_data(packet_out)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet_out)->payload.events_poll_res.total = total_events_to_send;
    magicnet_signed_data(packet_out)->payload.events_poll_res.events = events_vec;
    res = magicnet_client_write_packet(client, packet_out, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        goto out;
    }
out:
    magicnet_events_vector_free(events_vec);
    // So it doesnt get deleted again.. when we free the packet.
    magicnet_signed_data(packet_out)->payload.events_poll_res.events = NULL;
    magicnet_packet_free(packet_out);
    return res;
}

int magicnet_client_process_request_and_respond(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct magicnet_packet *packet_to_respond = magicnet_packet_new();
    int request_type = magicnet_signed_data(packet)->payload.request_and_respond.type;

    magicnet_log("%s local client has requested information type=%i we will find the handler and respond with the information\n", __FUNCTION__, request_type);

    bool response_received = false;
    struct request_and_respond_input_data *input_data = magicnet_signed_data(packet)->payload.request_and_respond.input_data;
    struct request_and_respond_output_data *output_data = NULL;
    // Lets get the handler
    REQUEST_RESPONSE_HANDLER_FUNCTION handler = reqres_get_handler(request_type);
    if (handler)
    {

        res = handler(magicnet_signed_data(packet)->payload.request_and_respond.input_data, &output_data);
        if (res >= 0 && output_data)
        {
            response_received = true;
        }
    }

    if (response_received)
    {

        // Log that the information was received and is being sent back to the client
        magicnet_log("%s information received and being sent back to client\n", __FUNCTION__);

        magicnet_signed_data(packet_to_respond)->type = MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND_RESPONSE;
        magicnet_signed_data(packet_to_respond)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
        magicnet_signed_data(packet_to_respond)->payload.request_and_respond_response.type = request_type;

        // No need to clone the output data as we created the memory, it will be freed when the packet is freed.
        magicnet_signed_data(packet_to_respond)->payload.request_and_respond_response.output_data = output_data;
        // We have to clone the input data as it belongs to the input packet
        magicnet_signed_data(packet_to_respond)->payload.request_and_respond_response.input_data = magicnet_reqres_input_data_clone(input_data);

        res = magicnet_client_write_packet(client, packet_to_respond, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
        if (res < 0)
        {
            goto out;
        }
    }
    else
    {
        // Log that either the handler could not be found or the handler could not locate the information
        magicnet_log("%s failed to obtain information from handler with request type %i\n", __FUNCTION__, request_type);

        // Yeah if we couldn't resolve the request and respond then its a not found packet to send..
        magicnet_signed_data(packet_to_respond)->type = MAGICNET_PACKET_TYPE_NOT_FOUND;
        // Since this is a packet of our creation it also must be signed.. We aren't relaying
        // anything new here.
        res = magicnet_client_write_packet(client, packet_to_respond, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
        if (res < 0)
        {
            goto out;
        }
    }

out:
    magicnet_packet_free(packet_to_respond);
    return res;
}

int magicnet_client_process_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    assert(client->server);
    int res = 0;
    if (magicnet_signed_data(packet)->flags & MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE)
    {
        if (!magicnet_signed_data(packet)->my_certificate)
        {
            magicnet_log("%s packet contains my council certificate but the certificate is null\n", __FUNCTION__);
            res = -1;
            return res;
        }

        if (!key_cmp(&magicnet_signed_data(packet)->my_certificate->owner_key, &packet->pub_key))
        {
            magicnet_log("%s packet contains council certificate but the certificate owner key does not match the packet key that signed the packet therefore someone is pretending to own a certificate they dont hold\n", __FUNCTION__);
            res = -1;
            return res;
        }

        // In cases where a council certificate is sent we must verify the signature of the packet there will be no
        // signing exemption even if its localhost
        if (!magicnet_client_verify_packet_was_signed(packet))
        {
            magicnet_log("%s the packet was not signed correctly\n", __FUNCTION__);
            res = -1;
            return res;
        }
    }

    if (!(client->flags & MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST))
    {
        // Non local host clients have access to only one packet type
        switch (magicnet_signed_data(packet)->type)
        {

            // DEPRECATED
            // case MAGICNET_PACKET_TYPE_SERVER_SYNC:
            //     res = magicnet_client_process_server_sync_packet(client, packet);
            //     break;

        case MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_REQUEST:
            res = magicnet_client_process_block_super_download_request_packet(client, packet);
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
            // case MAGICNET_PACKET_TYPE_POLL_PACKETS:
            //     res = magicnet_client_process_packet_poll_packets(client, packet);
            //     break;

        case MAGICNET_PACKET_TYPE_USER_DEFINED:
            res = magicnet_client_process_user_defined_packet(client, packet);
            break;

            // DEPRECATED
            // case MAGICNET_PACKET_TYPE_SERVER_SYNC:
            //     res = magicnet_client_process_server_sync_packet(client, packet);
            //     break;

        case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
            res = magicnet_client_process_transaction_send_packet(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_TRANSACTION_LIST_REQUEST:
            res = magicnet_client_process_transaction_list_request_packet(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_EVENTS_POLL:
            res = magicnet_client_process_packet_events_poll(client, packet);
            break;

        case MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND:
            res = magicnet_client_process_request_and_respond(client, packet);
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

    return res;
}

int magicnet_client_manage_next_packet(struct magicnet_client *client)
{
    int res = 0;
    struct magicnet_packet *packet = magicnet_recv_next_packet(client, &res);
    if (!packet)
    {
        magicnet_log("%s failed to receive new packet from client\n", __FUNCTION__);
        res = MAGICNET_ERROR_CRITICAL_ERROR;
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
        magicnet_packet_free(packet);
    }
    return res;
}

int magicnet_server_push_event(struct magicnet_server *server, struct magicnet_event *event)
{
    int res = 0;
    for (int i = 0; i < MAGICNET_MAX_INCOMING_CONNECTIONS; i++)
    {
        struct magicnet_client *client = &server->clients[i];
        if (magicnet_connected(client) && magicnet_is_localhost(client) &&
            strncmp(client->program_name, "magicnet", strlen("magicnet")) != 0)
        {
            // Alright lets push the event to this thing.
            magicnet_client_push_event(client, event);
        }
    }

    return res;
}

int magicnet_client_entry_protocol_read_known_clients(struct magicnet_client *client, struct magicnet_packet *packet)
{

    int res = 0;

    // We will always have the known peers vector created
    // even when theres zero peers
    struct vector *known_peer_vector = vector_create(sizeof(struct magicnet_peer_information *));
    magicnet_signed_data(packet)->payload.login_protocol_iden.known_peers = known_peer_vector;
    if (!known_peer_vector)
    {
        res = MAGICNET_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    // Lets read all the IPS until we get a NULL.
    int total_peers = magicnet_read_int(client, NULL);
    if (total_peers <= 0)
    {
        res = total_peers;
        goto out;
    }

    for (int i = 0; i < total_peers; i++)
    {
        struct magicnet_peer_information *peer_info = calloc(1, sizeof(struct magicnet_peer_information));
        if (!peer_info)
        {
            res = MAGICNET_ERROR_OUT_OF_MEMORY;
            goto out;
        }

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

        char ip_str[MAGICNET_MAX_IP_STRING_SIZE] = {0};
        // Convert the in_addr to a string
        inet_ntop(AF_INET, &s_addr, ip_str, INET_ADDRSTRLEN);
        peer_info->key = key;
        strncpy(peer_info->ip_address, ip_str, MAGICNET_MAX_IP_STRING_SIZE);

        // push to the vector
        vector_push(known_peer_vector, &peer_info);
    }

out:
    return res;
}

int magicnet_read_peer_info(struct magicnet_client *client, int *peer_info_state_out, struct magicnet_peer_information *peer_info, char *hash_of_peer_info_out, struct signature *signature_out, struct buffer *store_in_buf)
{
    int res = 0;
    res = magicnet_read_int(client, store_in_buf);
    *peer_info_state_out = res;
    // If theres no peer info provided then leave.
    if (res < 0 || res == MAGICNET_ENTRY_PROTOCOL_NO_PEER_INFO_PROVIDED)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, &peer_info->key, sizeof(peer_info->key), store_in_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, &peer_info->name, sizeof(peer_info->name), store_in_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, peer_info->email, sizeof(peer_info->email), store_in_buf);
    if (res < 0)
    {
        goto out;
    }

    // Now lets read the hash of the data and the signature. Then we will verify it was sent by the key holder.
    res = magicnet_read_bytes(client, hash_of_peer_info_out, SHA256_STRING_LENGTH, store_in_buf);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_read_bytes(client, signature_out, sizeof(*signature_out), store_in_buf);
    if (res < 0)
    {
        goto out;
    }

out:
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

bool magicnet_client_login_protocol_sent(struct magicnet_client *client)
{
    return (client->states.flags & MAGICNET_CLIENT_STATE_FLAG_WE_SENT_LOGIN_PROTOCOL);
}

bool magicnet_client_login_protocol_door_open_sent(struct magicnet_client *client)
{
    return (client->states.flags & MAGICNET_CLIENT_STATE_FLAG_DOOR_OPEN_SENT);
}

bool magicnet_client_login_protocol_door_open_recv(struct magicnet_client *client)
{
    return (client->states.flags & MAGICNET_CLIENT_STATE_FLAG_DOOR_OPEN_RECV);
}

bool magicnet_client_door_opened(struct magicnet_client *client)
{
    return (client->states.flags & MAGICNET_CLIENT_STATE_FLAG_DOOR_OPENED);
}

bool magicnet_client_login_protocol_received(struct magicnet_client *client)
{
    return client->states.flags & MAGICNET_CLIENT_STATE_FLAG_PEER_COMPLETED_LOGIN_PROTOCOL;
}

bool magicnet_client_login_protocol_completed(struct magicnet_client *client)
{
    return magicnet_client_login_protocol_sent(client) &&
           magicnet_client_login_protocol_received(client);
}

bool magicnet_peer_information_null(struct magicnet_peer_information *peer_info)
{
    struct magicnet_peer_information null_peer_info = {0};
    return memcmp(peer_info, &null_peer_info, sizeof(struct magicnet_peer_information)) == 0;
}

int magicnet_client_preform_entry_protocol_post_read_process_peer(struct magicnet_client *client, struct login_protocol_identification_peer_info *iden_peer_info)
{
    int res = 0;
    struct buffer *signed_data_buffer = buffer_create();
    if (!signed_data_buffer)
    {
        res = -ENOMEM;
        goto out;
    }

    // Write to the signed data buffer
    // we need to hash it later and comapre them.
    buffer_write_bytes(signed_data_buffer, iden_peer_info->info.name, sizeof(iden_peer_info->info.name));
    buffer_write_bytes(signed_data_buffer, iden_peer_info->info.email, sizeof(iden_peer_info->info.email));

    // Verify that the peer information was signed by the peer himself
    // we don't want people pretending to be others, signature is required.
    char *hash_of_info = iden_peer_info->hash_of_info;
    struct signature *signature = &iden_peer_info->signature;
    struct magicnet_peer_information *peer_info = &iden_peer_info->info;
    res = public_verify(&peer_info->key, hash_of_info, sizeof(iden_peer_info->hash_of_info), signature);
    if (res < 0)
    {
        magicnet_log("%s the data provided was not signed by the public key given to us.\n", __FUNCTION__);
        goto out;
    }

    // Let's rehash to ensure our hash matches the one they provided to us
    // if it doesn't match then it was not signed by them they lied
    char our_hash_of_data[SHA256_STRING_LENGTH];
    sha256_data(buffer_ptr(signed_data_buffer), our_hash_of_data, buffer_len(signed_data_buffer));
    if (memcmp(hash_of_info, our_hash_of_data, sizeof(our_hash_of_data)) != 0)
    {
        magicnet_log("%s the hash provided does not match the hash we calculated\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (strlen(peer_info->name) == 0)
    {
        // No name provided then this peer is anonymous.
        strncpy(peer_info->name, "Anonymous", sizeof(peer_info->name));
    }
    // Now we have proved this is a legit peer lets set the
    // peer info into the client information.
    client->peer_info = *peer_info;

out:
    return res;
}
int magicnet_client_preform_entry_protocol_post_read_process(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    // We are processing a read entry protocol identification packet..
    struct magicnet_peer_information *peer_info = &magicnet_signed_data(packet)->payload.login_protocol_iden.peer_info.info;
    // Was peer information actually provided?
    if (!magicnet_peer_information_null(peer_info))
    {

        // Let's validate this peer is who we think they are
        res = magicnet_client_preform_entry_protocol_post_read_process_peer(client, &magicnet_signed_data(packet)->payload.login_protocol_iden.peer_info);
        if (res < 0)
        {
            magicnet_log("%s the peer provided to us is FAKE and has not signed its self correctly.\n", __FUNCTION__);
            goto out;
        }

        // Okay we have peer information save it locally so we know who this person is
        // when they communicate with us forward from now.
        // We only want to save the peer info if we are a server client
        // i suggest making a new function for the client side #
        // to avoid these messy if statements
        if (client->server)
        {
            res = magicnet_save_peer_info(peer_info);
            if (res < 0)
            {
                goto out;
            }
        }
        // This particular peer is the client whos connected
        // therefore lets setup that client information so hes identifiyable for his session
        memcpy(&client->peer_info, peer_info, sizeof(client->peer_info));

        // Peer doesn't get to choose his own IP we will use the one we know to be true
        // based on the connected socket.
        char *ip_address = inet_ntoa(client->client_info.sin_addr);
        strncpy(client->peer_info.ip_address, ip_address, sizeof(client->peer_info.ip_address));
    }

    // Peer info now copied into the client so hes identifyable throughout
    // the session..

    // let's loop through the peers they have told us about, to expand our own network
    struct vector *peer_vector = magicnet_signed_data(packet)->payload.login_protocol_iden.known_peers;
    vector_set_peek_pointer(peer_vector, 0);

    // We only care about the peer info if we are a server client
    // WARNING: we need to refactor this into another function i guess..
    if (client->server)
    {

        struct magicnet_peer_information *vec_peer_info = vector_peek_ptr(peer_vector);
        while (vec_peer_info)
        {
            // Let's save this peer..
            magicnet_save_peer_info(vec_peer_info);
            // We won't check for errors, as theres plenty of others that may save correctlyl.
            peer_info = vector_peek_ptr(peer_vector);
        }
    }

out:
    if (res >= 0)
    {
        // All okay? then the peer completed the login protocol on our side
        // The peer successfully authenticated themselves to us.
        client->states.flags |= MAGICNET_CLIENT_STATE_FLAG_PEER_COMPLETED_LOGIN_PROTOCOL;

        magicnet_log("%s peer has completed his side of the login protocol\n", __FUNCTION__);
    }
    return res;
}
int magicnet_client_preform_entry_protocol_read(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    // Now lets see if we got the signature back
    int signature = 0;
    int login_protocol_size = 0;
    int signal_id = 0;
    int communication_flags = 0;

    signature = magicnet_read_int(client, NULL);
    if (signature < 0)
    {
        res = -1;
        goto out;
    }

    if (signature != MAGICNET_ENTRY_SIGNATURE)
    {
        // Bad signature
        res = -1;
        goto out;
    }

    // Is there a signal we need to invoke
    signal_id = magicnet_read_int(client, NULL);
    if (signal_id < 0)
    {
        res = signal_id;
        goto out;
    }

    communication_flags = magicnet_read_int(client, NULL);
    if (communication_flags < 0)
    {
        res = communication_flags;
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

    // Lets read what the client says our ip address is.
    res = magicnet_read_bytes(client, &client->my_ip_address_to_client, sizeof(client->my_ip_address_to_client), NULL);
    if (res < 0)
    {
        goto out;
    }

    int peer_info_state = -1;

    // Read the peer information into the packet for later processing..
    struct magicnet_peer_information *peer_info_in = &magicnet_signed_data(packet)->payload.login_protocol_iden.peer_info;
    char *peer_info_hash_in = magicnet_signed_data(packet)->payload.login_protocol_iden.peer_info.hash_of_info;
    struct signature *peer_info_sig_in = &magicnet_signed_data(packet)->payload.login_protocol_iden.peer_info.signature;

    res = magicnet_read_peer_info(client, &peer_info_state, peer_info_in, peer_info_hash_in, peer_info_sig_in, packet->not_sent.tmp_buf);

    if (res < 0)
    {
        goto out;
    }

    res = magicnet_client_entry_protocol_read_known_clients(client, packet);
    if (res < 0)
    {
        goto out;
    }

out:

    return res;
}

int magicnet_client_preform_entry_protocol_write(struct magicnet_client *client, const char *program_name, int communication_flags, int signal_id)
{
    int res = 0;
    res = magicnet_write_int(client, MAGICNET_ENTRY_SIGNATURE, NULL);
    if (res < 0)
    {
        goto out;
    }

    // 0 = no signal
    res = magicnet_write_int(client, signal_id, NULL);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_write_int(client, communication_flags, NULL);
    if (res < 0)
    {
        goto out;
    }

    char tmp_program_name[MAGICNET_PROGRAM_NAME_SIZE] = {0};
    strncpy(tmp_program_name, program_name, sizeof(tmp_program_name));
    res = magicnet_write_bytes(client, tmp_program_name, sizeof(tmp_program_name), NULL);
    if (res < 0)
    {
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

    // Write our client key
    res = magicnet_write_peer_info(client);
    if (res < 0)
    {
        goto out;
    }

    // // Okay let us send the ip addresses we are aware of
    res = magicnet_client_entry_protocol_write_known_clients(client);
    if (res < 0)
    {
        goto out;
    }

    client->states.flags |= MAGICNET_CLIENT_STATE_FLAG_WE_SENT_LOGIN_PROTOCOL;
    magicnet_log("%s magic net entry protocol was written\n", __FUNCTION__);
out:
    return res;
}

bool magicnet_client_needs_ping(struct magicnet_client *client)
{
    return time(NULL) - client->last_packet_received >= MAGICNET_CLIENT_FORCE_PING_SECONDS;
}

bool magicnet_client_must_send_ping(struct magicnet_client *client)
{
    return time(NULL) - client->last_packet_sent >= MAGICNET_CLIENT_FORCE_PING_SECONDS;
}

int magicnet_ping(struct magicnet_client *client)
{
    magicnet_log("%s sending ping..\n", __FUNCTION__);
    int res = 0;
    struct magicnet_packet *packet = magicnet_packet_new_init(MAGICNET_PACKET_TYPE_PING);
    if (!packet)
    {
        res = MAGICNET_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    res = magicnet_client_write_packet(client, packet, 0);
out:
    return res;
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

bool magicnet_server_verifier_is_signed_up(struct magicnet_server *server, struct magicnet_council_certificate *certificate)
{
    vector_set_peek_pointer(server->next_block.signed_up_verifiers, 0);
    struct magicnet_council_certificate *vec_certificate = vector_peek_ptr(server->next_block.signed_up_verifiers);
    while (vec_certificate)
    {
        if (memcmp(certificate->hash, vec_certificate->hash, sizeof(certificate->hash)) == 0)
        {
            return true;
        }

        vec_certificate = vector_peek_ptr(server->next_block.signed_up_verifiers);
    }

    return false;
}

int magicnet_server_verifier_signup(struct magicnet_server *server, struct magicnet_council_certificate *certificate)
{
    int res = 0;
    if (!certificate)
    {
        magicnet_log("%s certificate is null\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Check the certificate is valid and apart of the central council before we allow signup
    if (magicnet_central_council_certificate_verify(certificate) < 0)
    {
        magicnet_log("%s certificate is invalid will not allow signup!\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Already signed up.
    if (magicnet_server_verifier_is_signed_up(server, certificate))
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
    // Clone the certificate
    struct magicnet_council_certificate *cloned_cert = magicnet_council_certificate_clone(certificate);
    vector_push(server->next_block.signed_up_verifiers, &cloned_cert);

    magicnet_log("%s new verifier signup cert_hash=%s owned_by=%s\n", __FUNCTION__, certificate->hash, certificate->owner_key.key);
out:
    return res;
}

int magicnet_server_poll_process_verifier_signup_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_log("%s client has asked to signup as a verifier for the next block: %s\n", __FUNCTION__, inet_ntoa(client->client_info.sin_addr));
    magicnet_server_lock(client->server);
    res = magicnet_server_verifier_signup(client->server, magicnet_signed_data(packet)->payload.verifier_signup.certificate);
    magicnet_server_add_packet_to_relay(client->server, packet);

    magicnet_server_unlock(client->server);
    return res;
}

int magicnet_server_process_vote_for_verifier_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    struct magicnet_council_certificate *my_certificate = magicnet_signed_data(packet)->my_certificate;
    if (!my_certificate)
    {
        magicnet_log("%s packet does not contain my council certificate so I am not able to make a vote.\n", __FUNCTION__);
        return -1;
    }

    const char *voting_for_cert_hash = magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_cert;
    magicnet_server_lock(client->server);
    int res = magicnet_server_cast_verifier_vote(client->server, my_certificate, voting_for_cert_hash);
    magicnet_server_unlock(client->server);
    if (res < 0)
    {
        magicnet_log("%s Failed to cast vote from key = %s with certificate voting for certificate hash %s\n", __FUNCTION__, &packet->pub_key.key, my_certificate->hash, voting_for_cert_hash);
    }

    magicnet_server_add_packet_to_relay(client->server, packet);
    return res;
}

void magicnet_server_set_created_block(struct magicnet_server *server, struct block *block)
{
    if (!block->blockchain_id)
    {
        // Only blocks with valid blockchain id are accepted. Show message
        magicnet_log("%s block has no blockchain id, ignoring\n", __FUNCTION__);
        return;
    }
    if (server->next_block.created_block)
    {
        magicnet_log("%s we already have a created block set, freeing and resetting\n", __FUNCTION__);
        block_free(server->next_block.created_block);
    }

    server->next_block.created_block = block_clone(block);
}

// This function will remove all our own transactions from the server queue once they have been received in a block
void magicnet_server_update_our_transaction_states(struct magicnet_server *server, struct block *block)
{
    for (int i = 0; i < block->transaction_group->total_transactions; i++)
    {
        struct self_block_transaction *self_trans = magicnet_server_awaiting_transaction_find(server, block->transaction_group->transactions[i]);
        if (self_trans)
        {
            // Yeah we got our own transaction here. One of the transactions we made is now received from the block
            // Lets deal with this.
            magicnet_server_awaiting_transaction_update_state(server, self_trans, BLOCK_TRANSACTION_STATE_COMPLETED_AND_ON_CHAIN, "Transaction Completed");
            magicnet_log("%s marked a self-signed transaction as completed as its been found in a block\n", __FUNCTION__);
        }
    }
}

bool magicnet_server_is_authorized_to_send_block(struct magicnet_server *server, struct magicnet_council_certificate *certificate)
{
    return memcmp(certificate->hash, server->authorized_block_creator.authorized_cert_hash, sizeof(certificate->hash)) == 0;
}

int magicnet_server_process_block_send_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
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
        bool authorized_sender = false;
        magicnet_server_lock(client->server);
        authorized_sender = magicnet_server_is_authorized_to_send_block(client->server, block->certificate);
        if (!authorized_sender)
        {

            magicnet_log("%s block sender is not authorized to send blocks \033[1;31mIGNORED\033[0m\n", __FUNCTION__);
            magicnet_server_unlock(client->server);

            return -1;
        }

        if (client->server->authorized_block_creator.was_block_received)
        {
#warning "come back to this as its buggy"
            // magicnet_log("%s although the block was authorized to be sent we have already received a block from this verifier this time round\n", __FUNCTION__);
            // magicnet_server_unlock(client->server);
            // return -1;
        }

        // Its a valid block so mark it as received.
        client->server->authorized_block_creator.was_block_received = true;

        magicnet_server_unlock(client->server);

        int save_res = block_save(block);
        if (save_res < 0)
        {
            if (save_res == MAGICNET_DATA_SENT_BEFORE)
            {
                block = vector_peek_ptr(magicnet_signed_data(packet)->payload.block_send.blocks);
                continue;
            }
            break;
        }

        // Lets push a new event to all clients.
        magicnet_server_lock(client->server);
        magicnet_server_push_event(client->server, &(struct magicnet_event){.type = MAGICNET_EVENT_TYPE_NEW_BLOCK, .data.new_block_event.block = block});
        magicnet_server_unlock(client->server);

        // All okay the block was saved? Great lets update the hashes and verified blocks.
        magicnet_database_blockchain_update_last_hash(block->blockchain_id, block->hash);
        magicnet_database_blockchain_increment_proven_verified_blocks(block->blockchain_id);

        // We need to remove our self transactions from the received block so we dont resend them to the network
        magicnet_server_update_our_transaction_states(client->server, block);

        struct block *previous_block = block_load(block->prev_hash);
        if (!previous_block)
        {
            // No previous block? Then we should initiate a download for all blocks with no chain
            magicnet_chain_downloader_queue_for_block_download(block->prev_hash);
        }
        block_free(previous_block);

        // Is this a new block from a verifeir? Then lets set the created block so we have proof of this
        // created block.
        magicnet_server_set_created_block(client->server, block);

        block = vector_peek_ptr(magicnet_signed_data(packet)->payload.block_send.blocks);
    }

    // We don't relay if this was a block we requested.

    magicnet_server_lock(client->server);
    magicnet_server_add_packet_to_relay(client->server, packet);
    magicnet_server_unlock(client->server);

    return 0;
}

int magicnet_server_process_transaction_send_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_server_lock(client->server);
    // Oh and we add the transaction to our own queue as well.
    res = magicnet_server_next_block_transaction_add(client->server, magicnet_signed_data(packet)->payload.transaction_send.transaction);
    if (res < 0)
    {
        magicnet_log("%s failed to add transaction to server queue\n", __FUNCTION__);
        goto out;
    }

    magicnet_log("%s added new transaction from %s\n", __FUNCTION__, packet->pub_key.key);

    // Relay to others.
    res = magicnet_server_add_packet_to_relay(client->server, packet);
    if (res < 0)
    {
        magicnet_log("%s failed to relay transaction\n", __FUNCTION__);
        goto out;
    }

out:
    magicnet_server_unlock(client->server);
    return res;
}

void *magicnet_server_client_thread(void *_client);

// int (*MAGICNET_NTHREAD_POLL_FUNCTION)(struct magicnet_nthread_action* action)

magicnet_client_state magicnet_client_get_state(struct magicnet_client *client)
{
    int res = 0;
    bool requires_new_packet = false;
    int total_bytes_on_stream = magicnet_client_unread_bytes_count(client);
    magicnet_client_state state = MAGICNET_CLIENT_STATE_IDLE_WAIT;
    if (!magicnet_client_login_protocol_sent(client))
    {
        state = MAGICNET_CLIENT_STATE_AWAITING_LOGIN_PACKET_MUST_WRITE;
        goto out;
    }

    if (!magicnet_client_login_protocol_door_open_sent(client))
    {
        state = MAGICNET_CLIENT_STATE_MUST_OPEN_DOOR;
        goto out;
    }

    if (magicnet_client_must_send_ping(client))
    {
        state = MAGICNET_CLIENT_STATE_MUST_SEND_PING;
        goto out;
    }

    // Do we have any bytes? If so maybe we can start reading a new packet
    requires_new_packet = magicnet_client_no_packet_loading(client);
    if (total_bytes_on_stream < 0)
    {
        // I/O error..
        res = total_bytes_on_stream;
        goto out;
    }

    if (requires_new_packet)
    {

        // Okay we have enough to start reading the packet
        state = MAGICNET_CLIENT_STATE_PACKET_READ_PACKET_NEW;
        goto out;
    }

    // packet_in_loading will be set if we reach here.

    // We don't require a new packet?
    // then we must already be in the process of loading one
    // lets set the state to finish loading but only when the packet is ready to be loaded
    if (total_bytes_on_stream < magicnet_signed_data(client->packet_in_loading)->expected_size)
    {
        // We still dont have enough bytes yet so we going to maintain the idle state
        // when the packt is ready to read the state will accomodate that.
        state = MAGICNET_CLIENT_STATE_IDLE_WAIT;
        goto out;
    }
    state = MAGICNET_CLIENT_STATE_PACKET_READ_PACKET_FINISH_READING;

out:
    return state;
}

int magicnet_client_poll_read_packet_new(struct magicnet_client *client)
{
    int res = 0;
    struct magicnet_packet *packet = NULL;
    res = magicnet_client_should_start_reading_new_packet(client);
    if (res < 0)
    {
        // Not being able to read a packet yet isnt an error.
        res = 0;
        goto out;
    }
    // We need to create a new packet
    packet = magicnet_packet_new();
    if (!packet)
    {
        magicnet_log("%s out of memory when making new packet\n", __FUNCTION__);
        res = MAGICNET_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    res = magicnet_client_read_new_packet(client, packet);
    if (res < 0)
    {
        magicnet_log("%s error reading new packet\n", __FUNCTION__);
        // problem
        goto out;
    }

out:
    if (res < 0)
    {
        magicnet_packet_free(packet);
        packet = NULL;
    }
    return res;
}

/**
 * Loads the rest of the packet and processes it. Only proceses if packet_out is NULL
 * if packet_out is not NULL its assumed the caller wants to deal with this packet.
 *
 * It shall not be processed by us in this regard.
 */
int magicnet_client_poll_read_packet_finish_reading_and_process(struct magicnet_client *client, PROCESS_PACKET_FUNCTION process_packet_func)
{
    int res = 0;
    if (!client->packet_in_loading)
    {
        res = MAGICNET_ERROR_CRITICAL_ERROR;
        goto out;
    }

    // Must make it local as it can be changed when packet is loaded
    struct magicnet_packet *packet = client->packet_in_loading;
    res = magicnet_client_read_packet(client, packet);
    if (res < 0)
    {
        goto out;
    }

    if (!magicnet_client_packet_loaded(packet))
    {
        // Strange erorr packet was read but isnt loaded?
        res = MAGICNET_ERROR_CRITICAL_ERROR;
        goto out;
    }

    res = magicnet_packet_allowed_to_be_processed(client, packet);
    if (res < 0)
    {
        magicnet_log("%s packet refused\n");
        goto out;
    }

    // Finally we can now process the loaded packet
    res = process_packet_func(client, packet);
    if (res < 0)
    {
        goto out;
    }

    client->last_packet_received = time(NULL);

out:
    return res;
}

int magicnet_client_poll_write_identification(struct magicnet_client *client)
{
    int res = 0;
    // Null for security, otherwise we risk sending sensitive memory
    // thats on the stack
    char program_name[MAGICNET_PROGRAM_NAME_SIZE] = {0};
    strncpy(program_name, "RECEIVER", strlen("RECEIVER"));

    // Let's craft the packet
    struct magicnet_packet *auth_iden_packet = magicnet_packet_new();
    if (!auth_iden_packet)
    {
        res = -1; // magicno no good, change it..
        goto out;
    }

    // Set the type don't forget
    magicnet_signed_data(auth_iden_packet)->type = MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET;

    // Copy the program name to the packet data.
    strncpy(magicnet_signed_data(auth_iden_packet)->payload.login_protocol_iden.program_name, program_name, sizeof(magicnet_signed_data(auth_iden_packet)->payload.login_protocol_iden.program_name));

    // Let's send the packet now
    res = magicnet_client_write_packet(client, auth_iden_packet, 0);
    if (res < 0)
    {
        goto out;
    }

    magicnet_log("%s Login protocol identification was sent to the connected peer\n", __FUNCTION__);

out:

    if (auth_iden_packet)
    {
        magicnet_packet_free(auth_iden_packet);
        auth_iden_packet = NULL;
    }
    return res;
}

bool magicnet_client_check_door_fully_open(struct magicnet_client *client)
{
    if (magicnet_client_login_protocol_door_open_recv(client) &&
        magicnet_client_login_protocol_door_open_sent(client))
    {
        // We also received therefore the door is fully open
        client->states.flags |= MAGICNET_CLIENT_STATE_FLAG_DOOR_OPENED;
        magicnet_log("%s the door has been fully opened\n", __FUNCTION__);
        return true;
    }

    return false;
}

int magicnet_client_open_door(struct magicnet_client *client)
{
    int res = 0;
    magicnet_log("%s we shall open the door with the peer\n", __FUNCTION__);

    if (magicnet_client_login_protocol_door_open_sent(client))
    {
        magicnet_log("%s door is already open from our side. We will assume to reopen it again\n", __FUNCTION__);
    }

    int door_key = client->door_keys.our_key;
    if (door_key == 0)
    {
        // Let's generate a door key to share
        // the client must send it back

        // shitty random, should change this at some point
        // its okay fo rnow...
        door_key = (rand() % 999999) + 1;
        client->door_keys.our_key = door_key;
    }

    struct magicnet_packet *packet = magicnet_packet_new_init(MAGICNET_PACKET_TYPE_OPEN_DOOR);
    if (!packet)
    {
        res = MAGICNET_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    magicnet_signed_data(packet)->payload.open_door.door_key = door_key;

    res = magicnet_client_write_packet(client, packet, 0);
    if (res < 0)
    {
        goto out;
    }

    client->states.flags |= MAGICNET_CLIENT_STATE_FLAG_DOOR_OPEN_SENT;
    // Maybe the door is fully open at this point.
    magicnet_client_check_door_fully_open(client);

out:
    return res;
}

/**
 * Must be called to poll and enhance potential client state
 * , through single thread or through thread pool it doesnt matter
 * just call it..
 *
 * If packet_out is not NULL then the packet wont be processed, the packet_out
 * will be set to the packet that was loaded and the caller of the poll becomes responsible
 * for the memory and processing
 */
int magicnet_client_poll(struct magicnet_client *client, PROCESS_PACKET_FUNCTION process_packet_func)
{
    int res = 0;
    bool should_close = false;
    struct magicnet_server *server = NULL;

    magicnet_client_lock(client);

    // Keep us waiting more than a few seconds we need to disconnect them
    // if they haven't logged in on time
    if (magicnet_client_inactive(client))
    {
        magicnet_log("%s server booted inactive client\n", __FUNCTION__);
        res = MAGICNET_ERROR_CRITICAL_ERROR;
        should_close = true;
        server = client->server;
        goto out;
        // ban TODO.. implement later..
    }

    magicnet_client_state state = magicnet_client_get_state(client);
    if (state < 0)
    {
        res = state;
        goto out;
    }

    // One state per cycle shall be ran.
    switch (state)
    {
    case MAGICNET_CLIENT_STATE_IDLE_WAIT:
        // Do nothinbg we are instructed to wait
      //  magicnet_log("%s IDLE WAIT STATE\n", __FUNCTION__);
        break;

    case MAGICNET_CLIENT_STATE_AWAITING_LOGIN_PACKET_MUST_WRITE:
        // System requires us to identify ourselves
        res = magicnet_client_poll_write_identification(client);
        break;

    case MAGICNET_CLIENT_STATE_PACKET_READ_PACKET_NEW:
        res = magicnet_client_poll_read_packet_new(client);
        break;

    // Invoked if we need to complete the reading of a single packet in our non-blocking protocol
    // Lag is bad today..
    case MAGICNET_CLIENT_STATE_PACKET_READ_PACKET_FINISH_READING:
        res = magicnet_client_poll_read_packet_finish_reading_and_process(client, process_packet_func);
        break;

    case MAGICNET_CLIENT_STATE_MUST_SEND_PING:
        res = magicnet_ping(client);
        break;

    case MAGICNET_CLIENT_STATE_MUST_OPEN_DOOR:
        res = magicnet_client_open_door(client);
        break;

    default:
        magicnet_log("%s unknown state or potential error %i\n", __FUNCTION__, (int)state);
    }

    if (res == MAGICNET_ERROR_TRY_AGAIN)
    {
        // Normal error, means we dont have enough bytes on the stream yet we can ignore it
        res = 0;
        // but we can't do anything more right now..
        goto out;
    }

out:
    if (res < 0)
    {
        magicnet_log("%s client poll error %i\n", __FUNCTION__, res);
        // destruct the client
        should_close = true;
        server = client->server;
    }
    // We return zero so that it will call us again in a few cycles..

    magicnet_client_unlock(client);

    if (should_close)
    {
        if (server)
        {
            magicnet_server_lock(server);
            magicnet_close(client);
            magicnet_server_unlock(server);
        }
        else
        {
            magicnet_close(client);
        }
    }
    return res;
}
int magicnet_client_thread_poll(struct magicnet_nthread_action *action)
{
    int res = 0;

    struct magicnet_client *client = (struct magicnet_client *)action->private;

    res = magicnet_client_poll(client, magicnet_server_poll_process);
    return res;
}

int magicnet_client_push(struct magicnet_client *client)
{
    int res = 0;
    struct magicnet_nthread_action *thread_action = magicnet_threads_action_new(magicnet_client_thread_poll, client, NULL);
    res = magicnet_threads_push_action(thread_action);
    return res;
}
int magicnet_server_process_make_new_connection_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_log("%s request for us to make new connection\n", __FUNCTION__);

    // Create a variable that points to the program name of this connection packet
    char *program_name = magicnet_signed_data(packet)->payload.new_connection.program_name;

    // Extract the ip address from the packet client information and convert it to a string
    char *ip = inet_ntoa(client->client_info.sin_addr);

    // Connect to the client with a new connection
    struct magicnet_client *new_client = magicnet_tcp_network_connect_for_ip_for_server(client->server, ip, MAGICNET_SERVER_PORT, program_name, magicnet_signed_data(packet)->payload.new_connection.entry_id, 0);
    if (new_client)
    {
        // Push the new client to the thread pool for regular polling.
        magicnet_client_push(new_client);
    }

    magicnet_log("%s new server thread is running that will handle this new connection\n", __FUNCTION__);

    return res;
}

// Helper function to send a single block
int magicnet_client_send_single_block(struct magicnet_client *client, struct block *block)
{
    int res = 0;
    magicnet_log("%s sending block %s\n", __FUNCTION__, block->hash);
    struct magicnet_packet *packet = magicnet_packet_new();
    // The block vector holds the blocks to send
    struct vector *block_vector = vector_create(sizeof(struct block *));

    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_BLOCK_SEND;
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet)->payload.block_send.blocks = block_vector;

    // When a packet is freed it deletes the block, therefore a clone is required!
    struct block *cloned_block = block_clone(block);
    vector_push(block_vector, &cloned_block);
    res = magicnet_client_write_packet(client, packet, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        magicnet_log("%s failed to send block %s\n", __FUNCTION__, block->hash);
        goto out;
    }

    magicnet_packet_free(packet);

out:
    return res;
}

int magicnet_client_process_block_super_download_request_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    const char *starting_hash = magicnet_signed_data(packet)->payload.block_super_download.begin_hash;
    size_t total_blocks_to_load = magicnet_signed_data(packet)->payload.block_super_download.total_blocks_to_request;
    char current_hash[SHA256_STRING_LENGTH];

    // Initialize the hash
    strncpy(current_hash, starting_hash, sizeof(current_hash));

    // Loop through all of the blocks to load
    while (total_blocks_to_load > 0)
    {
        // Load the block
        struct block *block = block_load(current_hash);
        if (!block)
        {
            magicnet_log("%s Failed to load block %s\n", __FUNCTION__, current_hash);
            res = -1;
            goto out;
        }

        // Load the block fully
        res = block_load_fully(block);
        if (res < 0)
        {
            magicnet_log("%s Failed to load block %s fully\n", __FUNCTION__, current_hash);
            goto out;
        }

        // Send the block
        res = magicnet_client_send_single_block(client, block);
        if (res < 0)
        {
            goto out;
        }

        // Move to the next block
        strncpy(current_hash, block->prev_hash, sizeof(current_hash));
        block_free(block);
        total_blocks_to_load--;
    }

    // Now we must send a done packet
    struct magicnet_packet *done_packet = magicnet_packet_new();
    magicnet_signed_data(done_packet)->type = MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_DONE;
    magicnet_signed_data(done_packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    res = magicnet_client_write_packet(client, done_packet, MAGICNET_PACKET_FLAG_MUST_BE_SIGNED);
    if (res < 0)
    {
        magicnet_log("%s failed to send block super download done packet\n", __FUNCTION__);
        // free the done packet
        magicnet_packet_free(done_packet);
        goto out;
    }

    // free the done packet
    magicnet_packet_free(done_packet);

out:
    return res;
}

int magicnet_server_process_login_protocol_identification_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_log("%s Received login packet from this client \n");
    // slight lag.. today..
    res = magicnet_client_preform_entry_protocol_post_read_process(client, packet);
    return res;
}

int magicnet_packet_allowed_to_be_processed(struct magicnet_client *sending_client, struct magicnet_packet *packet)
{
    if (!magicnet_client_login_protocol_received(sending_client))
    {
        // We haven't received the login protocol yet, so we expect this to be
        // a login protocol packet if not we will drop it.
        // LIKELY NEED TO ACCEPT MORE PACKET TYPES HERE,, THAT WAS THE BUG I BELIEVE... FIX LATER.
        if (magicnet_signed_data(packet)->type != MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET)
        {
            magicnet_log("%s client sent packet before authenticating, dropping..\n", __FUNCTION__);

            // We won't treat this as an error as such but it wont be accepted.
            // they will time out soon if they dont follow the rules.
            //   return -EIO;
            // DISABLED FOR NOW WHILE I FIND OUT WHAT HAPPEND...
        }
    }

    return 0;
}

int magicnet_client_open_door_ack(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;

    struct magicnet_packet *ack_packet = magicnet_packet_new_init(MAGICNET_PACKET_TYPE_OPEN_DOOR_ACK);
    if (!ack_packet)
    {
        res = MAGICNET_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    // Set the key to the one its expected to be
    magicnet_signed_data(ack_packet)->payload.open_door_ack.door_key = magicnet_signed_data(packet)->payload.open_door.door_key;
    client->door_keys.their_key = magicnet_signed_data(packet)->payload.open_door.door_key;

    // We have the cknowledgement packet sent it to them
    res = magicnet_client_write_packet(client, ack_packet, 0);
    // The acknowledgement was sent.
out:
    return res;
}
int magicnet_server_process_open_door_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    magicnet_log("%s open door process\n", __FUNCTION__);
    if (magicnet_client_door_opened(client))
    {
        magicnet_log("%s door is already open\n", __FUNCTION__);
        goto out;
    }

    // We got a door open packet so we have to send ours back
    // unless we are fully open at this point
    if (!magicnet_client_check_door_fully_open(client))
    {
        // Not fully open open our door.
        magicnet_client_open_door(client);
    }
    // We also have to acknowledge their packet
    res = magicnet_client_open_door_ack(client, packet);
out:
    return res;
}

int magicnet_server_process_open_door_ack_packet(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    if (client->door_keys.our_key != magicnet_signed_data(packet)->payload.open_door_ack.door_key)
    {
        // Client doesnt know what thec ode is
        // not paying attention kill it
        res = MAGICNET_ERROR_INVALID_PARAMETERS;
        goto out;
    }
    // Key is valid authenticate
    // recv flag only set when they acknowledge our open door.
    client->states.flags |= MAGICNET_CLIENT_STATE_FLAG_DOOR_OPEN_RECV;

    // nOW CHECK THE keys see if its open on both sides
    magicnet_client_check_door_fully_open(client);
out:
    return res;
}

#warning "BELOW FUNCTIONS DONT RESPECT THE MUTEXES, MAKE SURE YOU CALL THEM WITH A LOCK"
bool magicnet_client_monitoring_packet_type(struct magicnet_client *client, int type)
{
    if (vector_exists(client->packet_monitoring.type_ids, &type))
    {
        return true;
    }

    return false;
}

void magicnet_client_monitor_packet_type(struct magicnet_client *client, int type)
{
    vector_push(client->packet_monitoring.type_ids, &type);
}

void magicnet_client_unmonitor_packet_type(struct magicnet_client *client, int type)
{
    vector_pop_value(client->packet_monitoring.type_ids, &type);
}

void magicnet_client_handle_packet_monitoring(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    struct magicnet_packet *cloned_packet = NULL;

    // Do we have packet monitoring enabled for this type of packet
    if (magicnet_client_monitoring_packet_type(client, magicnet_signed_data(packet)->type))
    {
        // yes great..
        cloned_packet = magicnet_packet_new();
        if (!cloned_packet)
        {
            // nomem..
            res = -1;
            goto out;
        }

        magicnet_copy_packet(cloned_packet, packet);

        // We have the clone push it to the vector
        vector_push(client->packet_monitoring.packets, &cloned_packet);
    }

out:
    if (res < 0)
    {
        if (cloned_packet)
        {
            magicnet_packet_free(cloned_packet);
            cloned_packet = NULL;
        }
    }
}
/**
 * DO NOT DO SERVER LOGIC IN THIS FUNCTION
 * THIS IS A GENERIC FUNCTION FOR SHARING ACROSS ALL FORMS OF CONNECTIONS
 */
int magicnet_default_poll_packet_process(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_packet_allowed_to_be_processed(client, packet);
    if (res < 0)
    {
        magicnet_log("%s sending client isn't allowed to process this packet at least for now\n");
        goto out;
    }

    magicnet_log("%s processing packet\n", __FUNCTION__);

    // Login protocol is expected for all peers, so its in this default logic
    switch (magicnet_signed_data(packet)->type)
    {
    case MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET:
        res = magicnet_server_process_login_protocol_identification_packet(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_OPEN_DOOR:
        res = magicnet_server_process_open_door_packet(client, packet);
        break;

    case MAGICNET_PACKET_TYPE_OPEN_DOOR_ACK:
        res = magicnet_server_process_open_door_ack_packet(client, packet);
        break;
    }

    client->last_packet_received = time(NULL);

    magicnet_client_lock(client);
    magicnet_client_handle_packet_monitoring(client, packet);
    magicnet_client_unlock(client);
out:
    return res;
}

/**
 * Called ONLY by clients that have been pushed to the server thread pool
 */
int magicnet_server_poll_process(struct magicnet_client *client, struct magicnet_packet *packet)
{
    int res = 0;
    res = magicnet_default_poll_packet_process(client, packet);
    if (res < 0)
    {
        goto out;
    }

    // so we have disabled the functionality for the time being.
    // direct read after write is a problem in non-blocking mode.
    switch (magicnet_signed_data(packet)->type)
    {
    case MAGICNET_PACKET_TYPE_USER_DEFINED:
        res = magicnet_server_poll_process_user_defined_packet(client, packet);
        break;

        // case MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP:
        //     res = magicnet_server_poll_process_verifier_signup_packet(client, packet);
        //     break;

        // case MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER:
        //     res = magicnet_server_process_vote_for_verifier_packet(client, packet);
        //     break;

        // case MAGICNET_PACKET_TYPE_BLOCK_SEND:
        //     res = magicnet_server_process_block_send_packet(client, packet);
        //     break;

        // case MAGICNET_PACKET_TYPE_TRANSACTION_SEND:
        //     res = magicnet_server_process_transaction_send_packet(client, packet);
        //     break;

        // case MAGICNET_PACKET_TYPE_REQUEST_BLOCK:
        //     res = magicnet_client_process_request_block_packet(client, packet);
        //     break;

        // case MAGICNET_PACKET_TYPE_REQUEST_BLOCK_RESPONSE:
        //     res = magicnet_client_process_request_block_response_packet(client, packet);
        //     break;

        // case MAGICNET_PACKET_TYPE_MAKE_NEW_CONNECTION:
        //     res = magicnet_server_process_make_new_connection_packet(client, packet);
        //     break;
    };

    magicnet_server_lock(client->server);
    res = magicnet_server_add_seen_packet(client->server, packet);
    magicnet_server_unlock(client->server);
    if (res < 0)
    {
        goto out;
    }

    // Lets flush any packets now awaiting to be flushed to our client
    res = magicnet_client_packets_for_client_flush(client);

    // Since we processed something lets for the next 10 seconds increase the bandwidth just in case theres more to send
    magicnet_client_set_max_bytes_to_send_per_second(client, MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_WHEN_PROCESSING_PACKETS, 10);
    magicnet_client_set_max_bytes_to_recv_per_second(client, MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_WHEN_PROCESSING_PACKETS, 10);

out:
    return res;
}

/**
 * Called if your a client that connected to another peer, you call it to sync with it.
 */
int magicnet_server_poll(struct magicnet_client *client)
{
#warning "MUST BE REFACTORED INCOMPATIBLE WITH PROTOCOL CHANGES!"!!!"
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

    magicnet_packet_free(packet_to_send);
    magicnet_packet_free(packet);
    magicnet_packet_free(packet_to_relay);

    // We don't really want to over whelm the thread... This would be better in the loop however.
    if (should_sleep)
    {
        //   usleep(2000000);
    }
    return res;
}
void *magicnet_client_thread(void *_client)
{

#warning "DO NOT USE THIS FUNCTION ITS DEPRECATED"
    //     int res = 0;
    //     bool server_shutting_down = false;
    //     struct magicnet_client *client = _client;

    //     sigset_t set;
    //     sigemptyset(&set);
    //     sigaddset(&set, SIGINT);
    //     pthread_sigmask(SIG_BLOCK, &set, NULL);

    //     if (client->server)
    //     {
    //         magicnet_server_lock(client->server);
    //         magicnet_server_add_thread(client->server, pthread_self());
    //         magicnet_server_unlock(client->server);
    //     }

    //     if (!(client->flags & MAGICNET_CLIENT_FLAG_ENTRY_PROTOCOL_COMPLETED))
    //     {
    //         res = magicnet_client_preform_entry_protocol_read(client);
    //         if (res < 0)
    //         {
    //             // entry protocol failed.. illegal client!
    //             goto out;
    //         }
    //     }

    //     if (client->signal_id)
    //     {
    //         magicnet_signal_post_for_signal(client->signal_id, "connect-again-signal", client, sizeof(struct magicnet_client), 0);
    //         // Now the waiting thread is in charge of the client we will leave this thread and let the waiting thread take over being sure not
    //         // to free the memory of the client
    //         goto out;
    //     }

    //     if (client->server)
    //     {
    //         magicnet_server_lock(client->server);
    //         magicnet_server_recalculate_my_ip(client->server);
    //         magicnet_server_unlock(client->server);
    //     }

    //     while (res != MAGICNET_ERROR_CRITICAL_ERROR && !server_shutting_down)
    //     {
    //         res = magicnet_client_manage_next_packet(client);
    //         if (client->server)
    //         {
    //             magicnet_server_lock(client->server);
    //             server_shutting_down = client->server->shutdown;
    //             if (server_shutting_down)
    //             {
    //                 magicnet_log("%s the server is shutting down suspending client\n", __FUNCTION__);
    //             }
    //             magicnet_server_unlock(client->server);
    //         }
    //     }
    // out:
    //     if (client->server)
    //     {
    //         magicnet_server_lock(client->server);
    //         // Only when theirs no signal who has taken over this client will we free the client
    //         if (!client->signal_id)
    //         {
    //             magicnet_close(client);
    //         }
    //         magicnet_server_remove_thread(client->server, pthread_self());
    //         magicnet_server_unlock(client->server);
    //     }
    //     else
    //     {
    //         // Only when theirs no signal who has taken over this client will we free the client
    //         if (!client->signal_id)
    //         {
    //             magicnet_close(client);
    //         }
    //     }
    return NULL;
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
    bool sleeping = false;
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
        if (!sleeping)
        {
            // We must ask the server to relay packets to us
            res = magicnet_server_poll(client);
        }
        else
        {
            sleep(1);
        }

        magicnet_server_read_lock(client->server);
        shutdown = client->server->shutdown;
        sleeping = false;
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

    struct magicnet_client *client = magicnet_tcp_network_connect_for_ip_for_server(server, ip, MAGICNET_SERVER_PORT, MAGICNET_LISTEN_ALL_PROGRAM, 0, 0);
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

void magicnet_server_client_signup_as_verifier(struct magicnet_server *server, struct magicnet_council_certificate *certificate)
{
    int res = 0;
    // Lets create verifier signups for the block
    // peers can ask to be elected to make the next block

    struct magicnet_packet *packet = magicnet_packet_new();
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP;
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet)->payload.verifier_signup.certificate = magicnet_council_certificate_clone(certificate);

    // Lets sign ourselves up to our local server
    res = magicnet_server_verifier_signup(server, magicnet_signed_data(packet)->payload.verifier_signup.certificate);
    if (res < 0)
    {
        magicnet_error("%s failed to signup as a verifier in our own server\n", __FUNCTION__);
        goto out;
    }

    // Let's add this packet to the server relay so all connected hosts will find it and relay it
    // to millions
    res = magicnet_server_add_packet_to_relay(server, packet);
    if (res < 0)
    {
        magicnet_error("%s signed up as a verifier locally but failed to signup as a verifier remotely.. Issue with relaying the packet\n", __FUNCTION__);
    }

out:
    magicnet_packet_free(packet);
}

bool magicnet_vote_allowed(struct key *key, struct key *votes_for)
{
    // Cannot vote for yourself
    if (key_cmp(key, votes_for))
    {
        return false;
    }

    return true;
}

struct magicnet_council_certificate *magicnet_server_get_random_block_verifier(struct magicnet_server *server)
{
    if (vector_count(server->next_block.signed_up_verifiers) == 0)
    {
        return NULL;
    }

    int random_key_index = rand() % vector_count(server->next_block.signed_up_verifiers);
    return vector_peek_ptr_at(server->next_block.signed_up_verifiers, random_key_index);
}

size_t magicnet_total_verifiers(struct magicnet_server *server)
{
    return vector_count(server->next_block.signed_up_verifiers);
}

struct magicnet_council_certificate *magicnet_server_find_verifier_to_vote_for(struct magicnet_server *server)
{
    struct magicnet_council_certificate *verifier_certificate = NULL;
    size_t attempts = 0;
    while ((verifier_certificate = magicnet_server_get_random_block_verifier(server)) != NULL && attempts < 4)
    {
        // Is the key that we chose allowed?
        // if (magicnet_vote_allowed(MAGICNET_public_key(), verifier_certificate))
        // {
        //     // yeah allowed? okay great
        //     break;
        // }
        attempts++;
    }

    return verifier_certificate;
}

/**
 * Applies the provided certificate to the my_certificate field of the packet, proves the certificate of the person
 * who crafted a packet. Only neccessary to be applied to certain packets to prove authenticity.
 */
int magicnet_packet_apply_my_certificate(struct magicnet_packet *packet, struct magicnet_council_certificate *certificate)
{
    int res = 0;
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE;
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER;
    magicnet_signed_data(packet)->my_certificate = magicnet_council_certificate_clone(certificate);
    return res;
}
void magicnet_server_client_vote_for_verifier(struct magicnet_server *server)
{
    int res = 0;
    struct magicnet_council_certificate *certificate = NULL;
    struct magicnet_council_certificate *verifier_cert_to_vote_for = magicnet_server_find_verifier_to_vote_for(server);
    if (!verifier_cert_to_vote_for)
    {
        magicnet_error("%s failed to find a key to vote for\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_council_default_certificate_for_key(NULL, MAGICNET_public_key(), &certificate);
    if (res < 0)
    {
        magicnet_error("%s failed to get our own certificate, I guess we are not a council member and cant vote.\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_server_cast_verifier_vote(server, certificate, verifier_cert_to_vote_for->hash);
    if (res < 0)
    {
        magicnet_error("%s we failed to cast a vote on our local client\n", __FUNCTION__);
        goto out;
    }

    // Let us create a new vote packet to relay.
    struct magicnet_packet *packet = magicnet_packet_new();
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_packet_apply_my_certificate(packet, certificate);
    memcpy(magicnet_signed_data(packet)->payload.vote_next_verifier.vote_for_cert, verifier_cert_to_vote_for->hash, sizeof(verifier_cert_to_vote_for->hash));
    magicnet_server_add_packet_to_relay(server, packet);

    magicnet_packet_free(packet);

out:
    if (certificate)
    {
        magicnet_council_certificate_free(certificate);
    }
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
    struct magicnet_certificate_vote *cert_vote = vector_peek_ptr(server->next_block.verifier_votes.votes);
    while (cert_vote)
    {
        magicnet_council_certificate_free(cert_vote->vote_from_cert);
        free(cert_vote);
        cert_vote = vector_peek_ptr(server->next_block.verifier_votes.votes);
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
    struct magicnet_council_certificate *verifier_council_cert = vector_peek_ptr(server->next_block.signed_up_verifiers);
    while (verifier_council_cert)
    {
        // Free the certificate
        magicnet_council_certificate_free(verifier_council_cert);

        verifier_council_cert = vector_peek_ptr(server->next_block.signed_up_verifiers);
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

    if (server->next_block.created_block)
    {
        block_free(server->next_block.created_block);
        server->next_block.created_block = NULL;
    }

    server->next_block.step = BLOCK_CREATION_SEQUENCE_SIGNUP_VERIFIERS;
}

int magicnet_server_create_block(struct magicnet_server *server, const char *prev_hash, struct block_transaction_group *transaction_group, struct block **block_out)
{
    int res = 0;
    struct block *block = block_create(transaction_group, prev_hash);

    res = magicnet_council_my_certificate(NULL, &block->certificate);
    if (res < 0)
    {
        magicnet_error("%s failed to get our own certificate, are you sure we are a member of the council\n", __FUNCTION__);
        goto out;
    }

    res = block_hash_sign_verify(block);
    if (res < 0)
    {
        magicnet_error("%s could not hash sign and verify the block\n", __FUNCTION__);
        goto out;
    }

    res = block_verify(block);
    if (res < 0)
    {
        magicnet_error("%s failed to verify the block we created. We did something wrong\n", __FUNCTION__);
        goto out;
    }

    // Save the block
    block_save(block);
    magicnet_database_blockchain_update_last_hash(block->blockchain_id, block->hash);
    magicnet_database_blockchain_increment_proven_verified_blocks(block->blockchain_id);

    // We need to remove our self transactions from the received block so we dont resend them to the network
    magicnet_server_update_our_transaction_states(server, block);
    *block_out = block;

out:
    if (res < 0)
    {
        if (block)
        {
            block_free(block);
        }
    }
    return 0;
}

void magicnet_server_create_and_send_block(struct magicnet_server *server)
{
    int res = 0;
    magicnet_important("%s block creation sequence for this peer. Peer will make block\n", __FUNCTION__);
    struct blockchain *active_chain = NULL;
    struct vector *blockchains = vector_create(sizeof(struct blockchain *));
    struct vector *block_vector = vector_create(sizeof(struct block *));
    struct block_transaction_group *transaction_group = block_transaction_group_new();
    struct magicnet_packet *packet = magicnet_packet_new();
    magicnet_signed_data(packet)->type = MAGICNET_PACKET_TYPE_BLOCK_SEND;
    magicnet_signed_data(packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(packet)->payload.block_send.blocks = block_vector;

    // Let's loop through all of the block transactions that we are aware of and add them to the block
    vector_set_peek_pointer(server->next_block.block_transactions, 0);
    struct block_transaction *transaction = vector_peek_ptr(server->next_block.block_transactions);
    while (transaction)
    {
        block_transaction_add(transaction_group, block_transaction_clone(transaction));
        transaction = vector_peek_ptr(server->next_block.block_transactions);
    }

    active_chain = magicnet_blockchain_get_active();
    if (!active_chain)
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

    // Push the new block event.
    magicnet_server_push_event(server, &(struct magicnet_event){.type = MAGICNET_EVENT_TYPE_NEW_BLOCK, .data.new_block_event.block = block});

    magicnet_server_add_packet_to_relay(server, packet);
    // Set the created block so other parts of the sequences are aware of it.
    magicnet_server_set_created_block(server, block);
out:
    if (active_chain)
    {
        blockchain_free(active_chain);
    }
    magicnet_packet_free(packet);
}

size_t magicnet_server_total_waiting_transactions_to_send(struct magicnet_server *server)
{
}
bool magicnet_server_should_sign_and_send_self_transaction(struct self_block_transaction *self_transaction)
{
    // We do still allow you to resend even if its been sent before.
    return self_transaction->state == BLOCK_TRANSACTION_STATE_PENDING_SIGN_AND_SEND || self_transaction->state == BLOCK_TRANSACTION_STATE_SIGNED_AND_SENT;
}

void magicnet_server_sign_and_send_self_transaction(struct magicnet_server *server, struct self_block_transaction *self_transaction, const char *last_block_hash)
{
    int res = 0;
    // Many times we should not even bother signing the transaction, such as if its already been done.
    // Lets ensure its actually pending because we dont delete self transactions from memory without a good reason.
    if (!magicnet_server_should_sign_and_send_self_transaction(self_transaction))
    {
        magicnet_log("%s the transaction has already been sent before so we will not send it again. This is not a BUG and is intended behaviour to allow a history of transactions per session\n", __FUNCTION__);
        return;
    }

    struct magicnet_packet *transaction_packet = magicnet_packet_new();
    char status_message[MAGICNET_MAX_SMALL_STRING_SIZE];
    strncpy(status_message, "Transaction sent to the network", sizeof(status_message));

    // We need to update the block transaction data to have a previous block hash set to the one provided
    memcpy(self_transaction->transaction->data.prev_block_hash, last_block_hash, sizeof(self_transaction->transaction->data.prev_block_hash));

    // Theres a good chance we need to modify the transaction packet send to us by localhost
    // // Rebuild the transaction packet
    res = magicnet_transaction_rebuild(self_transaction->transaction);
    if (res < 0)
    {
        magicnet_log("%s rebuilding of packet failed\n", __FUNCTION__);
        strncpy(status_message, "We failed to rebuild the packet", sizeof(status_message));
        goto out;
    }

    // We must sign the transaction in the packet
    res = block_transaction_hash_and_sign(self_transaction->transaction);
    if (res < 0)
    {
        strncpy(status_message, "Hashing and signing has failed", sizeof(status_message));
        goto out;
    }

    // Lets now check the transaction is valid before wasting our time
    res = block_transaction_valid(self_transaction->transaction);
    if (res < 0)
    {
        strncpy(status_message, "The transaction is not structured in a valid way", sizeof(status_message));
        goto out;
    }

    magicnet_signed_data(transaction_packet)->type = MAGICNET_PACKET_TYPE_TRANSACTION_SEND;
    magicnet_signed_data(transaction_packet)->flags |= MAGICNET_PACKET_FLAG_MUST_BE_SIGNED;
    magicnet_signed_data(transaction_packet)->payload.transaction_send.transaction = block_transaction_clone(self_transaction->transaction);
    // Now we signed the transaction we must resign the packet.
    // All we do with a packet like this is add it to the relay so the server can relay to all other peers.
    res = magicnet_server_add_packet_to_relay(server, transaction_packet);
    if (res < 0)
    {
        strncpy(status_message, "We failed to add the packet to the relay", sizeof(status_message));
        goto out;
    }
    // Oh and we add the transaction to our own queue as well.
    res = magicnet_server_next_block_transaction_add(server, self_transaction->transaction);
    if (res < 0)
    {
        strncpy(status_message, "We failed to add the transaction to the next block queue", sizeof(status_message));
        goto out;
    }

    magicnet_log("%s Processed our self-signed transaction packet. RELAYING\n", __FUNCTION__);

out:
    magicnet_packet_free(transaction_packet);
    self_transaction->state = BLOCK_TRANSACTION_STATE_SIGNED_AND_SENT;
    if (res < 0)
    {
        magicnet_log("%s issue signing and sending our own transaction... \n", __FUNCTION__);
        self_transaction->state = BLOCK_TRANSACTION_STATE_FAILED;
    }

    strncpy(self_transaction->status_message, status_message, sizeof(self_transaction->status_message));
}
void magicnet_server_sign_and_send_self_transactions(struct magicnet_server *server, struct block *block)
{
    if (vector_count(server->our_waiting_transactions) == 0)
    {
        // Nothing for us to send of ours.. Nothing waiting
        return;
    }
    magicnet_log("%s we have %i transactions in the queue, if they havent been put in the chain yet we will broadcast them now. If they are in the chain they will be ignored\n", __FUNCTION__, vector_count(server->our_waiting_transactions));
    int active_blockchain_id = magicnet_blockchain_get_active_id();
    if (active_blockchain_id != block->blockchain_id)
    {
        magicnet_log("%s We are not on the active blockchain. We will avoid sending the transactions this time round\n", __FUNCTION__);
        return;
    }

    struct block *prev_block = block_load(block->prev_hash);
    if (!prev_block)
    {
        magicnet_log("%s We don't know the previous block for the block that we should sign with. Therefore we dont really know the blockchain. We will avoid sending the transactions this time round\n", __FUNCTION__);
        return;
    }

    // Free the previous block that was loaded.
    block_free(prev_block);

    vector_set_peek_pointer(server->our_waiting_transactions, 0);
    struct self_block_transaction *self_transaction = vector_peek_ptr(server->our_waiting_transactions);
    while (self_transaction)
    {
        magicnet_server_sign_and_send_self_transaction(server, self_transaction, block->hash);
        self_transaction = vector_peek_ptr(server->our_waiting_transactions);
    }
}

/**
 * Sets the computer/peer/council member that we expect to receive the next block from
 * All other senders are unauthorized and will be ignored.
 */
int magicnet_server_set_authorized_block_creator(struct magicnet_server *server, const char *certificate_hash)
{
    int res = 0;
    memcpy(server->authorized_block_creator.authorized_cert_hash, certificate_hash, sizeof(server->authorized_block_creator.authorized_cert_hash));
    server->authorized_block_creator.was_block_received = false;
    return res;
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
    // the first fifth of that time we will be signing up as a verifier and receving new verifiers
    // the second fifth we will be casting votes
    // third fifth we calculate the verifier who won the vote
    // fourth fifth we await the block
    // final fifth we reset the block creation rules, clearing all the verifiers and votes wether
    // we receive a block or not this will happen
    time_t one_fifth_seconds = MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS / 5;
    time_t block_time_first_fifth_start = 0;
    time_t block_time_second_fifth_start = one_fifth_seconds * 1;
    time_t block_time_third_fifth_start = one_fifth_seconds * 2;
    time_t block_time_fourth_fifth_start = one_fifth_seconds * 3;
    time_t block_time_fifth_fifth_start = one_fifth_seconds * 4;
    time_t block_cycle_end = one_fifth_seconds * 5;

    // This gives us what second into the sequence we are I.e 15 seconds into the block sequence
    // it cannot be greater than the MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS
    time_t current_block_sequence_time = time(NULL) % MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS;

    magicnet_server_lock(server);

    // First quarter, signup as a verifier. (Note we check that the step is correct for clients that came online too late.. or did not complete a vital step on time)
    int step = server->next_block.step;
    if (current_block_sequence_time >= block_time_first_fifth_start && current_block_sequence_time < block_time_second_fifth_start && step == BLOCK_CREATION_SEQUENCE_SIGNUP_VERIFIERS)
    {
        // Alright lets deal with this

        // Lets get our certificate
        struct magicnet_council_certificate *certificate = NULL;
        int res = magicnet_council_my_certificate(NULL, &certificate);
        if (res >= 0)
        {
            // We have a council certificate okay great!
            magicnet_server_client_signup_as_verifier(server, certificate);
        }

        // Free the certificate we dont need it anymore
        if (certificate)
        {
            magicnet_council_certificate_free(certificate);
        }

        server->next_block.step = BLOCK_CREATION_SEQUENCE_CAST_VOTES;
    }
    else if (current_block_sequence_time >= block_time_second_fifth_start && current_block_sequence_time < block_time_third_fifth_start && step == BLOCK_CREATION_SEQUENCE_CAST_VOTES)
    {
        magicnet_important("%s second quarter in the block sequence, lets create a random vote\n", __FUNCTION__);
        magicnet_server_client_vote_for_verifier(server);
        server->next_block.step = BLOCK_CREATION_SEQUENCE_CALCULATE_VOTED_VERIFIER;
    }
    else if (current_block_sequence_time >= block_time_third_fifth_start && current_block_sequence_time < block_time_fourth_fifth_start && step == BLOCK_CREATION_SEQUENCE_CALCULATE_VOTED_VERIFIER)
    {
        // We must select a verifier who won the vote.
        struct magicnet_vote_count *verifier_vote_who_won = magicnet_server_verifier_who_won(server);
        if (!verifier_vote_who_won)
        {
            magicnet_important("%s no verifier certificate won the vote.\n", __FUNCTION__);
        }
        else
        {
            if (magicnet_council_certificate_is_mine(verifier_vote_who_won->vote_for_cert_hash))
            {
                magicnet_important("%s we won the vote! We will send the block next cycle\n", __FUNCTION__);
            }
            else
            {
                magicnet_important("%s we did not win the vote. We will wait for the block to be sent to us\n", __FUNCTION__);
            }

            // Let's set the authroized block creator to the winner whome we expect to receive blocks from
            // even if we created the block we may end up receving it again from the network
            // so we must be prepared to accept it.
            magicnet_server_set_authorized_block_creator(server, verifier_vote_who_won->vote_for_cert_hash);
        }

        server->next_block.step = BLOCK_CREATION_SEQUENCE_AWAIT_NEW_BLOCK;
    }
    else if (current_block_sequence_time >= block_time_fourth_fifth_start && current_block_sequence_time < block_time_fifth_fifth_start && step == BLOCK_CREATION_SEQUENCE_AWAIT_NEW_BLOCK)
    {
        struct magicnet_vote_count *verifier_vote_who_won = magicnet_server_verifier_who_won(server);
        if (verifier_vote_who_won)
        {
            magicnet_important("%s awaiting for new block from voted verifier certificate: %s \n", __FUNCTION__, verifier_vote_who_won->vote_for_cert_hash);
            if (magicnet_council_certificate_is_mine(verifier_vote_who_won->vote_for_cert_hash))
            {
                magicnet_important("%s creating and sending block\n", __FUNCTION__);
                // What do you know we won the vote! Lets create this block
                magicnet_server_create_and_send_block(server);
            }
        }
        server->next_block.step = BLOCK_CREATION_SEQUENCE_CLEAR_EXISTING_SEQUENCE;
    }
    else if (current_block_sequence_time >= block_time_fifth_fifth_start && step == BLOCK_CREATION_SEQUENCE_CLEAR_EXISTING_SEQUENCE)
    {
        // Clone the created block as reset will free it.
        struct block *created_block = server->next_block.created_block ? block_clone(server->next_block.created_block) : NULL;

        // We dont check for the step in this IF statement, just in case a peer doesnt keep up
        // we dont want them stuck forever out of being able to make block sequences, therefore we allow this one to always run
        // yes it will run every few seconds for ages but its fine as then we can reject people
        // sending verifier packets when they shouldnt be since they will be discarded.
        magicnet_server_reset_block_sequence(server);

        // After we reset the block sequence let us sign and send any pending self transactions.
        // Must be after we reset otherwise any work we do will be erased in the reset.
        // Reset also frees the created block so a clone is neccessary
        if (created_block)
        {
            magicnet_server_sign_and_send_self_transactions(server, created_block);
            block_free(created_block);
        }
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
