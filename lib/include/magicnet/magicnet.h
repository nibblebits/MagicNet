
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
#include "buffer.h"

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
    MAGICNET_PACKET_TYPE_VERIFIER_SIGNUP,
    MAGICNET_PACKET_TYPE_VOTE_FOR_VERIFIER,
    MAGICNET_PACKET_TYPE_TRANSACTION_SEND,
    MAGICNET_PACKET_TYPE_BLOCK_SEND,
    MAGICNET_PACKET_TYPE_NOT_FOUND,
};

enum
{
    MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE = 0b00000001,
    MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING = 0b00000010,
    MAGICNET_PACKET_FLAG_MUST_BE_SIGNED = 0b00000100
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
    MAGICNET_ERROR_ALREADY_EXISTANT = -1003,
    MAGICNET_ERROR_UNKNOWN = -1004,
    MAGICNET_ERROR_SECURITY_RISK = -1005,
    MAGICNET_ERROR_NO_BLOCK_FOUND = -1006,
    MAGICNET_ERROR_TOO_LARGE = 1007,
    // Critical errors will terminate connections when received be cautious..
    // You may not send a critical error over the network it will be ignored and changed to an unknown error
    MAGICNET_ERROR_CRITICAL_ERROR = -1,
    MAGICNET_ACKNOWLEGED_ALL_OKAY = 0
};

struct block;

struct magicnet_packet
{

    // The public key use to sign the signature.
    struct key pub_key;

    // The signature used to sign the datahash. To verify the packets check the signature signed
    // the datahash. Rehash the signed_data with sha256 and compare the hashes. If all tests pass then
    // this signature signed the data provided.
    struct signature signature;
    // The hash of the data in tmp_buf
    char datahash[SHA256_STRING_LENGTH];

    /**
     * @brief The not_sent structure contains values that will not be sent to any peers
     * or clients at all. It is used for our own internal information regarding the packet we are dealing with.
     *
     */
    struct
    {
        /**
         * @brief This tmp_buf is NULL until we send this packet. When the packet is being sent
         * the buffer is initialized and filled with every byte we send to the peer. Once we are done sending the packet
         * it is freed and NULLED Once more.
         *
         * It is used for debugging purposes and also to ensure packet integrity through the use of signatures.
         * The datahash further above is based off the buffer of tmp_buf. tmp_buf contains every single byte
         * sent to the client in regards to this packet.
         */
        struct buffer *tmp_buf;
    } not_sent;

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

                /**
                 * This packet describes a VOTE of the key who should verify the next block.
                 * SOme better abstraction would be better i think, come back to revise...
                 */
                struct magicnet_vote
                {
                    // Contains the public key of whome this vote is for.
                    // If enough people vote for this key they will create the next block
                    // all blocks signed whome are not the winner will be rejected.
                    struct key vote_for_key;
                } vote_next_verifier;

                /**
                 * @brief Once this packet is signed and sent your public key
                 * will be eligible to be voted for to be the next signer of the block
                 * unless you signup before a block is created you wont be considered.
                 * You must sign up for every block you wish to sign.
                 */
                struct magicnet_verifier_signup
                {
                    // Empty... We will use the key that signed this block.
                } verifier_signup;


                struct magicnet_transaction_send
                {
                    struct block_transaction* transaction;
                } transaction_send;
                struct magicnet_block_send
                {
                    struct block *block;
                } block_send;
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

struct magicnet_key_vote
{
    // THe key who voted
    struct key vote_from;
    // The key voted for
    struct key voted_for;
};

struct magicnet_vote_count
{
    struct key key;
    // The number of voters whome voted for this key.
    size_t voters;
};

enum
{
    BLOCK_CREATION_SEQUENCE_SIGNUP_VERIFIERS,
    BLOCK_CREATION_SEQUENCE_CAST_VOTES,
    BLOCK_CREATION_SEQUENCE_AWAIT_NEW_BLOCK,
    BLOCK_CREATION_SEQUENCE_CLEAR_EXISTING_SEQUENCE
};

struct block_transaction;
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

    /**
     * @brief Rules on how the next block will be created
     *
     */
    struct next_block
    {
        /**
         * The votes for the verifier who will make the next block.
         */
        struct votes
        {
            // vector of struct magicnet_key_vote*
            struct vector *votes;

            // vector of struct magicnet_vote_count*
            struct vector *vote_counts;
        } verifier_votes;

        // Vector of struct key* . Everybody in this vector can be voted on to make the next block
        // do not vote on people who are not signed up to sign the next block!
        struct vector *signed_up_verifiers;

        // The pending transactions that should be added to the next block. struct block_transaction*
        struct vector* block_transactions;

        // The step in the block creation sequence we are currently in.
        int step;

    } next_block;

    // The timestamp the server started
    time_t server_started;
    // THe first time the block cycle begins for this server instance
    time_t first_block_cycle;
    pthread_mutex_t lock;

    // BELOW MUST BE PROCESSED ONLY BY THE SERVER THREAD
    off_t last_new_connection_attempt;
    const char *loaded_ip_addresses[MAGICNET_MAX_LOADED_IP_ADDRESSES];
    size_t total_loaded_ips;
    FILE *ip_file;
    // END
};

struct block_transaction_data
{
    // The program name who this transaction is intended for.. All listening to this program
    // will have access to the transaction
    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
    time_t time;
    char *ptr;
    size_t size;
};

struct block_transaction
{
    char hash[SHA256_STRING_LENGTH];
    // Signed signature of the creator of the transaction.
    struct signature signature;
    // The public key of the creator of the transaction
    struct key key;
    // Pointer to raw data of the transacton known only by the application using the network
    struct block_transaction_data data;
};

struct block_data
{
    // Pointer arrayto the loaded transactions data in memory
    struct block_transaction* transactions[MAGICNET_MAX_TOTAL_TRANSACTIONS_IN_BLOCK];
    // The total transactions in this block
    size_t total_transactions;
};

struct block
{

    // Hash of this block
    char hash[SHA256_STRING_LENGTH];
    // Hash of the previous block
    char prev_hash[SHA256_STRING_LENGTH];

    struct block_data *data;
};

enum
{
    MAGICNET_CLIENT_FLAG_CONNECTED = 0b00000001,
    MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE = 0b00000010,
    // True if this connection is from an IP address on our local machine.
    MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST = 0b00000100,

};
struct signed_data *magicnet_signed_data(struct magicnet_packet *packet);
int magicnet_network_thread_start(struct magicnet_server *server);
struct magicnet_server *magicnet_server_start();
struct magicnet_client *magicnet_accept(struct magicnet_server *server);
int magicnet_client_thread_start(struct magicnet_client *client);
int magicnet_client_preform_entry_protocol_write(struct magicnet_client *client, const char *program_name);
struct magicnet_client *magicnet_tcp_network_connect(const char *ip_address, int port, int flags, const char *program_name);
int magicnet_next_packet(struct magicnet_program *program, void **packet_out);
int magicnet_client_read_packet(struct magicnet_client *client, struct magicnet_packet *packet_out);
int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet, int flags);
int magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet);
int magicnet_send_pong(struct magicnet_client *client);
void magicnet_free_packet(struct magicnet_packet *packet);
void magicnet_free_packet_pointers(struct magicnet_packet *packet);
struct magicnet_packet *magicnet_packet_new();
int magicnet_init();
int magicnet_get_structure(int type, struct magicnet_registered_structure *struct_out);
int magicnet_register_structure(long type, size_t size);
struct magicnet_program *magicnet_program(const char *name);
int magicnet_database_save_block(struct block *block);
int magicnet_database_load_last_block(char *hash_out, char *prev_hash_out);

/**
 * @brief Creates a new block in memory, no block is added to the chain.
 *
 * @param hash
 * @param prev_hash
 * @param data
 * @param len
 * @return struct block*
 */

struct block *block_create_with_data(const char *hash, const char *prev_hash, struct block_data *data);
struct block *block_create();
int block_save(struct block* block);
void block_free(struct block *block);

struct block *block_clone(struct block *block);
struct block_data *block_data_new();
void block_data_free(struct block_data* block_data);

struct block_transaction* block_transaction_new();
struct block_transaction* block_transaction_clone(struct block_transaction* transaction);
void block_transaction_free(struct block_transaction* transaction);
struct block_transaction* block_transaction_build(const char* program_name, char* data, size_t data_len);
int block_transaction_add(struct block *block, struct block_transaction *transaction);
int block_transaction_valid(struct block_transaction* transaction);
int block_transaction_hash_and_sign(struct block_transaction *transaction);
int block_verify(struct block* block);
int block_hash_sign_verify(struct block* block);
void magicnet_get_block_path(struct block *block, char *block_path_out);
const char *block_hash_create(struct block_data *data, const char *prev_hash, char *hash_out);
struct block *magicnet_block_load(const char *hash);

#endif