
#ifndef MAGICNET_H
#define MAGICNET_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
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
    // Signifies a new connection should be made between the peer who received the packet and the peer who sent it.
    MAGICNET_PACKET_TYPE_NEW_CONNECTION,
    MAGICNET_PACKET_TYPE_REQUEST_BLOCK,
    MAGICNET_PACKET_TYPE_REQUEST_BLOCK_RESPONSE,
    // A group of up to 100 blocks sent back. When we request a block the sender can send the next 100 we asked for.
    MAGICNET_PACKET_TYPE_GROUP_OF_BLOCKS,
    MAGICNET_PACKET_TYPE_BLOCK_SEND,
    // When sent to a client a new connection will be made to the person who sent it. This packet must not be relayed
    MAGICNET_PACKET_TYPE_MAKE_NEW_CONNECTION,
    // Super downloads allow a client to download a large amount of blocks from the peer without the natural delay
    // caused by other packets. The download is done 20 blocks at a time in a single packet.
    MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_REQUEST,
    // Sent when theirs no more blocks to send. Also sent if the inital start block couldnt be found.
    MAGICNET_PACKET_TYPE_BLOCK_SUPER_DOWNLOAD_DONE,
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
    MAGICNET_ERROR_TOO_LARGE = -1006,
    // Sent when data was believed to be available but during a running algorithm the data became non-existant or incorrect.
    MAGICNET_ERROR_DATA_NO_LONGER_AVAILABLE = -1007,
    MAGICNET_ERROR_INCOMPATIBLE = -1008,

    // Critical errors will terminate connections when received be cautious..
    // You may not send a critical error over the network it will be ignored and changed to an unknown error
    MAGICNET_ERROR_CRITICAL_ERROR = -1,
    MAGICNET_ACKNOWLEGED_ALL_OKAY = 0,
    // Sometimes returned for certain operations when something is completed.
    MAGICNET_TASK_COMPLETE = 200,
    MAGICNET_BLOCK_SENT_BEFORE = 201,
    MAGICNET_CREATED = 202,
    MAGICNET_UPDATED = 203,
};

// ENTRY PROTOCOL
enum
{
    MAGICNET_ENTRY_PROTOCOL_NO_IPS = 0,
    MAGICNET_ENTRY_PROTOCOL_HAS_IPS = 1,
    MAGICNET_ENTRY_PROTOCOL_NO_PEER_INFO_PROVIDED = 2,
    MAGICNET_ENTRY_PROTOCOL_PEER_INFO_PROVIDED = 3,
};

// Reserved transaction types.. Custom types should use type of 1000 and above
// We have this because their are special types of transactions deep in the abstraction where the data pointer
// can contain important structured data known to the protocol
// examples include sending coins.
enum
{
    MAGICNET_TRANSACTION_TYPE_UNKNOWN = 0,
    MAGICNET_TRANSACTION_TYPE_COIN_SEND = 1,
};

struct block;
struct blockchain;

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
                    struct block_transaction *transaction;
                } transaction_send;

                struct magicnet_new_connection
                {
                    // The entry ID for the connection. Sent by connector so we know how to route the controller of the new client.
                    int entry_id;
                    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
                } new_connection;

                struct magicnet_block_send
                {
                    // a vector of struct block* that holds the blocks we are sending.
                    // A copy of the exact same block is expected for each blockchain known by the peer
                    struct vector *blocks;
                    // The group of transactions associated with all blocks in the vector above.
                    struct block_transaction_group *transaction_group;
                } block_send;

                struct magicnet_request_block
                {
                    char request_hash[SHA256_STRING_LENGTH];
                    int signal_id;
                } request_block;

                /**
                 * Response for the request block. Once received block group send can be initiated.
                 * Receving this means we can connect on another thread and download the blocks until satisfied.
                 */
                struct magicnet_request_block_response
                {
                    char request_hash[SHA256_STRING_LENGTH];
                    int signal_id;
                } request_block_response;

                struct magicnet_block_group_send
                {
                    char begin_hash[SHA256_STRING_LENGTH];
                    // Vector of struct block*
                    struct vector *blocks;
                } block_group_send;

                struct magicnet_block_super_download
                {
                    char begin_hash[SHA256_STRING_LENGTH];
                    size_t total_blocks_to_request;
                } block_super_download;
            };
        } payload;
    } signed_data;
};

enum
{
    // When set the server will not send relayed packets to this client.
    MAGICNET_COMMUNICATION_FLAG_NO_RELAYED_PACKETS = 0b00000001
};

struct magicnet_peer_information
{
    char ip_address[MAGICNET_MAX_IP_STRING_SIZE];
    struct key key;
    char name[MAGICNET_MAX_NAME_SIZE];
    char email[MAGICNET_MAX_EMAIL_SIZE];
    int found_out;
};

/**
 * @brief The magicnet_peer_blockchain_info struct to describe peer information relating to a particular blockchain
 * // Since blockchains can change the information about a peer this is neccessary for when their are forks.
 */
struct magicnet_peer_blockchain_info
{
    char key[SHA256_STRING_LENGTH];
    double money;
    int blockchain_id;
};

struct magicnet_client
{
    int sock;
    // The flags must not be instructed by any remote party. These flags are for this server instance only
    // not to be set or updated by command of a remote host.
    int flags;

    // This is our ipv4 ip address from the prespective of the connected client.
    // We store per client to prevent someone telling us an ip address is ours when it is not.
    // Our real ip address is the one that most peers think is ours.
    char my_ip_address_to_client[MAGICNET_MAX_IP_STRING_SIZE];

    // Communication flags are set in the entry protocol they determine the type of packets this peer is willing to accept.
    int communication_flags;
    time_t last_contact;

    time_t connection_began;

    // The total bytes this client has ever sent
    size_t total_bytes_sent;

    // The total bytes this client has ever received
    size_t total_bytes_received;

    // Upload microsecond delay.
    time_t send_delay;

    // Download microsecond delay
    time_t recv_delay;

    // The total bytes we want to send per second. Rate limiting system..
    size_t max_bytes_send_per_second;

    // Max bytes received per second
    size_t max_bytes_recv_per_second;

    // When the current time exceeds this time the max bytes per second is reset to the MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND
    time_t reset_max_bytes_to_send_at;

    time_t reset_max_bytes_to_recv_at;

    // signal id variable If this is non zero then upon a connection being accepted we will post the semaphore
    // giving control to the signal. We will not process this client on its own thread and any existing thread will be killed
    // when it is found that the signal is present
    int signal_id;

    char program_name[MAGICNET_PROGRAM_NAME_SIZE];

    /**
     * Used for localhost applications. Anything added here is an awaiting packet for the application that is listening to this
     * program name. These awaiting packets will be received directly by the localhost application requesting them.
     */
    struct magicnet_packet awaiting_packets[MAGICNET_MAX_AWAITING_PACKETS];

    /**
     * These are the packets that are directly for this connected client. When a sync packet is used we will send the
     * next packet from this array to this client in question.
     */
    struct packets_for_client
    {
        struct magicnet_packet packets[MAGICNET_MAX_AWAITING_PACKETS];
        off_t pos_read;
        off_t pos_write;
    } packets_for_client;

    struct sockaddr_in client_info;

    struct magicnet_peer_information peer_info;
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

// This is used for calculating the ip address of our client. The total count is how many peers
// believe the ip address to be ours. We need this system to prevent fakers telling us ips that we are not.
struct magicnet_ip_count
{
    char ip_address[MAGICNET_MAX_IP_STRING_SIZE];
    size_t count;
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

    // vector of pthread_t . Holds all the thread ids for every thread created in this server instance.
    struct vector *thread_ids;
    // Clients our server accepted.
    struct magicnet_client clients[MAGICNET_MAX_INCOMING_CONNECTIONS];

    // Clients our server initiated the connection for
    struct magicnet_client outgoing_clients[MAGICNET_MAX_OUTGOING_CONNECTIONS];

    // This is the last client that sent a block to us.
    struct magicnet_client *last_client_to_send_block;

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
        struct vector *block_transactions;

        // The step in the block creation sequence we are currently in.
        int step;

    } next_block;


    // Vector of struct self_block_transaction* all transactions in here are unsigned. These are transactions waiting to be sent
    // but havent been sent yet to the network.
    struct vector* our_waiting_transactions;
    
    // The timestamp the server started
    time_t server_started;
    // THe first time the block cycle begins for this server instance
    time_t first_block_cycle;
    pthread_rwlock_t lock;

    // When true the server will refuse new connections and attempt to shutdown.
    bool shutdown;
    // BELOW MUST BE PROCESSED ONLY BY THE SERVER THREAD
    off_t last_new_connection_attempt;

    // This is our ipv4 ip address based on what all connected clients have told us it is.
    // empty if not known.
    char our_ip[MAGICNET_MAX_IP_STRING_SIZE];

    // This is true if we are able to accept incoming connections from our IP address. If this is false
    // we are unable to receive incoming traffic and can only create ourgoing connections.
    // THis is not something we choose, we either can receive traffic or we cannot. This boolean if it is true
    // means we have successfully tested that we are able to receive incoming connections.
    bool port_forwarded;
};

struct block_transaction_data
{
    // The program name who this transaction is intended for.. All listening to this program
    // will have access to the transaction
    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
    time_t time;
    // This is the bid that the signer has wedged. This is the amount of money they are willing to pay to put a transaction
    // on the next block. Zero is completley valid, theirs a certain amount of transactions allowed in a block.
    // If your bid is lower than someone elses and we run out of transactions for the next block, we will begin to remove transactions
    // whose bid is lower than the  bidder who has no room in the next block. The new bidder will then take their place.
    // The bid money disappears forever, never being sent to anyone. It deflates the currency.
    // If a peer bids an amount that he does not have then the transaction is dropped.
    // If a peer bids and the receiver of the transaction is not aware of the peer then they cannot prove the balance of the peer therefore
    // the peer transaction is dropped.
    double bid;
    char *ptr;
    size_t size;
};

struct block_transaction_group
{
    // The hash of all combined transactions in this block transaction group.
    char hash[SHA256_STRING_LENGTH];
    size_t total_transactions;

    // Pointer arrayto the loaded transactions data in memory
    struct block_transaction *transactions[MAGICNET_MAX_TOTAL_TRANSACTIONS_IN_BLOCK];
};

struct block_transaction
{
    char hash[SHA256_STRING_LENGTH];

    // The hash of the transaction group  that this transaction belongs to
    char transaction_group_hash[SHA256_STRING_LENGTH];

    // The type of transaction. Can be a custom integer, should be over 1000 for non protocol related transactions
    // i.e custom applications
    int type;

    // Signed signature of the creator of the transaction.
    struct signature signature;
    // The public key of the creator of the transaction
    struct key key;

    // The public key of the target key of this transaction
    // Some transactions may have both a signer key and a transaction target...
    // For example in the case of a money send transaction a target key could be the recipient.
    // In other examples maybe an admin of a decentralized app is issueing a transaction that bans someone..
    // In that case the target key could be the key of who is being banned..
    // This field is useful as it means we dont have to load the data from the database to be able to bring back records about
    // certain keys.
    struct key target_key;

    // Pointer to raw data of the transacton known only by the application using the network
    struct block_transaction_data data;
};


// Transaction states
enum
{
    // The transaction must be signed, hash generated and then sent to the network
    BLOCK_TRANSACTION_STATE_PENDING_SIGN_AND_SEND,
    // The transaction was sent and is now on the blockchain that is shared around the network.
    BLOCK_TRANSACTION_STATE_COMPLETED_AND_ON_CHAIN,
    // The transaction we added has failed either due to the transaction data being valid or six block cycles have passed
    // that have not included our transaction. After 6 tries we abort.
    BLOCK_TRANSACTION_STATE_FAILED,
    // The transaction is no longer on the blockchain, possibly due to a chain fork and the new chain becoming the popular one
    // and not containing our transaction.
    BLOCK_TRANSACTION_STATE_TRANSACTION_VOIDED,
    // The transaction was cancelled by the sender. May only be cancelled when it is not sent to the network yet.
    // after the network has seen the transaction cancellation is no longer possible.
    // If we receive a block with a transaction that we cancelled we will change its state to BLOCK_TRANSACTION_STATE_COMPLETED_AND_ON_CHAIN
    BLOCK_TRANSACTION_STATE_CANCELLED,
};

/**
 * Represents a transaction that was created on our local machine, that may or may not have been sent to the network yet
*/
struct self_block_transaction
{
    struct block_transaction* transaction;
    // The state of our transaction
    int state;
    // A message declaring the state of the message (If any)
    char status_message[MAGICNET_MAX_SMALL_STRING_SIZE];
};

/**
 * Custom block transaction types
 */

struct block_transaction_money_funding_source_and_amount
{
    // Where are we getting the "amount" from? What transaction is funding this transfer.
    // Basically we reference a transaction that has already been added to the blockchain where we received money.
    char funding_transaction_hash[SHA256_STRING_LENGTH];

    // The amount of money being sent
    double amount;
};

// Block transaction type for money transfer
struct block_transaction_money_transfer
{
    // Since some funding sources might only have a balance of like 10 coins and maybe you want to send 12 coins we need
    // multiple funding sources to send money.
    // This way you could have one funding source that uses 10 coins
    // and another that uses two. completing the transfer.
    struct block_transaction_money_funding_source_and_amount transfer_funding[MAGICNET_MONEY_TRANSACTION_TOTAL_FUNDING_SOURCES];
    // The public key of the recipient
    struct key recipient_key;


    // The amount of money being sent. This is the sum of all transfer funding amounts. It is required to ensure
    // you confirm the amount of money being sent.
    // If the sum of all funding amounts differs from the amount the transaction will be rejected as it will be assumed it was a bug in the
    // applciation making the transaction.
    // However if all the transfer funding is NULL then when a local program sends the packet to the localhost server
    // The server will calculate the transfer funding array to match the amount provided.
    // If the server is unable to fill the array with  funding sources that reach the amount provided then the transaction will be rejected.
    double amount;

    // The sender is the person who signed the transaction.

};
/**
 * This is a structure representing banned peer information it represents the table in database.c
 */
struct magicnet_banned_peer_information
{
    int id;

    // The ip address of the banned peer
    char ip_address[MAGICNET_MAX_IP_STRING_SIZE];

    struct key key;

    // The time the peer was banned
    time_t banned_at;
    // The time the peer will be unbanned
    time_t banned_until;
};

enum
{
    // MAGICNET_BLOCKCHAIN_TYPE_UNIQUE_CHAIN - specifies that this chain has no shared history with any other chain, it is unique.
    MAGICNET_BLOCKCHAIN_TYPE_UNIQUE_CHAIN,
    // MAGICNET_BLOCKCHAIN_TYPE_SPLIT_CHAIN - specifies that this chain was created from a previous existing chain that split into two directions
    MAGICNET_BLOCKCHAIN_TYPE_SPLIT_CHAIN,
    // MAGICNET_BLOCKCHAIN_TYPE_INCOMPLETE - specifies an incomplete blockchain that should not be taken serioiusly until the chain is completed. Once that happens its type will change to the appropaite new type for the completed blockchain.
    MAGICNET_BLOCKCHAIN_TYPE_INCOMPLETE,

    // Returned when we should not create a new blockchain.
    MAGICNET_BLOCKCHAIN_TYPE_NO_NEW_CHAIN,
};
typedef int BLOCKCHAIN_TYPE;
struct blockchain
{
    int id;
    BLOCKCHAIN_TYPE type;
    char begin_hash[SHA256_STRING_LENGTH];
    char last_hash[SHA256_STRING_LENGTH];

    // The blockchain with the highest count is the active chain.
    size_t proved_verified_blocks;
};

struct block
{

    // Hash of this block
    char hash[SHA256_STRING_LENGTH];
    // Hash of the previous block
    char prev_hash[SHA256_STRING_LENGTH];

    // Signed signature of the creator of the block
    struct signature signature;
    // The public key of the creator of the block.
    struct key key;

    struct block_transaction_group *transaction_group;

    // LOCAL DATA ONLY The below data is not sent across the network
    int blockchain_id;
};

struct magicnet_chain_downloader;
struct magicnet_chain_downloader_hash_to_download
{
    char hash[SHA256_STRING_LENGTH];

    // Equal to the time we last requested this block. Zero if we have not requested it yet.
    time_t last_request;
};

struct magicnet_chain_downloader
{
    // Vector of  magicnet_chain_downloader_hash_to_download* . Must free the pointers when done.
    struct vector *hashes_to_download;

    // The current total blocks downloaded
    size_t total_blocks_downloaded;

    // Also used as an identifier for the chain downloader iD.
    pthread_t thread_id;

    // The server
    struct magicnet_server *server;

    // When true this thread should terminate its self at the next possible moment
    bool finished;

    // When a peer thread recognizes the whole chain has been downloaded it will set this to true.
    bool download_completed;
};

/**
 * Represents the active chain downloads.
 */
struct magicnet_active_chain_downloads
{
    // Vector of struct magicnet_chain_downloader*
    struct vector *chain_downloads;
    pthread_mutex_t lock;
};

struct magicnet_connection_exchange_peer_data
{
    struct in_addr sin_addr;
    struct key public_key;
};

enum
{
    MAGICNET_CLIENT_FLAG_CONNECTED = 0b00000001,
    MAGICNET_CLIENT_FLAG_SHOULD_DELETE_ON_CLOSE = 0b00000010,
    // True if this connection is from an IP address on our local machine.
    MAGICNET_CLIENT_FLAG_IS_LOCAL_HOST = 0b00000100,
    // True if this client is an outgoing connection made with connect()
    MAGICNET_CLIENT_FLAG_IS_OUTGOING_CONNECTION = 0b00001000,
};

enum
{
    // An outgoing connection type means that we connected to a server
    MAGICNET_CONNECTION_TYPE_OUTGOING,
    // An incoming connection type means that a server connected to us.
    MAGICNET_CONNECTION_TYPE_INCOMING,
};

int magicnet_chain_downloader_queue_for_block_download(const char *block_hash);
int magicnet_chain_downloaders_setup_and_poll(struct magicnet_server *server);
void magicnet_server_read_lock(struct magicnet_server *server);
void magicnet_server_lock(struct magicnet_server *server);
void magicnet_server_unlock(struct magicnet_server *server);
void magicnet_server_shutdown_server_instance(struct magicnet_server *server);
struct magicnet_client *magicnet_tcp_network_connect(struct sockaddr_in addr, int flags, int communication_flags, const char *program_name);
struct magicnet_client *magicnet_client_new();
void magicnet_client_free(struct magicnet_client *client);
bool magicnet_connected(struct magicnet_client *client);
void magicnet_close(struct magicnet_client *client);
void magicnet_close_and_free(struct magicnet_client *client);
int magicnet_client_connection_type(struct magicnet_client *client);
struct magicnet_client *magicnet_connect_again(struct magicnet_client *client, const char *program_name);
struct magicnet_client *magicnet_connect_for_key(struct magicnet_server *server, struct key *key, const char *program_name);

int magicnet_server_add_packet_to_relay(struct magicnet_server *server, struct magicnet_packet *packet);

struct signed_data *magicnet_signed_data(struct magicnet_packet *packet);

int magicnet_network_thread_start(struct magicnet_server *server);
struct magicnet_server *magicnet_server_start();
struct magicnet_client *magicnet_accept(struct magicnet_server *server);
int magicnet_client_thread_start(struct magicnet_client *client);
int magicnet_client_preform_entry_protocol_write(struct magicnet_client *client, const char *program_name, int communication_flags, int signal_id);
struct magicnet_client *magicnet_tcp_network_connect_for_ip(const char *ip_address, int port, int flags, const char *program_name);
int magicnet_next_packet(struct magicnet_program *program, void **packet_out);
int magicnet_client_read_packet(struct magicnet_client *client, struct magicnet_packet *packet_out);
int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet, int flags);
int magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet);
int magicnet_client_entry_protocol_read_known_clients(struct magicnet_client *client);
int magicnet_client_entry_protocol_write_known_clients(struct magicnet_client *client);
struct magicnet_client *magicnet_server_get_client_with_key(struct magicnet_server *server, struct key *key);
int magicnet_relay_packet_to_client(struct magicnet_client *client, struct magicnet_packet *packet);

/**
 * Pushes all connected ip addresses to the output vector.
 *
 * Output vector should be sizeof(struct sockaddr_in)
 */
void magicnet_server_push_outgoing_connected_ips(struct magicnet_server *server, struct vector *vector_out);

/**
 * @brief Makes a transaction on the network which will eventually be put into a block.
 *
 * @param program
 * @param data
 * @param size
 * @return int
 */
int magicnet_make_transaction(struct magicnet_program* program, int type, void* data, size_t size);

int magicnet_send_pong(struct magicnet_client *client);
void magicnet_free_packet(struct magicnet_packet *packet);
void magicnet_free_packet_pointers(struct magicnet_packet *packet);
struct magicnet_packet *magicnet_packet_new();
int magicnet_init();
int magicnet_get_structure(int type, struct magicnet_registered_structure *struct_out);
int magicnet_register_structure(long type, size_t size);
struct magicnet_program *magicnet_program(const char *name);
/**
 * Makes a money transfer to the recipient
 * \param to The recipient's public key
 * \amount The amount to transfer
*/
int magicnet_make_money_transfer(struct magicnet_program* program, const char* to, double amount);


// Shared network functions
int magicnet_server_get_next_ip_to_connect_to(struct magicnet_server *server, char *ip_out);
struct magicnet_client *magicnet_tcp_network_connect_for_ip_for_server(struct magicnet_server *server, const char *ip_address, int port, const char *program_name, int signal_id);

void magicnet_server_free(struct magicnet_server *server);
/**
 * @brief Creates a new block in memory, no block is added to the chain.
 *
 * @param hash
 * @param prev_hash
 * @param data
 * @param len
 * @return struct block*
 */

struct block *block_create_with_group(const char *hash, const char *prev_hash, struct block_transaction_group *group);
struct block *block_create(struct block_transaction_group *transaction_group, const char *prev_hash);
const char *block_transaction_group_hash_create(struct block_transaction_group *group, char *hash_out);
struct block_transaction_group *block_transaction_group_clone(struct block_transaction_group *transaction_group_in);
struct block *block_load(const char *hash);
int block_load_transactions(struct block *block);

int block_save(struct block *block);
int block_sign(struct block *block);
void block_free(struct block *block);
void block_free_vector(struct vector *block_vec);
bool block_transaction_is_signed(struct block_transaction *transaction);

bool sha256_empty(const char *hash);

int blockchain_init();
struct blockchain *blockchain_new();
void blockchain_free(struct blockchain *blockchain);
struct blockchain *magicnet_blockchain_get_active();
int magicnet_blockchain_get_active_id();

struct block *block_clone(struct block *block);
struct block_transaction *block_transaction_new();
struct self_block_transaction* block_self_transaction_new(struct block_transaction* transaction);

struct block_transaction_group *block_transaction_group_new();
void block_transaction_group_free(struct block_transaction_group *transaction_group);

struct block_transaction *block_transaction_new();
struct block_transaction *block_transaction_clone(struct block_transaction *transaction);
void block_transaction_free(struct block_transaction *transaction);
struct block_transaction *block_transaction_build(const char *program_name, char *data, size_t data_len);
int block_transaction_add(struct block_transaction_group *transaction_group, struct block_transaction *transaction);
int block_transaction_valid(struct block_transaction *transaction);
int block_transaction_hash_and_sign(struct block_transaction *transaction);
bool block_transaction_is_signed(struct block_transaction *transaction);

int block_verify(struct block *block);
int block_hash_sign_verify(struct block *block);
void magicnet_get_block_path(struct block *block, char *block_path_out);
const char *block_hash_create(struct block *block, char *hash_out);
struct block *magicnet_block_load(const char *hash);

// Blockchain downloader
struct magicnet_chain_downloader *magicnet_chain_downloader_download(struct magicnet_server *server);
void magicnet_chain_downloader_hash_add(struct magicnet_chain_downloader *downloader, const char *hash);
int magicnet_chain_downloader_start(struct magicnet_chain_downloader *downloader);
void magicnet_chain_downloader_blocks_catchup(struct magicnet_server *server);
bool magicnet_default_downloader_is_hash_queued(const char *hash);
int magicnet_chain_downloader_post_client_with_block(pthread_t thread_id, struct magicnet_client *client);
void magicnet_chain_downloaders_shutdown();
void magicnet_chain_downloaders_cleanup();

// Banned peer functionality
bool magicnet_peer_ip_is_banned(const char *ip_address);
int magicnet_save_peer_info(struct magicnet_peer_information *peer_info);

#endif