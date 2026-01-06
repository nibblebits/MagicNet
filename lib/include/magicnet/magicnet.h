
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

struct magicnet_packet;
struct magicnet_client;
typedef int (*PROCESS_PACKET_FUNCTION)(struct magicnet_client* client, struct magicnet_packet* packet);

#define PACKET_PACKET_SIZE_FIELD_SIZE sizeof(int)

struct magicnet_client;
struct magicnet_buffer_stream_private_data
{
    struct magicnet_client *client;
    // The buffer to write all data too after its been sent to the network
    struct buffer *write_buf;
};
// Initialization flags for magicnet
enum
{
    MAGICNET_INIT_FLAG_NO_STDOUT_GENERAL_LOGGING = 0b00000001,
    MAGICNET_INIT_FLAG_NO_STDOUT_WARNING_LOGGING = 0b00000010,
    MAGICNET_INIT_FLAG_NO_STDOUT_ERROR_LOGGING = 0b00000100,
    // When set we will block on certain requests in magicnet.c wait forever.
    MAGICNET_INIT_FLAG_ENABLE_BLOCKING = 0b00001000,
    MAGICNET_INIT_FLAG_USE_PROGRAMS = 0b00010000
};

struct magicnet_registered_structure
{
    // Numerical ID determined by the application using this network. This is the structure ID
    long type;
    // The size of the structure in bytes
    size_t size;
};

struct magicnet_client;

enum
{
    MAGICNET_EVENT_TYPE_NOT_USED,
    // Sent to test the event system does nothing at all. for debugging only.
    MAGICNET_EVENT_TYPE_TEST,
    MAGICNET_EVENT_TYPE_NEW_BLOCK,
};
struct magicnet_event
{
    int id;
    int type;
    struct data
    {
        union
        {
            struct magicnet_event_type_block
            {
                struct block *block;
            } new_block_event;
        };
    } data;
};

struct magicnet_program
{
    char name[MAGICNET_PROGRAM_NAME_SIZE];
    struct magicnet_client *client;
};

enum
{
    #warning "NOTE TO SELF THERES MEMORY CORRUPTION ON PACKET SEND. pROVEN AS empty packet is now 7000 yet packet type still zero"
    MAGICNET_PACKET_TYPE_EMPTY_PACKET = 7000,
    MAGICNET_PACKET_TYPE_LOGIN_PROTOCOL_IDENTIFICATION_PACKET,

    // To be sent once both parties have authenticated with eachother
    // this confirms they are ready to communicate.
    MAGICNET_PACKET_TYPE_OPEN_DOOR,
    MAGICNET_PACKET_TYPE_OPEN_DOOR_ACK,
    MAGICNET_PACKET_TYPE_USER_DEFINED,
    MAGICNET_PACKET_TYPE_EVENTS_POLL,
    MAGICNET_PACKET_TYPE_EVENTS_RES,
    MAGICNET_PACKET_TYPE_POLL_PACKETS,

    // Request some data and expect a response.
    MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND,
    MAGICNET_PACKET_TYPE_REQUEST_AND_RESPOND_RESPONSE,
    MAGICNET_PACKET_TYPE_PING,
    MAGICNET_PACKET_TYPE_PONG,
    MAGICNET_PACKET_TYPE_SERVER_SYNC = 200,
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
    MAGICNET_PACKET_TYPE_TRANSACTION_LIST_REQUEST,
    MAGICNET_PACKET_TYPE_TRANSACTION_LIST_RESPONSE,
    MAGICNET_PACKET_TYPE_NOT_FOUND,
};

enum
{
    MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE = 0b00000001,
    MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING = 0b00000010,
    MAGICNET_PACKET_FLAG_MUST_BE_SIGNED = 0b00000100,
    // The below flag is set if the packet has been signed by a council member who has provided his certificate.
    MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE = 0b00001000,

};

#define MAGICNET_PACKET_PRIVATE_FLAGS (MAGICNET_PACKET_FLAG_IS_AVAILABLE_FOR_USE | MAGICNET_PACKET_FLAG_IS_READY_FOR_PROCESSING | MAGICNET_PACKET_FLAG_MUST_BE_SIGNED)
enum
{
    MAGICNET_BLOCK_SAVE_FLAG_NONE = 0,
    // Preforms a weak verification, only checks the signature and that the key that signed it is  valid.
    // Ignores verification of money transfers and other such things.. This is ideal for chain downloads when its not possible
    // to know right away if a transaction is completely valid. But we will assume that it is valid because
    // for it to end up as the active chain most of the network would of had to approve the block at some point.
    MAGICNET_BLOCK_SAVE_FLAG_WEAK_VERIFY = 1
};

enum
{
    MAGICNET_BLOCK_VERIFICATION_VERIFY_SIGNATURE = 0b000000001,
    MAGICNET_BLOCK_VERIFICATION_VERIFY_TIMESTAMP = 0b000000010,
    MAGICNET_BLOCK_VERIFICATION_VERIFY_TRANSACTIONS = 0b000000100,
    MAGICNET_BLOCK_VERIFICATION_VERIFY_TRANSACTION_DATA = 0b000001000,
};

#define MAGICNET_BLOCK_VERIFICATION_VERIFY_ALL (MAGICNET_BLOCK_VERIFICATION_VERIFY_SIGNATURE | MAGICNET_BLOCK_VERIFICATION_VERIFY_TIMESTAMP | MAGICNET_BLOCK_VERIFICATION_VERIFY_TRANSACTIONS | MAGICNET_BLOCK_VERIFICATION_VERIFY_TRANSACTION_DATA)
#define MAGICNET_BLOCK_VERIFICATION_VERIFY_WITHOUT_TRANSACTION_DATA (MAGICNET_BLOCK_VERIFICATION_VERIFY_ALL) & ~MAGICNET_BLOCK_VERIFICATION_VERIFY_TRANSACTION_DATA
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
    MAGICNET_ERROR_INVALID_PARAMETERS = -1008,
    MAGICNET_ERROR_END_OF_STREAM = -1009,
    MAGICNET_DATA_SENT_BEFORE = -1010,
    MAGICNET_ERROR_OUT_OF_BOUNDS = -1011,
    MAGICNET_ERROR_TRY_AGAIN = -1012,
    MAGICNET_ERROR_OUT_OF_MEMORY = -1013,

    // Critical errors will terminate connections when received be cautious..
    // You may not send a critical error over the network it will be ignored and changed to an unknown error
    MAGICNET_ERROR_CRITICAL_ERROR = -1,
    MAGICNET_ACKNOWLEGED_ALL_OKAY = 0,
    // Sometimes returned for certain operations when something is completed.
    MAGICNET_TASK_COMPLETE = 200,
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
    MAGICNET_TRANSACTION_TYPE_INITIATE_CERTIFICATE_TRANSFER = 2,
    // Issued by a key who wishes to claim a certificate, it will be rejected if the peer did not win any transfer vote or has no right to that certificate he is claiming.
    MAGICNET_TRANSACTION_TYPE_CLAIM_CERTIFICATE = 3,
};

struct block;
struct blockchain;

struct magicnet_transactions
{
    size_t amount;
    // An array of block transactions
    struct block_transaction **transactions;
};

enum
{
    MAGICNET_TRANSACTIONS_REQUEST_FLAG_INITIALIZED = 0b00000001,
    // Signifies that we should search for either the key or the target key, without this flag
    // both will be required to be equal for a transaction to be returned.
    MAGICNET_TRANSACTIONS_REQUEST_FLAG_KEY_OR_TARGET_KEY = 0b00000010,
};

struct magicnet_transactions_request
{
    int flags;

    // This it not NULL if the request must only bring back transactions with the given transaction group hash
    char transaction_group_hash[SHA256_STRING_LENGTH];

    // The block hash to load, this is set while loading transactions using the request
    // it can also be set prior to the request in which case it will load the block with the hash you provided
    // and look for transactions. By default loading transactions will change this block hash to the hash of the next block  to load
    char block_hash[SHA256_STRING_LENGTH];

    // Null key if we do not care who made the transaction
    struct key key;
    // nulL key if we do not care what the target key is
    // target key
    struct key target_key;

    // -1 iF WE WISH to bring back all transactions
    int type;
    int total_per_page;
    int page;
};

struct request_and_respond_input_data
{
    void *input;
    size_t size;
};

struct request_and_respond_output_data
{
    void *output;
    size_t size;
};

struct magicnet_peer_information
{
    char ip_address[MAGICNET_MAX_IP_STRING_SIZE];
    struct key key;
    char name[MAGICNET_MAX_NAME_SIZE];
    char email[MAGICNET_MAX_EMAIL_SIZE];
    int found_out;
};


struct login_protocol_identification_peer_info
{
    struct magicnet_peer_information info;
    struct signature signature;
    // Hash of the info..
    char hash_of_info[SHA256_STRING_LENGTH];
};

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

        // The total read bytes of this packet, when it is >= expected_size
        // then the packet is ready for processing
        int total_read_bytes;
    } not_sent;

    struct signed_data
    {
        // Random ID for the packet, prevents duplicate packets.
        int id;
        // The type of this packet see above.
        int type;
        // The expected size of the packet, this is the data that needs to be read or was read
        // to complete the craft of the packet, not neccessarily the amount of data
        // that the packet uses in memory.
        int expected_size;

        int flags;

        // When a packet is sent from someone who holds a council certificate, they should
        // send there certificate with the packet. This is used to verify the packet for council operations.
        // you dont need to provide the certificate if the packet is not a council operation it becomes optional.
        // The MAGICNET_PACKET_FLAG_CONTAINS_MY_COUNCIL_CERTIFICATE flag must be set if the my_certificate is provided.
        struct magicnet_council_certificate *my_certificate;

        struct payload
        {
            union
            {

                struct login_protocol_identification
                {

                    // NOTE: NOT VERIFIED UNTIL THE PACKET WAS PROCESSED!
                    // BELIEVE EVERYTHIGN TO BE FALSE UNTIL THEN
                    
                    // COME BACK AND TRY ABSTRACT THIS OUT...
                    struct login_protocol_identification_peer_info peer_info;
                    
                    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
                    int communication_flags;
                    int signal_id;

                    // Vector of struct magicnet_peer_information*
                    // these peers are known by the peer who signed this packet.
                    // we can connect to them later expanding our network.
                    struct vector* known_peers;

                } login_protocol_iden;
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

                struct events_poll
                {
                    // The total events to request
                    size_t total;
                } events_poll;

                struct events_poll_res
                {
                    // The total events responded with
                    size_t total;
                    // A vector of struct magicnet_event*
                    struct vector *events;
                } events_poll_res;

                struct request_and_respond
                {
                    // The numeric type of the particular request we are making
                    int type;
                    int flags;
                    // The data that helps us locate the information we are requesting
                    struct request_and_respond_input_data *input_data;

                } request_and_respond;

                struct request_and_respond_response
                {
                    // The numeric type of the request
                    int type;
                    int flags;

                    struct request_and_respond_input_data *input_data;
                    struct request_and_respond_output_data *output_data;

                } request_and_respond_response;

                struct sync
                {
                    int flags;
                    struct magicnet_packet *packet;
                } sync;

                struct ping
                {
                    // no data for ping yet.
                } ping;

                struct open_door
                {
                    // No payload for open door packet yet
                    // actually we can have a unique id of some kind
                    // This id must match same as the one we sent
                    // when we tried to open the door to them.
                    // or packet shall drop.
                    int door_key;
                } open_door;

                struct open_door_ack
                {
                    // acknowledge the door key..
                    int door_key;
                } open_door_ack;

                /**
                 * This packet describes a VOTE of the key who should verify the next block.
                 * SOme better abstraction would be better i think, come back to revise...
                 */
                struct magicnet_vote
                {
                    // Contains the certificate hash of whome this vote is for.
                    // If enough people vote for this certificate they will create the next block
                    // all blocks signed whome are not the winner will be rejected.
                    char vote_for_cert[SHA256_STRING_LENGTH];
                } vote_next_verifier;

                /**
                 * @brief The verifier with a validate certificate may sign up to sign the next block
                 */
                struct magicnet_verifier_signup
                {
                    // The valid council certificate that wishes to sign the next block.
                    struct magicnet_council_certificate *certificate;
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
                    struct vector *blocks;

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

                struct magicnet_transaction_list_request
                {
                    struct magicnet_transactions_request req;
                } transaction_list_request;

                struct magicnet_transaction_list_response
                {
                    struct magicnet_transactions_request req;

                    int total_transactions;
                    // Vector of struct block_transaction*
                    struct vector *transactions;
                } transaction_list_response;
            };
        } payload;
    } signed_data;
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

enum
{
    // Peer sent us login protocol and completed it correctly
    MAGICNET_CLIENT_STATE_FLAG_PEER_COMPLETED_LOGIN_PROTOCOL = 0b00000001,
    // We sent login protocol correctly to the peer.
    MAGICNET_CLIENT_STATE_FLAG_WE_SENT_LOGIN_PROTOCOL = 0b00000010,
    // Set if this peer has opened the door from his side
    MAGICNET_CLIENT_STATE_FLAG_DOOR_OPEN_SENT = 0b00000100,
    // Set if the peer has opened the door on his side
    MAGICNET_CLIENT_STATE_FLAG_DOOR_OPEN_RECV = 0b00001000,
    // Set when the door is mutually opened on both sides
    MAGICNET_CLIENT_STATE_FLAG_DOOR_OPENED = 0b00010000
};

enum
{
    MAGICNET_CLIENT_STATE_AWAITING_LOGIN_PACKET_MUST_READ = 1,
    MAGICNET_CLIENT_STATE_AWAITING_LOGIN_PACKET_MUST_WRITE = 2,
    MAGICNET_CLIENT_STATE_IDLE_WAIT = 3,
    MAGICNET_CLIENT_STATE_PACKET_READ_PACKET_NEW = 4,
    MAGICNET_CLIENT_STATE_PACKET_READ_PACKET_FINISH_READING = 5,
    MAGICNET_CLIENT_STATE_MUST_SEND_PING = 6,
    MAGICNET_CLIENT_STATE_MUST_OPEN_DOOR = 7,
};

typedef int magicnet_client_state;

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
    time_t last_packet_received;
    time_t last_packet_sent;

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

    // THe unique key shared between the client
    // and other peer that confirms the opening of the door
    // the first to open the door shall generate the key
    // the receiver must send the same key back to establish the door opened.
    struct door_keys
    {
        int our_key;
        int their_key;
    } door_keys;
    

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

    // These are pending events for this client, events only apply to localhost clients and are a way for
    // the server to inform a local listning client of a particular event that has happend such as a new block being created
    // or a key being requested.
    // Any events pushed to a remote client will never be received by the remote client and will clog the vector forever.
    // This might change in the future.
    struct vector *events;

    struct sockaddr_in client_info;

    struct magicnet_peer_information peer_info;
    struct magicnet_server *server;

    struct
    {
        int flags;
    } states;

    // New design we will store all data in memory will not be sent to the client
    // until its flushed.
    struct buffer *unflushed_data;

    // The current unloaded/incomplete packet that we are waiting for from the peer
    // it may have been partially sent at this point. this is an unblocked protocol
    // so we need to be sure the packet is ready before processing.
    struct magicnet_packet *packet_in_loading;
};

// This is the network vote structure to vote for the next block creator
struct magicnet_certificate_vote
{
    // The certificate that voted for the next block creator
    struct magicnet_council_certificate *vote_from_cert;

    // The hash of the certificate that was voted for. This is the person who will create the next block.
    char vote_for_cert_hash[SHA256_STRING_LENGTH];
};

struct magicnet_vote_count
{
    // The hash of the certificate
    char vote_for_cert_hash[SHA256_STRING_LENGTH];
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
    BLOCK_CREATION_SEQUENCE_CALCULATE_VOTED_VERIFIER,
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
            // vector of struct magicnet_certificate_vote*
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

        // Pointer to the created block.
        struct block *created_block;

    } next_block;

    /**
     * The peer who in this cycle is authorized to send us a single block without us requesting.
     * This would be the certificate who won the last vote.
     *
     * All blocks sent to us from anyone other than this peer will be ignored.
     */
    struct authorized_block_creator
    {
        char authorized_cert_hash[SHA256_STRING_LENGTH];
        bool was_block_received;
    } authorized_block_creator;

    // Vector of struct self_block_transaction* all transactions in here are unsigned. These are transactions waiting to be sent
    // but havent been sent yet to the network.
    struct vector *our_waiting_transactions;

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
    // The last known active blockchain block hash at the time of creating the transaction
    char prev_block_hash[SHA256_STRING_LENGTH];

    // The program name who this transaction is intended for.. All listening to this program
    // will have access to the transaction
    char program_name[MAGICNET_PROGRAM_NAME_SIZE];
    time_t time;

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
    // The transaction was signed and sent awaiting delivery now..
    BLOCK_TRANSACTION_STATE_SIGNED_AND_SENT,
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
    struct block_transaction *transaction;
    // The state of our transaction
    int state;
    // A message declaring the state of the message (If any)
    char status_message[MAGICNET_MAX_SMALL_STRING_SIZE];
};

// Block transaction type for money transfer
struct block_transaction_money_transfer
{
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

    // These are the new balances after the transfer is completed. It is rejected by everyone who receives this transfer, if the balances are invalid once taking into account the amount
    struct block_transaction_money_transfer_balances
    {
        double sender_balance;
        double recipient_balance;
    } new_balances;

    // The sender is the person who signed the transaction.
};

enum
{
    // Only possible when the flag MAGICNET_COUNCIL_CERTIFICATE_FLAG_TRANSFERABLE_WITHOUT_VOTE is set in a council certificate.
    COUNCIL_CERTIFICATE_TRANSFER_FLAG_TRANSFER_WITHOUT_VOTE = 0b00000001,

    // Flag is set if the actual certificate object is provided with the transaction
    // All remote peers should reject the transaction if this flag isnt set.
    // Only local clients to the server are allowed to provide no certificate object.
    COUNCIL_CERTIFICATE_TRANSFER_FLAG_INCLUDES_CURRENT_CERTIFICATE = 0b00000010,
    // Can contain the new certificate, can be unsigned or signed
    COUNCIL_CERTIFICATE_TRANSFER_FLAG_INCLUDES_NEW_CERTIFICATE = 0b00000100,
};
/**
 * transaction for initiating a council certificate transfer, this is only a proposal and
 * is not a completed transfer until the votes are in.
 */
struct block_transaction_council_certificate_initiate_transfer_request
{

    // Flags about the transfer
    int flags;

    char certificate_to_transfer_hash[SHA256_STRING_LENGTH];
    struct key new_owner_key;

    // The timestamp when this request for transfer will expire
    // The request expiry must not exceed eight days or it will be rejected.
    // If the transfer is not completed before this time the transfer is voided.
    time_t request_expires_at;

    // The current certificate that is being transferred. Holding the hash of certificate_to_transfer_hash
    struct magicnet_council_certificate *current_certificate;

    // The new_unsigned_certificate will be set to the new certificate that
    // needs to be signed by the peer who won the transfer vote.
    // For now self transfers only exist.
    struct magicnet_council_certificate *new_unsigned_certificate;
};

/**
 * This certificate claim request is used to claim a certificate that was won in a transfer vote.
 */
struct block_transaction_council_certificate_claim_request
{
    char initiate_transfer_transaction_hash[SHA256_STRING_LENGTH];
    // Though we can get the certificate hash from the transaction the user must provide it to ensure their was no mistake.
    char certificate_hash[SHA256_STRING_LENGTH];
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

enum
{
    MAGICNET_COUNCIL_MEMORY_FLAG_COUNCIL_WAS_VERIFIED = 0b00000001,
};

/**
 * The network can have many councils registered
 * applications that created a council are responsible for managing it.
 */
struct magicnet_council_certificate;
struct magicnet_council
{
    struct magicnet_council_signed_data
    {
        struct magicnet_council_id_signed_data
        {
            char name[MAGICNET_COUNCIL_NAME_LENGTH];
            // You can never create more certificates for a council
            // one certificate grants one council vote on decisions.
            // Certificates once expired will be transfeered to a new person to join the council.
            size_t total_certificates;

            // The timestamp of when the council was created.
            time_t creation_time;
        } id_signed_data;

        // The ID hash is used to identify the council
        char id_hash[SHA256_STRING_LENGTH];

        // This is an array of total_certificates and is the state the certificates
        // first began existance in. It does not include transfer information from where certificates
        // got transfeered to other peers.
        // It contians only the very first initial state of the certificate.
        struct magicnet_council_certificate *certificates;
    } signed_data;

    // THe hash of the council signed data. Not to be used for identification.
    // Seek id_hash for identification.
    char hash[SHA256_STRING_LENGTH];

    /**
     * All certificates created by this council must start with the creator
     * as the first owner
     */
    struct magicnet_council_creator
    {
        // Signed signature of the creator of the council.
        struct signature signature;
        // The public key of the creator of the council
        struct key key;
    } creator;

    // Flags used to determine states of the loaded council.
    // The flags are not saved or transfeered over the network
    int memory_flags;

    // This is equal to the default certificate of the person using the software if they have a certificate with this council
    // this is not saved and is for in-memory purposes and preformance reasons only.
    struct magicnet_council_certificate *my_certificate;
};

/**
 *
 * TODO:
 *
 * Some design concerns
 * 1. What if someone on the council creates artifical transfer with himself as the only voter?
 * 2. What if someone extracts only the votes that were for them, forges a certificate and signs it as if they was the block creator
 *
 * Solution is probably a linked list of votes where the signer of a vote has the previous vote as part of his signed data
 * this would mean if someone took a single vote and put it in the votes table the old vote wouldnt be present
 * which would show clear intention of fraud. It is still possible with that solution for someone to create an artifical transfer
 * with himself as the only voter. This can be protected against by discarding all related blocks in the event we ever receive
 * a certificate that shows the same transfer with a much higher vote count. We can then discard all works of the fraudulent certificate.
 */

struct council_certificate_transfer_vote_signed_data
{
    // The hash of the certificate that we want to transfer.
    char certificate_to_transfer_hash[SHA256_STRING_LENGTH];

    // The total voters who voted in the the transfer
    size_t total_voters;
    // The total voters who voted the same key as us
    size_t total_for_vote;
    // The total voters who voted against the key we voted for
    size_t total_against_vote;

    // The timestamp of when the new certificate will expire
    time_t certificate_expires_at;

    // The timestamp of when this certificate becomes valid.
    time_t certificate_valid_from;

    // The key you wish to vote to have the certificate transferred too.
    struct key new_owner_key;

    // The winning key is who we believed won the transfer
    struct key winning_key;
};

struct council_certificate_transfer_vote
{

    // Data signed with the voter_key
    struct council_certificate_transfer_vote_signed_data signed_data;

    // The hash of the signed data
    char hash[SHA256_STRING_LENGTH];

    // The signature of the hash signed by the voter certificate key.
    struct signature signature;

    // The certificate who voted
    struct magicnet_council_certificate *voter_certificate;
};

/**
 * Transfers are only valid where all voters have signed the total voters, total who voted for the same key as them
 * signed the total against them and finally who has signed who the winning key is. If the voters differ in opinion
 * then the transfer is invalid thus the certificate issued is illegal.
 */
struct council_certificate_transfer
{
    // The certificate before a transfer took place
    struct magicnet_council_certificate *certificate;

    // The key who this certificate will be transfeered too
    // The new owner will be the most voted key in the transfer votes.
    struct key new_owner;

    // The total voters who have voted for a transfer.
    size_t total_voters;

    // Voters are stored here each voter must be a valid council certificate. We ill check this before approving a transfer
    // that we receive.
    struct council_certificate_transfer_vote *voters;
};

enum
{
    // Set for a given certificate if it has never been transfeered before.
    MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS = 0b00000001,

    // In some cases council members may want the power to transfer certificates without the need for a vote
    // this is possible if the certificate has the transferable without vote flag set.
    // With this flag set the owner of the certificate can transfer it to anybody without the need for a vote.
    // In practice for security reasons the flag should rarely be used, the only valid use case that I can think of
    // is in the case of a genesis certificate and in such cases we need to allocate certificates to many people quickly
    // to avoid voting delays from parties who are not truly interested in maintaining the network this flag could be crucial.
    MAGICNET_COUNCIL_CERTIFICATE_FLAG_TRANSFERABLE_WITHOUT_VOTE = 0b00000010,
};

/**
 * Council certificate data that is to be signed.
 */
struct council_certificate_signed_data
{
    // The Unique numerical certificate ID that is unique to the council only.
    int id;

    // Certificate flags.
    int flags;

    // The ID of the council this certificate belongs to.
    char council_id_hash[SHA256_STRING_LENGTH];
    // The timestamp of when this certificate will expires
    time_t expires_at;

    // The timestamp of when this certificate becomes valid.
    time_t valid_from;

    // The last certificate transfer of this certificate.
    struct council_certificate_transfer transfer;
};

enum
{
    // When set siginifies that a council certificate has already been verified before.
    MAGICNET_COUNCIL_CERTIFICATE_MEMORY_FLAG_VERIFIED = 0b00000001,
};

struct magicnet_council_certificate
{
    // We have all the transfer history of the certificate here.
    struct council_certificate_signed_data signed_data;

    // Hash of the council certificate signed data.
    char hash[SHA256_STRING_LENGTH];

    // Should be signed by the owner of the certificate.
    struct key owner_key;
    struct signature signature;

    // The council this certificate belongs too, this is NULL if the council isnt currently loaded or located
    // in which case you must rely on the signed_data.council_id_hash to locate and load the council.
    struct magicnet_council *council;

    // Memory flags for this certificate, that are not saved or sent over the network and are purley used as a way of storing
    // runtime data for this certificate
    int memory_flags;
};

struct block
{

    // Hash of this block
    char hash[SHA256_STRING_LENGTH];
    // Hash of the previous block
    char prev_hash[SHA256_STRING_LENGTH];

    // Certificate used to sign the block
    struct magicnet_council_certificate *certificate;

    // The sigend signature of the block hash, signed with the certificate
    struct signature signature;

    struct block_transaction_group *transaction_group;

    // The timestamp of when the block was created. Note that this is the time the block verifier has told us
    // he created the block. He could lie here we dont know. So this field shouldnt be used for security reasons.
    // and should just be used as informative reasons. However all blocks should be rejected if the previous block
    // has a time that is greater than the time provided to us.
    time_t time;

    // LOCAL DATA ONLY The below data is not sent across the network
    int blockchain_id;
};

struct magicnet_wallet
{
    // The public key of the wallet
    struct key key;

    // The balance of the wallet
    double balance;
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
    // True if this client has completed the protocol exchange.
    // DEPRECATED DO NOT USE! USE THE STATES IN THE CLIENT.
    // MAGICNET_CLIENT_FLAG_ENTRY_PROTOCOL_COMPLETED = 0b00010000,
    MAGICNET_CLIENT_FLAG_IGNORE_TRANSACTION_AND_BLOCK_VALIDATION = 0b00100000,
    MAGICNET_CLIENT_FLAG_MUST_BLOCK = 0b01000000,
    MAGICNET_CLIENT_FLAG_
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

/**
 * Returns true if the login protocol has been completed from both sides, our clients side
 * and the server completed his side too.
 */
bool magicnet_client_login_protocol_completed(struct magicnet_client *client);
bool magicnet_client_must_send_ping(struct magicnet_client* client);
bool magicnet_client_needs_ping(struct magicnet_client* client);

void magicnet_client_free(struct magicnet_client *client);
bool magicnet_connected(struct magicnet_client *client);
void magicnet_close(struct magicnet_client *client);
bool magicnet_client_no_packet_loading(struct magicnet_client *client);

/**
 * To be called to enhance the client to the next stage, such as moving forward
 * in the login protocol, or reading part or all of a packet.
 *
 * For server threads, they will call this function, for single threaded applications
 * you are responsible.
 * 
 * \param client The client to read the packet/ or poll
 * \param process_packet_func This function is called when the packet is fully read and ready 
 */
int magicnet_client_poll(struct magicnet_client *client, PROCESS_PACKET_FUNCTION process_packet_func);

void magicnet_reconnect(struct magicnet_program *program);

void magicnet_event_release_data_for_event_type_new_block(struct magicnet_event *event);
void magicnet_event_release_data(struct magicnet_event *event);
void magicnet_event_release(struct magicnet_event *event);
struct magicnet_event *magicnet_event_new(struct magicnet_event *event);
void magicnet_copy_event_data_new_block(struct magicnet_event *copy_to_event, struct magicnet_event *copy_from_event);
void magicnet_copy_event_data(struct magicnet_event *copy_to_event, struct magicnet_event *copy_from_event);
struct magicnet_event *magicnet_copy_event(struct magicnet_event *original_event);
struct vector *magicnet_copy_events(struct vector *events_vec_in);
int _magicnet_events_poll(struct magicnet_program *program, bool reconnect_if_neccessary);
int magicnet_event_make_for_block(struct magicnet_event **event_out, struct block *block);
int magicnet_events_poll(struct magicnet_program *program);
size_t magicnet_client_total_known_events(struct magicnet_client *client);
bool magicnet_client_has_known_events(struct magicnet_client *client);
int magicnet_client_pop_event(struct magicnet_client *client, struct magicnet_event **event);
int magicnet_client_push_event(struct magicnet_client *client, struct magicnet_event *event);
bool magicnet_has_queued_events(struct magicnet_program *program);
struct magicnet_event *magicnet_next_event(struct magicnet_program *program);
void magicnet_events_vector_free(struct vector *events_vec);
void magicnet_events_vector_clone_events_and_push(struct vector *events_from, struct vector *events_to);

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

/**
 * Default handler of packets to be processed. Must be called by all handlers to enforce
 * the protocol correctly.
 * 
 * DO NOT PREFORM SERVER LOGIC IN THIS FUNCTION
 */
int magicnet_default_poll_packet_process(struct magicnet_client *client, struct magicnet_packet *packet);

/**
 * Pushes the client to the thread pool so it can be polled frequently
 */
int magicnet_client_push(struct magicnet_client *client);
int magicnet_client_read_packet(struct magicnet_client *client, struct magicnet_packet *packet_out);
int magicnet_client_write_packet(struct magicnet_client *client, struct magicnet_packet *packet, int flags);
int magicnet_send_packet(struct magicnet_program *program, int packet_type, void *packet);
int magicnet_client_entry_protocol_read_known_clients(struct magicnet_client *client, struct magicnet_packet* packet);
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
int magicnet_make_transaction(struct magicnet_program *program, int type, void *data, size_t size);
int magicnet_make_transaction_using_buffer(struct magicnet_program *program, int type, struct buffer *buffer);
int magicnet_money_transfer_data(struct block_transaction *transaction, struct block_transaction_money_transfer *money_transfer);
int magicnet_money_transfer_data_write(struct block_transaction *transaction, struct block_transaction_money_transfer *money_transfer);
int magicnet_read_transaction_council_certificate_initiate_transfer_data(struct block_transaction *transaction, struct block_transaction_council_certificate_initiate_transfer_request *council_certificate_transfer);
int magicnet_read_transaction_council_certificate_claim_request(struct block_transaction *transaction, struct block_transaction_council_certificate_claim_request *claim_req_out);
/*
 *Called to claim transfers of council certificates.. This is only possible if the transfer was successful. As always
 * we will verify the request on our local server but only distribute the packet if we believe we are eligible
 * to claim a certificate transfer.
 */
int magicnet_certificate_transfer_claim(struct magicnet_program *program, const char *initiate_transfer_transaction_hash, const char *certificate_hash);
int magicnet_certificate_transfer_data_write(struct block_transaction *transaction, struct block_transaction_council_certificate_initiate_transfer_request *transfer_request);

/**
 * Returns zero if we are allowed to process this packet for this sending client
 * negative if it must be refused.
 */
int magicnet_packet_allowed_to_be_processed(struct magicnet_client* sending_client, struct magicnet_packet* packet);

int magicnet_send_pong(struct magicnet_client *client);
void magicnet_packet_free(struct magicnet_packet *packet);
void magicnet_free_packet_pointers(struct magicnet_packet *packet);
struct magicnet_packet *magicnet_packet_new();
struct magicnet_packet* magicnet_packet_new_init(int packet_type);
void magicnet_packet_make_new_id(struct magicnet_packet *packet);
int magicnet_init(int flags, int t_threads);
int magicnet_flags();

int magicnet_get_structure(int type, struct magicnet_registered_structure *struct_out);
int magicnet_register_structure(long type, size_t size);
struct magicnet_program *magicnet_program(const char *name);

/**
 * Makes a money transfer to the recipient
 * \param to The recipient's public key
 * \amount The amount to transfer
 */
int magicnet_make_money_transfer(struct magicnet_program *program, const char *to, double amount);

/**
 * Initiates a transfer request of a council certificate to a new owner, the transaction is likely to be dropped
 * by receving peers if the signer of this transaction is not a council certificate holder in the council of the
 * certificate they are trying to transfer.
 *
 * Transfer requests are not final and further steps need to be taken for them to be official such as proving you have
 * the right to transfer the certificate. Or through voting.
 *
 * \param program The program to make the transaction with
 * \param flags The flags of the transfer
 * \param certificate_to_transfer_hash The hash of the certificate to transfer
 * \param new_owner_key The key of the new owner of the certificate
 * \return int 0 if the transaction was successfully created
 */
int magicnet_certificate_transfer_initiate(struct magicnet_program *program, int flags, const char *certificate_to_transfer_hash, struct key *new_owner_key);

// Shared network functions
int magicnet_server_get_next_ip_to_connect_to(struct magicnet_server *server, char *ip_out);
struct magicnet_client *magicnet_tcp_network_connect_for_ip_for_server(struct magicnet_server *server, const char *ip_address, int port, const char *program_name, int signal_id, int flags);

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

/**
 * Loads the transaction with the given hash. If not found or error then NULL is returned.
 */
struct block_transaction *block_transaction_load(const char *transaction_hash);

/**
 * Lazily loads a block from storage. Does not load transactions.
 */
struct block *block_load(const char *hash);
/**
 * Loads the transactions of a lazily loaded block.
 */
int block_load_transactions(struct block *block);

/**
 * Loads the transactions from the request into the output transaction group
 */
int block_transactions_load(struct magicnet_transactions_request *request, struct block_transaction_group *transaction_group);

/**
 * Frees a vector of struct block_transaction*
 */
void block_transaction_vector_free(struct vector *vector);

/**
 * Fully loads what is not loaded with the provided lazily loaded block.
 * 1. Loads transactions
 * 2. ... Future
 */
int block_load_fully(struct block *block);

int block_save(struct block *block);
int block_save_with_rules(struct block *block, int flags);
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

struct magicnet_transactions *magicnet_transactions_request(struct magicnet_program *program, struct magicnet_transactions_request *request_data);

struct block *block_clone(struct block *block);
struct block_transaction *block_transaction_new();
struct self_block_transaction *block_self_transaction_new(struct block_transaction *transaction);

struct block_transaction_group *block_transaction_group_new();
void block_transaction_group_free(struct block_transaction_group *transaction_group);

struct block_transaction *block_transaction_new();
struct block_transaction *block_transaction_clone(struct block_transaction *transaction);
void block_transaction_free(struct block_transaction *transaction);
struct block_transaction *block_transaction_build(const char *program_name, char *data, size_t data_len);
int block_transaction_add(struct block_transaction_group *transaction_group, struct block_transaction *transaction);
int block_transaction_valid(struct block_transaction *transaction);
int block_transaction_valid_specified(struct block_transaction *transaction, int flags);
int block_transaction_hash_and_sign(struct block_transaction *transaction);
bool block_transaction_is_signed(struct block_transaction *transaction);

int block_verify(struct block *block);
int block_verify_specified(struct block *block, int flags);
int block_hash_sign_verify(struct block *block);
void magicnet_get_block_path(struct block *block, char *block_path_out);
const char *block_hash_create(struct block *block, char *hash_out);
struct block *magicnet_block_load(const char *hash);

// Council
int magicnet_council_init();
struct magicnet_council *magicnet_council_create(const char *name, size_t total_certificates, time_t creation_time);
void magicnet_council_free(struct magicnet_council *council);
int magicnet_council_save(struct magicnet_council *council);
int magicnet_council_verify(struct magicnet_council *council);
int magicnet_council_stream_alloc_and_read_certificate(struct buffer *buffer_in, struct magicnet_council_certificate **certificate);

/**
 *  Verifies that the council certificate is valid and apart of the council
 * This function will return < 0 if the certificate is not valid or not apart of the council
 * \param council The council to verify the certificate against
 * \param certificate The certificate to verify
 * \return 0 if the certificate is valid and apart of the council
 */
int magicnet_council_certificate_verify_for_council(struct magicnet_council *council, struct magicnet_council_certificate *certificate);

/**
 * Verifies that the council certificate is valid and apart of the central council
 * \param certificate The certificate to verify
 * \return -1 if the certificate is not valid or not apart of the central council
 */

int magicnet_central_council_certificate_verify(struct magicnet_council_certificate *certificate);

/**
 * Writes the council certificate data to the buffer
 * \param buffer_out The buffer to write the data to
 * \param certificate The certificate to write
 * \return 0 if the certificate was written to the buffer
 */
int magicnet_council_stream_write_certificate(struct buffer *buffer_out, struct magicnet_council_certificate *certificate);

/**
 * Reads the council certificate data from the buffer
 *
 */
int magicnet_council_stream_read_certificate(struct buffer *buffer_in, struct magicnet_council_certificate *certificate);

/**
 * Returns the certificates for the given council
 */
int magicnet_council_certificates_for_key(struct magicnet_council *council, struct key *key, struct vector *certificate_vec);
/**
 * Returns the default certificate of the key given, for now this returns the first certificate it encounters but in the future
 * we could have a means of determining the default certificate as some kind of setting that the owner can change
 *
 * \param council The council to search for the certificate in or NULL to use the central council
 * \param key The key to search for
 * \param certificate_out The certificate that was found
 *
 * \return 0 if the certificate was found, -1 if the certificate was not found
 */
int magicnet_council_default_certificate_for_key(struct magicnet_council *council, struct key *key, struct magicnet_council_certificate **certificate_out);

/**
 * Returns true if the council certificate exists
 */
bool magicnet_council_certificate_exists(const char *certificate_hash);

/**
 * Returns the default council certificate for the given key
 * \param council The council to search for the certificate in or NULL to use the central council
 * \param key The key to search for
 * \param certificate_out The certificate that was found
 */
int magicnet_council_my_certificate(struct magicnet_council *council, struct magicnet_council_certificate **certificate_out);

/**
 * Verifies that the council certificate is owned by the public key of this node
 *
 * \param certificate The certificate to verify
 */
bool magicnet_council_certificate_is_mine(const char *certificate_hash);

/**
 * Verifies that a given council certificate signed a particular hash.
 */
int magicnet_council_certificate_verify_signed_data(struct magicnet_council_certificate *certificate, struct signature *signature, const char *hash);

/**
 * Verifies that the certificate is valid and signed by the owner of the certificate.
 * Then saves the certificate to the database.
 */
int magicnet_council_certificate_save(struct magicnet_council_certificate *certificate);

enum
{
    // Before certificates are claimed they are unsigned
    // in such cases you may want to pass this flag to the magicnet_council_certificate_verify functioon
    // wwhicch will validate everything except the signature as its currently unsigned.
    // All transfer votes will be validated and all transfer rules everything except signature.
    MAGICNET_COUNCIL_CERTIFICATE_VERIFY_FLAG_IGNORE_FINAL_SIGNATURE = 0b00000001,
};

/**
 * Verifies that the council certificate is valid
 *
 * \param certificate The certificate to verify
 */
int magicnet_council_certificate_verify(struct magicnet_council_certificate *certificate, int flags);

struct magicnet_council_certificate *magicnet_council_certificate_create();
struct magicnet_council_certificate *magicnet_council_certificate_create_many(size_t total);

void magicnet_council_certificate_many_free(struct magicnet_council_certificate *certificates_ptr, size_t amount);
void magicnet_council_certificate_free(struct magicnet_council_certificate *certificate);
int magicnet_council_certificate_verify_signature(struct magicnet_council_certificate *certificate);
void magicnet_council_certificate_hash(struct magicnet_council_certificate *certificate, char *out_hash);

/**
 * Requests the certificate structure from the magicnet local server instance.
 * \param program The program to request the certificate from
 * \param council_certificate_hash The hash of the certificate to request
 * \param certificate_out The certificate that was requested
 *
 * \return 0 if the certificate was located successfully, otherwise below zero on error, in which case check the error code list
 */
int magicnet_council_request_certificate(struct magicnet_program *program, const char *council_certificate_hash, struct magicnet_council_certificate **certificate_out);

/**
 * Transfeers the council certificate without the need of vote, this is only allowed if the certificate holds the
 * MAGICNET_COUNCIL_CERTIFICATE_FLAG_TRANSFERABLE_WITHOUT_VOTE flag. Additionally if two certificates become in existance with overlapping
 * valid from and expiry times then both certificates will become invalidated. This is to prevent a situation where a certificate
 * is transfered to two people at the same time. Breaking this rule will invalidate the certificates in question when any peer becomes aware of a
 * co-existing certificate.
 *
 * This function will fail in the event the certificate cannot be transfeered due to overlapping times. If you force it programatically all nodes
 * will reject this certificate for the entire future so please ensure you respect the return result of this function.
 *
 */
int magicnet_council_certificate_self_transfer(struct magicnet_council_certificate *certificate, struct magicnet_council_certificate **new_certificate_out, struct key *new_owner, time_t valid_from, time_t valid_to);

/**
 * Should be called by anyone who wishes to claim a certificate that has been assigned to them. This function will sign the certificate and ensure
 * that the certificate is valid. If the certificate is not valid then the function will return an error.
 */
int magicnet_council_certificate_self_transfer_claim(struct magicnet_council_certificate *certificate_to_claim);
/**
 * Returns true if the given certificate is a genesis certificate belonging to the council
 */
bool magicnet_council_is_genesis_certificate(struct magicnet_council *council, struct magicnet_council_certificate *certificate);
/**
 * Will attempt to give you a certificate belonging to the provided public key and the council,
 * if multiple certificates belonging to the public key that are heldby the council
 * are found then the most valid certificate will be returned. Valid being the one that is in date and not expired.
 */
struct magicnet_council_certificate *magicnet_council_certificate_load(const char *certificate_hash);

struct magicnet_council_certificate *magicnet_council_certificate_clone(struct magicnet_council_certificate *certificate);

// End of council

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

void magicnet_transactions_request_init(struct magicnet_transactions_request *request);
void magicnet_transactions_request_remove_block_hash(struct magicnet_transactions_request *request);
void magicnet_transactions_request_remove_transaction_group_hash(struct magicnet_transactions_request *request);
void magicnet_transactions_request_set_transaction_group_hash(struct magicnet_transactions_request *request, const char *transaction_group_hash);
void magicnet_transactions_request_set_block_hash(struct magicnet_transactions_request *request, const char *hash);
void magicnet_transactions_request_set_flag(struct magicnet_transactions_request *request, int flag);
void magicnet_transactions_request_set_type(struct magicnet_transactions_request *request, int type);
void magicnet_transactions_request_set_block_hash(struct magicnet_transactions_request *request, const char *block_hash);
void magicnet_transactions_request_set_total_per_page(struct magicnet_transactions_request *request, int total_per_page);
void magicnet_transactions_request_set_page(struct magicnet_transactions_request *request, int page);
void magicnet_transactions_request_set_key(struct magicnet_transactions_request *request, struct key *key);
void magicnet_transactions_request_set_target_key(struct magicnet_transactions_request *request, struct key *target_key);

// Wallets
struct magicnet_wallet *magicnet_wallet_find(struct key *key);
int magicnet_wallet_calculate_balance(struct key *key, double *balance_out);
int magicnet_wallet_calculate_balance_from_block(struct key *key, double *balance_out, const char *block_hash);

// Settings

int magicnet_setting_set(const char *key, const char *value);
int magicnet_setting_set_timestamp(const char *key, time_t value);
int magicnet_setting_set_int(const char *key, int value);

int magicnet_setting_get_int(const char *key, int *value_out);
int magicnet_setting_get_timestamp(const char *key, time_t *value_out);
int magicnet_setting_get(const char *key, char *value_out);

bool magicnet_setting_exists(const char *key);

// Request response system, allowing local host clients to request information from the local server
#define MAGICNET_REQRES_MAX_HANDLERS 200

// 65k for now, work the real value out later..
#define MAGICNET_MAX_LOGIN_PROTOCOL_ENTRY_BYTES 65000

// For people writing modules for MagicNet Don't use any handler below 100 they are all reserved for internal system use
// Public use above 100 please, bare in mind that other modules might use the same ID so ensure you
// pick a completely random number
enum
{
    MAGICNET_REQRES_HANDLER_GET_COUNCIL_CERTIFICATE = 0,
};
typedef int (*REQUEST_RESPONSE_HANDLER_FUNCTION)(struct request_and_respond_input_data *input_data, struct request_and_respond_output_data **output_data_out);

int reqres_register_handler(REQUEST_RESPONSE_HANDLER_FUNCTION handler, int type);
REQUEST_RESPONSE_HANDLER_FUNCTION reqres_get_handler(int type);
int magicnet_reqres_request(struct magicnet_client *client, int type, struct request_and_respond_input_data *input_data, struct request_and_respond_output_data **output_data_out);
void magicnet_reqres_input_data_free(struct request_and_respond_input_data *input_data);
void magicnet_reqres_output_data_free(struct request_and_respond_output_data *output_data);
struct request_and_respond_output_data *magicnet_reqres_output_data_clone(struct request_and_respond_output_data *output_data);
struct request_and_respond_input_data *magicnet_reqres_input_data_clone(struct request_and_respond_input_data *input_data);
struct request_and_respond_output_data *magicnet_reqres_output_data_create(void *output_data_ptr, size_t size);
struct request_and_respond_input_data *magicnet_reqres_input_data_create(void *input_data_ptr, size_t size);
#endif