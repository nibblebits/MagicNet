#ifndef MAGICNET_CONFIG_H
#define MAGICNET_CONFIG_H

#define MAGICNET_SERVER_PORT 5873
#define MAGICNET_MAX_INCOMING_CONNECTIONS 30
#define MAGICNET_MAX_OUTGOING_CONNECTIONS 30

#define MAGICNET_CLIENT_TIMEOUT_SECONDS 10
#define MAGICNET_PROGRAM_NAME_SIZE 64
#define MAGICNET_MAX_AWAITING_PACKETS 256

#define MAGICNET_MAX_IP_STRING_SIZE 17
#define MAGICNET_MAX_NAME_SIZE 65
#define MAGICNET_MAX_EMAIL_SIZE 256

#define MAGICNET_MAX_SIGNALING_SIGNALS 1024
#define MAGICNET_MAX_SIGNAL_TYPE_NAME 32

#define MAGICNET_MAX_BLOCK_SUPER_DOWNLOAD_REQUEST_BLOCK_COUNT 100

// At least 10 seconds must pass for the server to attempt to connect to other peers
#define MAGICNET_ATTEMPT_NEW_CONNECTIONS_AFTER_SECONDS 10

// This SINGATURE must be sent when you connect to a server of ours. It proves that 
// this is a magicnet client not some accidental http request or something.
// Sent as a 4 byte integer.
#define MAGICNET_ENTRY_SIGNATURE 0xf6f4

#define MAGICNET_LOCAL_SERVER_ADDRESS "127.0.0.1"


// You may reference up to 10 funding sources to send money.
#define MAGICNET_MONEY_TRANSACTION_TOTAL_FUNDING_SOURCES 10

// 1 Million starting cash in the network. The value will decrease over time. With deflation.
#define MAGICNET_GENESIS_STARTING_MONEY 10000000

// 1 coin to bet to make a block
#define MAGICNET_BET_TO_MAKE_BLOCK 1
// 0.5 coins of the bet will be thrown away causing the currency to deflate.
#define MAGICNET_BLOCK_BET_MONEY_TO_THROW_AWAY 0.5

#define MAGICNET_GENESIS_KEY ""
// Anyone who listens on this will get all packets regardless who they are.
#define MAGICNET_LISTEN_ALL_PROGRAM "magicnet"


#define MAGICNET_DATA_BASE_DIRECTORY_ENV "HOME"
#define MAGICNET_DATA_BASE ".magicnet"
#define MAGICNET_DATABASE_SQLITE_FILEPATH "/database.db"
#define MAGICNET_BLOCK_DIRECTORY "/blocks"
#define MAGICNET_PUBLIC_KEY_FILEPATH "/key.pub"
#define MAGICNET_PRIVATE_KEY_FILEPATH "/key.pri"


//LOGGING
#define MAGICNET_SHOW_INFO_LOGS
#define MAGICNET_SHOW_IMPORTANT_LOGS
#define MAGICNET_SHOW_ERROR_LOGS


// CRYPTOGRAPHY

// 64 bytes for hashed key then +1 for null terminator
#define MAGICNET_MAX_KEY_LENGTH 140

#define MAGICNET_MAX_SIGNATURE_PART_LENGTH 65

#define MAGICNET_MAKE_BLOCK_EVERY_TOTAL_SECONDS 60

#define MAGICNET_CHAIN_DOWNLOADER_BLOCK_REQUEST_DELAY_SECONDS 10

#define MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_PER_SECOND 50000
#define MAGICNET_IDEAL_DATA_TRANSFER_BYTE_RATE_WHEN_PROCESSING_PACKETS 50000

// Aprox 5 MB of memory.
#define MAGICNET_MAX_VERIFIER_CONTESTANTS 20480

#define MAGICNET_MAX_TOTAL_TRANSACTIONS_IN_BLOCK 1024
#define MAGICNET_MAX_SIZE_FOR_TRANSACTION_DATA 65535


// We will download a chain from a maximum of 1 peers.
#define MAGICNET_MAX_CHAIN_DOWNLOADER_CONNECTIONS 1

#define MAGICNET_MAX_SMALL_STRING_SIZE 64

#endif