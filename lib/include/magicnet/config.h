#ifndef MAGICNET_CONFIG_H
#define MAGICNET_CONFIG_H

#define MAGICNET_SERVER_PORT 5873
#define MAGICNET_MAX_INCOMING_CONNECTIONS 30
#define MAGICNET_MAX_OUTGOING_CONNECTIONS 30

#define MAGICNET_CLIENT_TIMEOUT_SECONDS 30
#define MAGICNET_PROGRAM_NAME_SIZE 64
#define MAGICNET_MAX_AWAITING_PACKETS 1024

#define MAGICNET_MAX_IP_STRING_SIZE 17

// At least 10 seconds must pass for the server to attempt to connect to other peers
#define MAGICNET_ATTEMPT_NEW_CONNECTIONS_AFTER_SECONDS 10

// 1024 random ip addresses will be loaded during startup from the IP list file.
#define MAGICNET_MAX_LOADED_IP_ADDRESSES 1024

// This SINGATURE must be sent when you connect to a server of ours. It proves that 
// this is a magicnet client not some accidental http request or something.
// Sent as a 4 byte integer.
#define MAGICNET_ENTRY_SIGNATURE 0xf6f4

#define MAGICNET_LOCAL_SERVER_ADDRESS "127.0.0.1"

// Anyone who listens on this will get all packets regardless who they are.
#define MAGICNET_LISTEN_ALL_PROGRAM "magicnet"

#endif