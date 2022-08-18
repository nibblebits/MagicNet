#ifndef MAGICNET_CONFIG_H
#define MAGICNET_CONFIG_H

#define MAGICNET_SERVER_PORT 5873
#define MAGICNET_MAX_CONNECTIONS 30
#define MAGICNET_CLIENT_TIMEOUT_SECONDS 30
#define MAGICNET_PROGRAM_NAME_SIZE 64

// This SINGATURE must be sent when you connect to a server of ours. It proves that 
// this is a magicnet client not some accidental http request or something.
// Sent as a 4 byte integer.
#define MAGICNET_ENTRY_SIGNATURE 0xf6f4

#define MAGICNET_LOCAL_SERVER_ADDRESS "127.0.0.1"
#endif