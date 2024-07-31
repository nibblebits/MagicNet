#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "magicnet/magicnet.h"

int transfer_certificate_claim(struct magicnet_program *program, int argc, char **argv)
{
    int res = 0;
    if (argc < 3)
    {
        printf("USAGE: <type> <transfer_transaction_hash> <certificate_to_claim_hash>\n");
        return -1;
    }

    char *certificate_hash = argv[2];
    char *transfer_transaction_hash = argv[3];

    res = magicnet_certificate_transfer_claim(program, transfer_transaction_hash, certificate_hash);
    printf("transfer claim request has been made await next block to confirm if you claimed correctly");

    return res;
}
int transfer_certificate(struct magicnet_program *program, int argc, char **argv)
{

    // Extract the certificate hash
    if (argc < 4)
    {
        printf("USAGE: <type> <certificate_hash> <new_owner_key>\n");
        return -1;
    }

    // Get the certificate hash
    char *certificate_hash = argv[2];

    // Get the new owner key
    char *new_owner_key_data = argv[3];

    struct key new_owner_key = MAGICNET_key_from_string(new_owner_key_data);

    int res = magicnet_certificate_transfer_initiate(program, COUNCIL_CERTIFICATE_TRANSFER_FLAG_TRANSFER_WITHOUT_VOTE, certificate_hash, &new_owner_key);
    if (res < 0)
    {
        printf("Failed to create the certificate transfer initiate request\n");
        return -1;
    }

    printf("Created the certificate transfer initiate request\n");

    return 0;
}

int certificate_show(struct magicnet_program *program, int argc, char **argv)
{
    int res = 0;
    if (argc < 3)
    {
        printf("USAGE: show <certificate_hash> \n");
        return -1;
    }

    struct magicnet_council_certificate* certificate = NULL;
    const char* certificate_hash = argv[2];
    res = magicnet_council_request_certificate(program, certificate_hash, &certificate);
    if (res < 0)
    {
        if (res == MAGICNET_ERROR_NOT_FOUND)
        {
            printf("Unable to find the certificate with that hash\n");
            goto out;
        }
        else
        {
            printf("Failed to request the certificate, unknown error occured. res=%i\n", res);
            goto out;
        }

    }

    printf("Certificate Hash: %s, Owner key: %s\n",
           certificate->hash,
           certificate->owner_key.key);
out:
    if (certificate)
    {
        magicnet_council_certificate_free(certificate);
    }
    return res;
}
int main(int argc, char **argv)
{
    // Usage command type
    if (argc < 2)
    {
        printf("USAGE: <type>\n");
        return -1;
    }

    magicnet_init(0);

    struct magicnet_program *decentralized_program = magicnet_program("council-certificate-app");
    if (!decentralized_program)
    {
        printf("Issue creating a program is the local server running?\n");
        return -1;
    }

    // get command type
    char *type = argv[1];
    if (strcmp(type, "transfer") == 0)
    {
        return transfer_certificate(decentralized_program, argc, argv);
    }
    else if (strcmp(type, "claim") == 0)
    {
        return transfer_certificate_claim(decentralized_program, argc, argv);
    }
    else if (strcmp(type, "show") == 0)
    {
        return certificate_show(decentralized_program, argc, argv);
    }
    else
    {
        printf("Unknown command type\n");
    }

    return 0;
}