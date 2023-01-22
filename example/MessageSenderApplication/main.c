#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "magicnet/magicnet.h"

#define CHAT_PACKET 56
struct chat_packet
{
    char message[60];
};

int main()
{
    magicnet_init();
    struct magicnet_program *decentralized_program = magicnet_program("chat-app");
    if (!decentralized_program)
    {
        printf("Issue creating a program is the local server running?\n");
        return -1;
    }
    magicnet_register_structure(CHAT_PACKET, sizeof(struct chat_packet));

    struct chat_packet packet;
    

    magicnet_send_packet(decentralized_program, CHAT_PACKET, &packet);
    while (1)
    {
    }
}