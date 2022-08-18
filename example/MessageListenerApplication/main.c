#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include "magicnet/magicnet.h"

#define CHAT_PACKET 1
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
     while (1)
     {
         struct magicnet_packet* packet = magicnet_next_packet(decentralized_program);
    //     // if (packet->type == CHAT_PACKET)
    //     // {
    //     //     struct chat_packet* packet_data = packet->data;
    //     //     printf("%s\n", data->message);
    //     // }
    //     // magicnet_free_packet(packet);
     }
}