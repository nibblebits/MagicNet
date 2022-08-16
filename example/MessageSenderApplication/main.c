#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#define CHAT_PACKET 1

struct chat_packet
{
    char message[60];
};


int main()
{
    struct magic_program *decentralized_program = magicnet_program("chat-app");
    magicnet_register_structure(CHAT_PACKET, sizeof(struct chat_packet));
    while (1)
    {
        struct chat_packet packet;
        sprintf(&packet.message, "Packet sent successfully");
        magicnet_send_packet(decentralized_program, CHAT_PACKET, &packet);
    }
}