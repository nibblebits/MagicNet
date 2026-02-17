#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include "magicnet/magicnet.h"

#define CHAT_PACKET 56
struct chat_packet
{
    char message[60];
};


int main()
{
    magicnet_init(MAGICNET_INIT_FLAG_NO_STDOUT_WARNING_LOGGING | MAGICNET_INIT_FLAG_NO_STDOUT_GENERAL_LOGGING, 0);
    struct magicnet_program *decentralized_program = magicnet_program("chat-app");
    if (!decentralized_program)
    {
        printf("Issue creating a program is the local server running?\n");
        return -1;
    }

    // FUNCTIONALITY IS NOW WORKING AGAIN BUT ITS SLOW
    // A GOOD START TO THE REDESIGN


    magicnet_register_structure(CHAT_PACKET, sizeof(struct chat_packet));
   while (1)
     {
            struct chat_packet* packet = NULL;
            int type = magicnet_next_packet(decentralized_program, (void**)&packet);
            switch(type)
            {
                case CHAT_PACKET:
                    printf("testing: %s\n", packet->message);
                break;

                //default: 
                  //  printf("Bad packet %i\n",type);
            }
        usleep(10000);

     }

     // Will likely kill the cliejnt causing the ref count to drop expected

     magicnet_program_release(decentralized_program);
}