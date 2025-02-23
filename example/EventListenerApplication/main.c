#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "magicnet/magicnet.h"


int main()
{
    magicnet_init(0, 0);
    struct magicnet_program *decentralized_program = magicnet_program("event-listener-app");
    if (!decentralized_program)
    {
        printf("Issue creating a program is the local server running?\n");
        return -1;
    }
    
    struct magicnet_event* event = magicnet_next_event(decentralized_program);
    while(1)
    {
        if (event)
        {
            printf("Found an event\n");
            if (event->type == MAGICNET_EVENT_TYPE_NEW_BLOCK)
            {
                printf("%s block created\n", event->data.new_block_event.block->hash);
            }
        }
        else
        {
            printf("No event yet\n");
        }
        event = magicnet_next_event(decentralized_program);
        sleep(2);
    }
    
    return 0;
}