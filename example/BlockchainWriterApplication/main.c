#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "magicnet/magicnet.h"


int main()
{
    magicnet_init();
    struct magicnet_program *decentralized_program = magicnet_program("chat-app");
    if (!decentralized_program)
    {
        printf("Issue creating a program is the local server running?\n");
        return -1;
    }
    
    int res = magicnet_make_transaction(decentralized_program, 
            "Beer from UK", 
            strlen("Beer from UK"));

    if (res == 0)
    {
        printf("Created the transaction\n");
    }
    
    
    return 0;
}