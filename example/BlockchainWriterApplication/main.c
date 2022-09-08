#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
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
    
    

}