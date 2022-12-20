#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "magicnet/magicnet.h"
#include "magicnet/key.h"


int main(int argc, char** argv)
{

    if (argc < 3)
    {
        printf("USAGE: <public key> <amount_to_send>\n");
        return -1;
    }

    magicnet_init();
    struct magicnet_program *decentralized_program = magicnet_program("money-app");
    if (!decentralized_program)
    {
        printf("Issue creating a program is the local server running?\n");
        return -1;
    }
    
    int res = magicnet_make_money_transfer(decentralized_program, argv[1], atoi(argv[2]));

    if (res == 0)
    {
        printf("Created the transaction money has been sent\n");
    }
    
    
    return 0;
}