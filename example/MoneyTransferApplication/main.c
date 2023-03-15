#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "magicnet/magicnet.h"
#include "magicnet/key.h"

#define S_EQ(a, b) (strcmp(a, b) == 0)

int main(int argc, char** argv)
{

    if (argc < 2)
    {
        printf("USAGE: <key>\n");
        return -1;
    }

    magicnet_init(MAGICNET_INIT_FLAG_NO_STDOUT_GENERAL_LOGGING | MAGICNET_INIT_FLAG_NO_STDOUT_WARNING_LOGGING);
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