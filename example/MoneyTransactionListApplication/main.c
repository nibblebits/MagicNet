#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "magicnet/magicnet.h"
#include "magicnet/key.h"


int main(int argc, char** argv)
{

    if (argc < 2)
    {
        printf("USAGE: <public key> \n");
        return -1;
    }

    magicnet_init(MAGICNET_INIT_FLAG_NO_STDOUT_WARNING_LOGGING | MAGICNET_INIT_FLAG_NO_STDOUT_GENERAL_LOGGING, 0);
    struct magicnet_program *decentralized_program = magicnet_program("money-app");
    if (!decentralized_program)
    {
        printf("Issue creating a program is the local server running?\n");
        return -1;
    }
    
    struct magicnet_transactions_request request;
    magicnet_transactions_request_init(&request);
    struct key key = MAGICNET_key_from_string(argv[1]);
    magicnet_transactions_request_set_flag(&request, MAGICNET_TRANSACTIONS_REQUEST_FLAG_KEY_OR_TARGET_KEY);
    magicnet_transactions_request_set_key(&request, &key);
    magicnet_transactions_request_set_target_key(&request, &key);

    magicnet_transactions_request_set_type(&request, MAGICNET_TRANSACTION_TYPE_COIN_SEND);
    struct magicnet_transactions* transactions = magicnet_transactions_request(decentralized_program, &request);
    if (!transactions)
    {
        printf("Problem with transactions request\n");
        return -1;
    }

    printf("Transactions request completed found %i\n\n", (int)transactions->amount);
    for (int i = 0; i < transactions->amount; i++)
    {
        struct block_transaction* transaction = transactions->transactions[i];
        struct block_transaction_money_transfer money_data = {0};
        magicnet_money_transfer_data(transaction, &money_data);

        printf("#%i. \n", i+1);
        printf("Transaction ID:%s \nfrom=%s, \nto=%s \namount=%f\n", transaction->hash, transaction->key.key, transaction->target_key.key, money_data.amount);
        printf("\n");
    }
    
    return 0;
}