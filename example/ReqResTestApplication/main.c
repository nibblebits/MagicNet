#include "magicnet/magicnet.h"

int main()
{
    int res = 0;
    magicnet_init(0, 0);

    struct magicnet_program *program = magicnet_program("reqres");
    if (!program)
    {
        printf("is magicnet running?\n");
        return -1;
    }

    // Lets put in a request for the helloworld reqres to test the system
    struct magicnet_request_response_output_data *output_data = NULL;
    struct magicnet_client *client = magicnet_program_client_hold(program);
    res = magicnet_reqres_request_obj(client, MAGICNET_REQRES_HANDLER_HELLOWORLD_TEST, NULL, &output_data);
    if (res < 0)
    {
        printf("problem\n");
        return -1;
    }

    printf("%s response is: %s\n", __FUNCTION__, (const char*) output_data->output);
    magicnet_program_client_release(program);
}