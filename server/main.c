#include "magicnet/log.h"
#include "magicnet/magicnet.h"
#include "magicnet/database.h"
#include "magicnet/init.h"
#include "magicnet/log.h"
#include "magicnet/signaling.h"
#include "magicnet/shared.h"
#include "magicnet/sharedmutexobj.h"
#include <memory.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>

struct magicnet_server *server = NULL;
bool sig_int_was_sent = false;
int sig_int_thread_id;
void sig_int_handler(int sig_num)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    if (sig_int_was_sent)
    {
        magicnet_important("Be patient we are shutting down!\n");
        return;
    }
    sig_int_was_sent = true;
    magicnet_important("Shutting down please wait!\n");
    magicnet_signals_release_all();
    magicnet_chain_downloaders_shutdown();
    if (server)
    {
        magicnet_server_shutdown_server_instance(server);
        magicnet_server_free(server);
    }

    // Theres still a chance that during the server shutdown some threads might be using the downloaders
    // hence why we shutdown the downloaders and server instances before we do a memory cleanup.
    magicnet_chain_downloaders_cleanup();
    magicnet_database_close();
    magicnet_signals_free();

    exit(1);
}

void make_fake_chain()
{
    printf("making new chain\n");
    char prev_hash[SHA256_STRING_LENGTH] = {0};
    struct block_transaction_group *group = block_transaction_group_new();
    struct block *b = block_create(group, prev_hash);
    for (int i = 0; i < 10000000; i++)
    {
        block_hash_create(b, b->hash);
        block_save(b);
        memcpy(prev_hash, b->hash, sizeof(prev_hash));
        b->transaction_group = NULL;
        block_free(b);
        b = block_create(group, prev_hash);
    }
    printf("done\n");
}

void *sig_int_listener_thread(void *ptr)
{

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    time_t t = time(NULL);
    while (1)
    {   

        sleep(1);
    }
}
int test_poll(struct magicnet_nthread_action* action)
{
    int res = 0;

    printf("Poll test\n");

    return res;
}

void test_free(struct magicnet_nthread_action* action, void* private_data)
{
    printf("Action was freed\n");
}

void protected_int_free(void* data_ptr)
{
    free(data_ptr);
    magicnet_log("%s protected data deleted, test complete\n", __FUNCTION__);
}

int main(int argc, char **argv)
{
    int res = 0;
    printf("Starting MagicNet server\n");


    // We wil use two threads
    // but compute the cpu count next time
    // divide by half and thats what
    // we will use...
    magicnet_init(0, 2);

    
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    signal(SIGINT, sig_int_handler);

    res = magicnet_signals_init();
    if (res < 0)
    {
        printf("Failed to initialize signals\n");
        return res;
    }

    res = magicnet_server_init();
    if (res < 0)
    {
        printf("could not initialize the magicnet server\n");
        return res;
    }


    server = magicnet_server_start(MAGICNET_SERVER_PORT);
    if (!server)
    {
        printf("The  magic net server could not be started\n");
        return -1;
    }

    res = magicnet_network_thread_start(server);
    if (res < 0)
    {
        printf("failed to start magic server thread\n");
        return -1;
    }

    res = magicnet_chain_downloaders_setup_and_poll(server);
    if (res < 0)
    {
        printf("There was a problem setting up the chain downloaders\n");
        return -1;
    }

    if (pthread_create(&sig_int_thread_id, NULL, &sig_int_listener_thread, NULL))
    {
        magicnet_log("%s failed to start the sigint thread\n", __FUNCTION__);
        return -1;
    }

    struct key* key = MAGICNET_public_key();
    struct magicnet_wallet* test_wallet = magicnet_wallet_find(key);
    if (test_wallet)
    {
        printf("Wallet balance=%f\n", test_wallet->balance);
    }

    // shared test with viewer
    int* protected_int = malloc(sizeof(int));
    *protected_int = 50;
    struct magicnet_shared_mutex_obj* mutex_obj = 
        magicnet_shared_mutex_obj_create_hold_as_owner(protected_int, protected_int_free);

    // We already are an owner lets create a viewer to see if it remembers or not
    int* protected_int_data = magicnet_shared_mutex_obj_viewer_hold(mutex_obj);

    // Now lets release the only owner
    magicnet_shared_mutex_obj_owner_release(mutex_obj);

    magicnet_shared_mutex_obj_lock(mutex_obj);
    *protected_int_data = 80;
    magicnet_log("%s protected_int=%i\n", __FUNCTION__, *protected_int);
    magicnet_shared_mutex_obj_unlock(mutex_obj);
    // Data should be gone lets try that
    if (magicnet_shared_mutex_obj_is_stale(mutex_obj))
    {
        magicnet_log("%s Yeah the mutx is stale we can drop ourselves\n", __FUNCTION__);
        magicnet_shared_mutex_obj_viewer_release(mutex_obj);
    }


    // Accept the clients
    bool server_shutdown = false;
    while (!server_shutdown)
    {
        // Has the server shutdown
        magicnet_server_lock(server);
        server_shutdown = server->shutdown;
        magicnet_server_unlock(server);
        if (server_shutdown)
        {
            break;
        }

        struct magicnet_client *client = magicnet_accept(server);
        if (client)
        {
            magicnet_client_push(client);
           
        }

        usleep(1000);
    }
}