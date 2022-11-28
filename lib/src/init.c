
#include "init.h"
#include "magicnet.h"
#include "log.h"
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include "database.h"

int magicnet_create_files()
{
    char data_directory[PATH_MAX];
    sprintf(data_directory, "%s/%s", getenv("HOME"), ".magicnet");
    DIR *dir = opendir(data_directory);
    if (!dir)
    {
        // First time setup
        mkdir(data_directory, 0775);
        sprintf(data_directory, "%s/%s/%s", getenv("HOME"), ".magicnet", MAGICNET_BLOCK_DIRECTORY);
        mkdir(data_directory, 0775);
    }
    closedir(dir);
    return 0;
}

int magicnet_server_init()
{
    int res = 0;
    // We should setup the seeder for when we use random.

    struct timespec time_seed;
    // CLOCK_MONOTONIC: absolute elapsed wall-clock time since // an arbitrary point in the past.
    clock_gettime(CLOCK_MONOTONIC, &time_seed);
    // use nanoseconds to seed RNG.
    srand((time_t)time_seed.tv_nsec);

    res = magicnet_create_files();
    if (res < 0)
    {
        goto out;
    }
    magicnet_log_initialize();
    res = magicnet_database_load();
    if (res < 0)
    {
        goto out;
    }

    MAGICNET_load_keypair();

    res = blockchain_init();
    if (res < 0)
    {
        goto out;
    }


out:
    return res;
}