#include "magicnet.h"
#include "log.h"
#include <sqlite3.h>
#include <limits.h>

sqlite3* db = NULL;
const char *magicnet_database_path()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(MAGICNET_DATA_BASE_DIRECTORY_ENV), MAGICNET_DATA_BASE, MAGICNET_DATABASE_SQLITE_FILEPATH);
    return filepath;
}

int magicnet_database_load()
{
    int res = 0;
    if (db)
    {
        magicnet_log("the database has already been loaded before\n");
        res = -1;
        goto out;
    }

    int rc = sqlite3_open(magicnet_database_path(), &db);
    if (rc)
    {
        magicnet_log("could not open the magicnet database\n");
        res = -1;
        goto out;
    }
out:
    return res;
}