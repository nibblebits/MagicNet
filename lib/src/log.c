#include "magicnet/magicnet.h"
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
pthread_mutex_t log_lock;

void magicnet_log_initialize()
{
    pthread_mutex_init(&log_lock, NULL);

}

int magicnet_log(const char* message, ...)
{
    pthread_mutex_lock(&log_lock);
    va_list args;
    va_start(args, message);
    vfprintf(stdout, message, args);
    va_end(args);
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
}
