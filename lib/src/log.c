#include "magicnet/magicnet.h"
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
pthread_mutex_t log_lock;

void magicnet_log_initialize()
{
    pthread_mutex_init(&log_lock, NULL);

}

int magicnet_important(const char* message, ...)
{
    if (magicnet_flags() & MAGICNET_INIT_FLAG_NO_STDOUT_WARNING_LOGGING)
    {
        return -1;
    }
    
    #ifdef MAGICNET_SHOW_IMPORTANT_LOGS
    pthread_mutex_lock(&log_lock);
    va_list args;
    va_start(args, message);
    vfprintf(stdout, message, args);
    va_end(args);
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
    return 0;
    #else
    return -1;
    #endif
}

int magicnet_error(const char* message, ...)
{
    if (magicnet_flags() & MAGICNET_INIT_FLAG_NO_STDOUT_ERROR_LOGGING)
    {
        return -1;
    }
    
    #ifdef MAGICNET_SHOW_ERROR_LOGS
    pthread_mutex_lock(&log_lock);
    va_list args;
    va_start(args, message);
    vfprintf(stdout, message, args);
    va_end(args);
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
    return 0;
    #else
    return -1;
    #endif
}

int magicnet_log(const char* message, ...)
{
    if (magicnet_flags() & MAGICNET_INIT_FLAG_NO_STDOUT_GENERAL_LOGGING)
    {
        return -1;
    }

    #ifdef MAGICNET_SHOW_INFO_LOGS
    pthread_mutex_lock(&log_lock);
    va_list args;
    va_start(args, message);
    vfprintf(stdout, message, args);
    va_end(args);
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
    return 0;
    #else
    return -1;
    #endif
}


/*
  This is a log function for only the most serious of problems
*/
int magicnet_critical(const char* message, ...)
{
    #ifdef MAGICNET_SHOW_CRITICAL_LOGS
    pthread_mutex_lock(&log_lock);
    va_list args;
    va_start(args, message);
    vfprintf(stdout, message, args);
    va_end(args);
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
    return 0;
    #else
    return -1;
    #endif
}