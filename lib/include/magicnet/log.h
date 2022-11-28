#ifndef MAGICNET_LOG
#define MAGICNET_LOG
void magicnet_log_initialize();
int magicnet_log(const char* message, ...);
int magicnet_important(const char* message, ...);
int magicnet_error(const char* message, ...);
#endif