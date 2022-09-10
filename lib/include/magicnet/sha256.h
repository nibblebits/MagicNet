#ifndef MAGICNET_SHA256
#define MAGICNET_SHA256
#include <stddef.h>
#define SHA256_STRING_LENGTH 65
void sha256_string(char *string, char* outputBuffer);
void sha256_data(void* input, char* outputBuffer, size_t size);
int sha256_file(char *path, char* outputBuffer);

#endif
