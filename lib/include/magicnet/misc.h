#ifndef MISC_H
#define MISC_H
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#define NO_THREAD_SAFETY 
#define USES_LOCKS

#define S_EQ(s1, s2) \
    (s1 && s2 && strcmp(s1, s2) == 0)

bool file_exists(const char *filename);
size_t filesize(const char* filename);


void bin2hex(char *input, size_t input_size, char *output);
int hex2bin(unsigned char *data, const unsigned char *hexstring, unsigned int len);
bool is_hex(const char *str, size_t max_size);
void* alloc_memcpy(void* src, size_t size);
void alloc_memcpy_free(void* ptr);
long hash_number(const char *hash);

#endif