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

#endif