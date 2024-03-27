#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>


long hash_number(const char *hash)
{
    if (strlen(hash) < 8)
        return -1;

    char eight_bytes[9] = {};
    char *ptr = NULL;
    strncpy(eight_bytes, hash, 8);

    return strtol(eight_bytes, &ptr, 16);
}


void* alloc_memcpy(void* src, size_t size)
{
    void* dest = malloc(size);
    if (dest)
        memcpy(dest, src, size);
    return dest;
}

void alloc_memcpy_free(void* ptr)
{
    if (ptr)
        free(ptr);
}

bool file_exists(const char *filename)
{
    bool exists = false;
    FILE *fp = fopen(filename, "r");
    if (fp)
    {
        exists = true;
        fclose(fp);
    }
    return exists;
}

size_t filesize(const char* filename)
{
    FILE* f = fopen(filename, "r");
    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);

    size_t size = ftell(f);
    fclose(f);
    return size;
}

/**
 * This function checks if the input string is completley hexadecimal
*/
bool is_hex(const char *str, size_t max_size)
{
    size_t i = 0;
    while (i < max_size)
    {
        if (str[i] == '\0')
            return true;
        if (str[i] >= '0' && str[i] <= '9')
            i++;
        else if (str[i] >= 'a' && str[i] <= 'f')
            i++;
        else if (str[i] >= 'A' && str[i] <= 'F')
            i++;
        else
            return false;
    }
    return false;
}

void bin2hex(char *input, size_t input_size, char *output)
{
    int loop = 0;
    int i = 0;
    while (loop < input_size)
    {
        sprintf((char *)(output + i), "%02X", input[loop]);
        loop += 1;
        i += 2;
    }
    //marking the end of the string
    output[i++] = '\0';
}


int hex_to_int(char c)
{
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9)
        result--;
    return result;
}

int hex_to_ascii(char c, char d)
{
    int high = hex_to_int(c) * 16;
    int low = hex_to_int(d);
    return high + low;
}

int hex2bin(unsigned char *data, const unsigned char *hexstring, unsigned int len)
{
    unsigned const char *pos = hexstring;
    char *endptr;
    size_t count = 0;

    if ((hexstring[0] == '\0') || (strlen(hexstring) % 2)) {
        //hexstring contains no data
        //or hexstring has an odd length
        return -1;
    }

    for(count = 0; count < len; count++) {
        char buf[5] = {'0', 'x', pos[0], pos[1], 0};
        data[count] = strtol(buf, &endptr, 0);
        pos += 2 * sizeof(char);

        if (endptr[0] != '\0') {
            //non-hexadecimal character encountered
            return -1;
        }
    }

    return 0;
}