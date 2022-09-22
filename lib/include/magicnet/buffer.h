#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stddef.h>

#define BUFFER_REALLOC_AMOUNT 2000
struct buffer
{
    char* data;
    // Read index
    int rindex;
    int len;
    int msize;
};

struct buffer* buffer_create();
int buffer_len(struct buffer* buffer);
char buffer_read(struct buffer* buffer);
char buffer_peek(struct buffer* buffer);
void buffer_extend(struct buffer* buffer, size_t size);
void buffer_printf(struct buffer* buffer, const char* fmt, ...);
void buffer_printf_no_terminator(struct buffer* buffer, const char* fmt, ...);
void buffer_write(struct buffer* buffer, char c);
int buffer_write_bytes(struct buffer *buffer, void *ptr, size_t amount);
int buffer_write_int(struct buffer *buffer, int value);
int buffer_write_long(struct buffer *buffer, long value);
void* buffer_ptr(struct buffer* buffer);
void buffer_free(struct buffer* buffer);


#endif