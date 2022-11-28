#include "buffer.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <memory.h>

struct buffer* buffer_create()
{
    struct buffer* buf = calloc(sizeof(struct buffer), 1);
    buf->data = calloc(BUFFER_REALLOC_AMOUNT, 1);
    buf->len = 0;
    buf->msize = BUFFER_REALLOC_AMOUNT;
    return buf;
}

int buffer_len(struct buffer* buffer)
{
    return buffer->len;
}

void buffer_extend(struct buffer* buffer, size_t size)
{
    buffer->data = realloc(buffer->data, buffer->msize+size);
    buffer->msize+=size;
}

void buffer_need(struct buffer* buffer, size_t size)
{
    if (buffer->msize <= (buffer->len+size))
    {
        size += BUFFER_REALLOC_AMOUNT;
        buffer_extend(buffer, size);
    }
}


void buffer_printf(struct buffer* buffer, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int index = buffer->len;
    // Temporary, this is a limitation we are guessing the size is no more than 2048
    int len = 2048;
    buffer_extend(buffer, len);
    int actual_len = vsnprintf(&buffer->data[index], len, fmt, args);
    buffer->len += actual_len;
    va_end(args);
}

void buffer_printf_no_terminator(struct buffer* buffer, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int index = buffer->len;
    // Temporary, this is a limitation we are guessing the size is no more than 2048
    int len = 2048;
    buffer_extend(buffer, len);
    int actual_len = vsnprintf(&buffer->data[index], len, fmt, args);
    buffer->len += actual_len-1;
    va_end(args);
}

void buffer_write(struct buffer* buffer, char c)
{
    buffer_need(buffer, sizeof(char));

    buffer->data[buffer->len] = c;
    buffer->len++;
}


int buffer_write_bytes(struct buffer *buffer, void *ptr, size_t amount)
{
    int res = 0;
    buffer_need(buffer, amount);
    memcpy(&buffer->data[buffer->len], ptr, amount);
    buffer->len += amount;
    res = amount;
    return res;
}


int buffer_write_int(struct buffer *buffer, int value)
{
    // Preform bit manipulation for big-endianness todo later...
    if (buffer_write_bytes(buffer, &value, sizeof(value)) < 0)
    {
        return -1;
    }
    return 0;
}

int buffer_write_long(struct buffer *buffer, long value)
{
    // Preform bit manipulation for big-endianness todo later...
    if (buffer_write_bytes(buffer, &value, sizeof(value)) < 0)
    {
        return -1;
    }
    return 0;
}


void* buffer_ptr(struct buffer* buffer)
{
    return buffer->data;
}

char buffer_read(struct buffer* buffer)
{
    if (buffer->rindex >= buffer->len)
    {
        return -1;
    }
    char c = buffer->data[buffer->rindex];
    buffer->rindex++;
    return c;
}

char buffer_peek(struct buffer* buffer)
{
    if (buffer->rindex >= buffer->len)
    {
        return -1;
    }
    char c = buffer->data[buffer->rindex];
    return c;
}

void buffer_free(struct buffer* buffer)
{
    free(buffer->data);
    free(buffer);
}
