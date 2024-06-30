#include "buffer.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
int buffer_write_bytes_default_handler(struct buffer *buffer, void *ptr, size_t amount);
int buffer_read_bytes_default_handler(struct buffer *buffer, void *ptr, size_t amount);

struct buffer *buffer_create()
{
   return buffer_create_with_handler(NULL, NULL);
}

struct buffer* buffer_create_with_handler(BUFFER_WRITE_BYTES_FUNCTION write_bytes, BUFFER_READ_BYTES_FUNCTION read_bytes)
{
    struct buffer *buf = calloc(sizeof(struct buffer), 1);
    buf->data = calloc(BUFFER_REALLOC_AMOUNT, 1);
    buf->len = 0;
    buf->msize = BUFFER_REALLOC_AMOUNT;
    buf->write_bytes = buffer_write_bytes_default_handler;
    buf->read_bytes = buffer_read_bytes_default_handler;
    if (write_bytes)
    {
        buf->write_bytes = write_bytes;
    }
    if (read_bytes)
    {
        buf->read_bytes = read_bytes;
    }
    return buf;
}

struct buffer *buffer_wrap(void *data, size_t size)
{
    struct buffer *buf = calloc(sizeof(struct buffer), 1);
    buf->data = data;
    buf->len = size;
    buf->msize = size;
    buf->read_bytes = buffer_read_bytes_default_handler;
    buf->flags |= BUFFER_FLAG_WRAPPED;
    return buf;
}

int buffer_len(struct buffer *buffer)
{
    return buffer->len;
}

void buffer_private_set(struct buffer* buffer, void* private)
{
    buffer->private_data = private;
}

void* buffer_private_get(struct buffer* buffer)
{
    return buffer->private_data;
}

void buffer_extend(struct buffer *buffer, size_t size)
{
    buffer->data = realloc(buffer->data, buffer->msize + size);
    buffer->msize += size;
}

void buffer_need(struct buffer *buffer, size_t size)
{
    if (buffer->msize <= (buffer->len + size))
    {
        size += BUFFER_REALLOC_AMOUNT;
        buffer_extend(buffer, size);
    }
}

void buffer_printf(struct buffer *buffer, const char *fmt, ...)
{
    struct buffer* str_buf = buffer_create();
    // Temporary, this is a limitation we are guessing the size is no more than 2048
    int len = 2048;
    buffer_extend(str_buf, len);

    va_list args;
    va_start(args, fmt);
    int index = buffer->len;    

    int actual_len = vsnprintf(&str_buf->data[0], len, fmt, args);
    str_buf->len += actual_len;
    va_end(args);

    buffer_write_bytes(buffer, str_buf->data, str_buf->len);
    buffer_free(str_buf);
}

void buffer_printf_no_terminator(struct buffer *buffer, const char *fmt, ...)
{
    struct buffer* str_buf = buffer_create();
    // Temporary, this is a limitation we are guessing the size is no more than 2048
    int len = 2048;
    buffer_extend(str_buf, len);

    va_list args;
    va_start(args, fmt);
    int index = buffer->len;    

    int actual_len = vsnprintf(&str_buf->data[0], len, fmt, args);
    str_buf->len += actual_len - 1;
    va_end(args);

    buffer_write_bytes(buffer, str_buf->data, str_buf->len);
    buffer_free(str_buf);
}

void buffer_write(struct buffer *buffer, char c)
{
    buffer_need(buffer, sizeof(char));
    buffer_write_bytes(buffer, &c, sizeof(char));
}

int buffer_write_bytes_default_handler(struct buffer *buffer, void *ptr, size_t amount)
{
    int res = 0;
    buffer_need(buffer, amount);
    memcpy(&buffer->data[buffer->len], ptr, amount);
    buffer->len += amount;
    res = amount;
    return res;
}
int buffer_write_bytes(struct buffer *buffer, void *ptr, size_t amount)
{
    return buffer->write_bytes(buffer, ptr, amount);
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

// write double
int buffer_write_double(struct buffer *buffer, double value)
{
    // Preform bit manipulation for big-endianness todo later...
    if (buffer_write_bytes(buffer, &value, sizeof(value)) < 0)
    {
        return -1;
    }
    return 0;
}

// write float
int buffer_write_float(struct buffer *buffer, float value)
{
    // Preform bit manipulation for big-endianness todo later...
    if (buffer_write_bytes(buffer, &value, sizeof(value)) < 0)
    {
        return -1;
    }
    return 0;
}

void *buffer_ptr(struct buffer *buffer)
{
    return buffer->data;
}

char buffer_read(struct buffer *buffer)
{
    if (buffer->rindex >= buffer->len)
    {
        return -1;
    }
    char c = buffer->data[buffer->rindex];
    buffer->rindex++;
    return c;
}

int buffer_read_bytes_default_handler(struct buffer *buffer, void *ptr, size_t amount)
{
    int res = 0;
    if (buffer->rindex + amount > buffer->len)
    {
        return -1;
    }
    memcpy(ptr, &buffer->data[buffer->rindex], amount);
    buffer->rindex += amount;
    res = amount;
    return res;
}

// Read bytes
int buffer_read_bytes(struct buffer *buffer, void *ptr, size_t amount)
{
    return buffer->read_bytes(buffer, ptr, amount);
}

// Read short
int buffer_read_short(struct buffer *buffer, short *short_out)
{
    if (buffer_read_bytes(buffer, short_out, sizeof(short)) < 0)
    {
        return -1;
    }
    return 0;
}

// Read int
int buffer_read_int(struct buffer *buffer, int *int_out)
{
    if (buffer_read_bytes(buffer, int_out, sizeof(int)) < 0)
    {
        return -1;
    }
    return 0;
}

// Read long
int buffer_read_long(struct buffer *buffer, long *long_out)
{
    if (buffer_read_bytes(buffer, long_out, sizeof(long)) < 0)
    {
        return -1;
    }
    return 0;
}

// Read double
int buffer_read_double(struct buffer *buffer, double *double_out)
{
    if (buffer_read_bytes(buffer, double_out, sizeof(double)) < 0)
    {
        return -1;
    }
    return 0;
}

// Read float
int buffer_read_float(struct buffer *buffer, float *float_out)
{
    if (buffer_read_bytes(buffer, float_out, sizeof(float)) < 0)
    {
        return -1;
    }
    return 0;
}

char buffer_peek(struct buffer *buffer)
{
    if (buffer->rindex >= buffer->len)
    {
        return -1;
    }
    char c = buffer->data[buffer->rindex];
    return c;
}

void buffer_free(struct buffer *buffer)
{
    if (!(buffer->flags & BUFFER_FLAG_WRAPPED))
    {
        free(buffer->data);
    }
    free(buffer);
}
