#include "buffer.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
int buffer_write_bytes_default_handler(struct buffer *buffer, void *ptr, size_t amount);
int buffer_read_bytes_default_handler(struct buffer *buffer, void *ptr, size_t amount);

struct buffer *buffer_create()
{
    return buffer_create_with_handler(NULL, NULL, NULL);
}

struct buffer *buffer_clone(struct buffer *buffer_in)
{
    int res = 0;
    struct buffer *cloned_buffer = buffer_create();
    if (!cloned_buffer)
    {
        res = -1;
        goto out;
    }

    memcpy(cloned_buffer, buffer_in, sizeof(*cloned_buffer));
    cloned_buffer->data = calloc(buffer_in->msize, 1);
    if (!cloned_buffer->data)
    {
        res = -1;
        goto out;
    }

    memcpy(cloned_buffer->data, buffer_in->data, buffer_in->msize);

    // We shall inform the buffer that its been cloned
    // the owner is responsible for cloning his private data into cloned_buffer.
    res = buffer_in->buffer_cloned(buffer_in, cloned_buffer);
    if (res < 0)
    {
        // The buffer owner has refused the clone.
        goto out;
    }
out:
    if (res < 0)
    {
        free(cloned_buffer->data);
        free(cloned_buffer);
        cloned_buffer = NULL;
    }
    return cloned_buffer;
}

int buffer_cloned_default_handler(struct buffer *buffer_in, struct buffer *buffer_out)
{
    // Default handler accepts this cloning.
    return 0;
}

struct buffer *buffer_create_with_handler(BUFFER_WRITE_BYTES_FUNCTION write_bytes, BUFFER_READ_BYTES_FUNCTION read_bytes, BUFFER_CLONED_FUNCTION cloned)
{
    int res = 0;
    struct buffer *buf = calloc(sizeof(struct buffer), 1);
    // valgrind complains bytes uninitialized but calloc setss to zero
    //  odd false positive perhaps.
    buf->data = calloc(BUFFER_REALLOC_AMOUNT, 1);
    if (!buf->data)
    {
        res = -1;
        goto out;
    }

    buf->len = 0;
    buf->msize = BUFFER_REALLOC_AMOUNT;
    buf->write_bytes = buffer_write_bytes_default_handler;
    buf->read_bytes = buffer_read_bytes_default_handler;
    buf->buffer_cloned = buffer_cloned_default_handler;
    if (write_bytes)
    {
        buf->write_bytes = write_bytes;
    }
    if (read_bytes)
    {
        buf->read_bytes = read_bytes;
    }

    if (cloned)
    {
        buf->buffer_cloned = cloned;
    }
out:
    if (res < 0)
    {
        free(buf->data);
        free(buf);
        buf = NULL;
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
    buf->write_bytes = buffer_write_bytes_default_handler;
    buf->flags |= BUFFER_FLAG_WRAPPED;
    return buf;
}

int buffer_len(struct buffer *buffer)
{
    return buffer->len;
}

void buffer_private_set(struct buffer *buffer, void *private)
{
    buffer->private_data = private;
}

void *buffer_private_get(struct buffer *buffer)
{
    return buffer->private_data;
}

void buffer_extend(struct buffer *buffer, size_t size)
{
    buffer->data = realloc(buffer->data, buffer->msize + size);
    buffer->msize += size;
}

int buffer_memory_len(struct buffer* buffer)
{
    return buffer->msize;
}

void buffer_need(struct buffer *buffer, size_t size)
{
    if (buffer->msize <= (buffer->len + size))
    {
        size += BUFFER_REALLOC_AMOUNT;
        buffer_extend(buffer, size);
    }
}

void buffer_empty(struct buffer *buffer)
{
    // EMptying should be as simple as resetting the indexes
    // to zero.
    if (buffer->data && buffer->len > 0)
    {
        // Just in case someone uses the buffer for strings
        // and doesnt bother to work with the length.
        buffer->data[0] = 0x00;
    }

    buffer->rindex = 0;
    buffer->len = 0;
}
void buffer_printf(struct buffer *buffer, const char *fmt, ...)
{
    struct buffer *str_buf = buffer_create();
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
    struct buffer *str_buf = buffer_create();
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

void buffer_shift_right_at_position(struct buffer *buffer, int index, int amount)
{
    // index = 10
    // len = 100
    // amount = 1
    // goal shift the stream from index 10 one byte to the right
    // new location index 11
    // null index 10 
    // new length 101

    // first how much do we need
    // amount will always be the amount to shift the stream thus its the memory needed
    int amount_mem_needed = amount;
    buffer_need(buffer, amount_mem_needed);

    
    // Now we have the memory no possible overflow
    int shift_to_index = index+amount; // index 10 + 1(amount) = index 11
    int shift_from_index = index;      // 10 = old_index
    int amount_to_copy = (buffer->len - shift_from_index); // 100 - 10 = 90
    // lets prove it
    // 90 + 1 + 10 = 101 
    // ok it should be right.


    // copy the memory to the new location
    memmove(&buffer->data[shift_to_index], &buffer->data[shift_from_index], amount_to_copy);

    // null the old memory
    memset(&buffer->data[shift_from_index], 0x00, amount);

    buffer->len += amount;
}

int buffer_insert(struct buffer *buffer, int index, void *data, size_t len)
{
    // Make memory for the insertation.
    buffer_shift_right_at_position(buffer, index, len);

    // Move the data into the region
    memcpy(&buffer->data[index], data, len);

    return 0;
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
        if (buffer->data)
        {
            free(buffer->data);
        }
    }
    free(buffer);
}
