#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stddef.h>

#define BUFFER_REALLOC_AMOUNT 2000
#define BUFFER_FLAG_WRAPPED 0b00000001

struct buffer
{
    int flags;
    char* data;
    // Read index
    int rindex;
    int len;
    int msize;
};

struct buffer* buffer_create();
struct buffer* buffer_wrap(void* data, size_t size);

int buffer_len(struct buffer* buffer);
char buffer_read(struct buffer* buffer);

int buffer_read_bytes(struct buffer *buffer, void *ptr, size_t amount);


// Read short
int buffer_read_short(struct buffer *buffer, short* short_out);
// Read int
int buffer_read_int(struct buffer *buffer, int* int_out);

// Read long
int buffer_read_long(struct buffer *buffer, long* long_out);
// Read double
int buffer_read_double(struct buffer *buffer, double* double_out);
int buffer_read_float(struct buffer *buffer, float* float_out);

char buffer_peek(struct buffer* buffer);
void buffer_extend(struct buffer* buffer, size_t size);
void buffer_printf(struct buffer* buffer, const char* fmt, ...);
void buffer_printf_no_terminator(struct buffer* buffer, const char* fmt, ...);
void buffer_write(struct buffer* buffer, char c);
int buffer_write_bytes(struct buffer *buffer, void *ptr, size_t amount);
int buffer_write_int(struct buffer *buffer, int value);
int buffer_write_long(struct buffer *buffer, long value);
void* buffer_ptr(struct buffer* buffer);
int buffer_write_double(struct buffer *buffer, double value);
int buffer_write_float(struct buffer *buffer, float value);
void buffer_free(struct buffer* buffer);


#endif