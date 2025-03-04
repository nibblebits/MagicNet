#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stddef.h>


// Error codes
#define BUFFER_ALL_OK = 0

#define BUFFER_REALLOC_AMOUNT 2000
#define BUFFER_FLAG_WRAPPED 0b00000001
// If true the data wont be read or written to the buffer
// rather the buffer will act as a stream calling those read and writes will stream from the
// custom handler.
#define BUFFER_READS_FROM_CUSTOM_STREAM = 0b00000100

struct buffer;

typedef int(*BUFFER_WRITE_BYTES_FUNCTION)(struct buffer* buffer, void* ptr, size_t amount);
typedef int(*BUFFER_READ_BYTES_FUNCTION)(struct buffer* buffer, void* ptr, size_t amount);

struct buffer
{
    int flags;
    char* data;
    // Read index
    int rindex;
    int len;
    int msize;

    BUFFER_WRITE_BYTES_FUNCTION write_bytes;
    BUFFER_READ_BYTES_FUNCTION read_bytes;

    // Can be used to store private data related for the person who created the buffer
    void* private_data;
};

struct buffer* buffer_create();
struct buffer* buffer_create_with_handler(BUFFER_WRITE_BYTES_FUNCTION write_bytes, BUFFER_READ_BYTES_FUNCTION read_bytes);
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

void buffer_shift_right_at_position(struct buffer* buffer, int index, int amount);
int buffer_insert(struct buffer* buffer, int index, void* data, size_t len);

/**
 * @brief Set the private data for the buffer, this can be used to store data related to the person who created the buffer
 * 
 * @param buffer The buffer to set the private data for
 * @param private The private data to set
 * @return void
 * 
*/
void buffer_private_set(struct buffer* buffer, void* private);
/**
 * @brief Get the private data for the buffer
 * @param buffer The buffer to get the private data for
 * @return void* The private data
*/
void* buffer_private_get(struct buffer* buffer);


#endif