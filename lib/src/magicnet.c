#include "magicnet/magicnet.h"
#include "magicnet/config.h"
#include "magicnet/vector.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

/**
 * @brief A vector of struct magicnet_registered_structure determines the registered
 * structures for this client.
 */
static struct vector* structure_vec;
/**
 * @brief Registered program vector with the possible programs struct magicnet_program
 * 
 */
static struct vector* program_vec;


int magicnet_init()
{
    structure_vec = vector_create(sizeof(struct magicnet_registered_structure));
    program_vec = vector_create(sizeof(struct magicnet_program));
    return 0;
}

int magicnet_get_structure(int type, struct magicnet_registered_structure* struct_out)
{
    vector_set_peek_pointer(structure_vec, 0);
    int res = -1;
    struct magicnet_registered_structure* current_struct = vector_peek(structure_vec);
    while(current_struct)
    {
        if (current_struct->type == type)
        {
            memcpy(struct_out,current_struct, sizeof(struct magicnet_registered_structure));
            res = 0;
        }
        current_struct = vector_peek(structure_vec);
    }

    return res;

}

/**
 * @brief Registers the structure on THIS client only, any network operations will be translated
 * based on the structures registered.. Only APPLIES to this client only
 * 
 * @param type 
 * @param size 
 * @return int 
 */
int magicnet_register_structure(long type, size_t size)
{
   struct magicnet_registered_structure structure = {};
    if (magicnet_get_structure(type, &structure) == 0)
    {
        return -1;
    }

    // Let's register this network structure so the application can manage it.
    structure.type = type;
    structure.size = size;
    vector_push(structure_vec, &structure);
    return 0;
}


struct magicnet_program* magicnet_get_program(const char* name)
{
    vector_set_peek_pointer(program_vec, 0);
    struct magicnet_program* program = vector_peek(program_vec);
    while(program)
    {
        if (strncmp(program->name, name, sizeof(program->name)) == 0)
        {
            // A match?
            break;
        }
        program = vector_peek(program_vec);
    }

    return program;
}

struct magicnet_program* magicnet_program(const char* name)
{
    struct magicnet_program* program = magicnet_get_program(name);
    if (program)
    {
        // We already got the program
        return program;
    }

    // We must register the program

    program = calloc(1, sizeof(struct magicnet_program));
    strncpy(program->name, name, sizeof(program->name));
    vector_push(program_vec, program);
    return program;
}