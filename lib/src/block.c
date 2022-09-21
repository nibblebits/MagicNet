#include "magicnet.h"
#include "config.h"
void magicnet_get_block_path(struct block* block, char* block_path_out)
{
    sprintf(block_path_out, "%s/%s/%s/%s", getenv("HOME"), ".magicnet", MAGICNET_BLOCK_DIRECTORY, block->block_uri);
}