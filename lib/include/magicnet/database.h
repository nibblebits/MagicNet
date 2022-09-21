#ifndef MAGICNET_DATABASE
#define MAGICNET_DATABASE
int magicnet_database_load_block(const char* hash, struct block* block_out);
int magicnet_database_load();
#endif