#ifndef MAGICNET_DATABASE
#define MAGICNET_DATABASE
#include "magicnet.h"
#include "key.h"
int magicnet_database_load_block_no_locks(const char *hash, char *prev_hash_out, int *blockchain_id, char *transaction_group_hash, struct key* key, struct signature* signature);
int magicnet_database_load_block(const char *hash, char *prev_hash_out, int *blockchain_id, char *transaction_group_hash, struct key* key, struct signature* signature);
int magicnet_database_load_block_from_previous_hash(const char* prev_hash, char *hash_out, int *blockchain_id, char *transaction_group_hash);
int magicnet_database_load_block_from_previous_hash_no_locks(const char* prev_hash, char *hash_out, int *blockchain_id, char *transaction_group_hash);
int magicnet_database_load();
int magicnet_database_blockchain_increment_proven_verified_blocks(int blockchain_id);
int magicnet_database_save_block(struct block *block);
int magicnet_database_load_last_block(char *hash_out, char *prev_hash_out);
int magicnet_database_blockchain_load_from_last_hash(const char* last_hash, struct blockchain *blockchain_out);
int magicnet_database_blockchain_save(struct blockchain* blockchain);
int magicnet_database_blocks_swap_chain(int blockchain_id_to_swap, int blockchain_id_to_swap_to);
int magicnet_database_blockchain_delete(int blockchain_id);
int magicnet_database_blockchain_blocks_count(int blockchain_id);
int magicnet_database_update_block(struct block *block);
int magicnet_database_load_blocks(struct vector *block_vec_out, size_t amount);
int magicnet_database_load_blocks_with_no_chain(struct vector *block_vec_out, size_t amount);
int magicnet_database_load_block_transactions(struct block *block);
int magicnet_database_count_blocks_with_previous_hash(const char* prev_hash);
int magicnet_database_delete_all_chains_keep_blocks();
int magicnet_database_blockchain_get_active(struct blockchain **blockchain_out);
int magicnet_database_peer_add_no_locks(const char *ip_address, struct key *key, const char *name, const char *email);
int magicnet_database_peer_add(const char *ip_address, struct key *key, const char *name, const char *email);
int magicnet_database_peer_get_random_ip(char *ip_address_out);
int magicnet_database_peer_update_or_create(struct magicnet_peer_information* peer_info);
int magicnet_database_peer_load_by_key(struct key *key, struct magicnet_peer_information *peer_out);
int magicnet_database_peer_load_by_key_no_locks(struct key *key, struct magicnet_peer_information *peer_out);
int magicnet_database_keys_create(struct key* pub_key, struct key* pri_key);
int magicnet_database_keys_set_default(struct key* pub_key);
int magicnet_database_keys_get_active(struct key* key_pub_out, struct key* key_pri_out);
int magicnet_database_banned_peer_load_by_ip(const char *ip_address, struct magicnet_banned_peer_information *peer_out);

/**
 * Creates a new blockchain 
 */
int magicnet_database_blockchain_create(BLOCKCHAIN_TYPE type, const char* begin_hash, struct blockchain *blockchain_out);
int magicnet_database_blockchain_update_last_hash(int blockchain_id, const char* new_last_hash);
int magicnet_database_load_block_with_previous_hash(const char *prev_hash, char *hash_out);
int magicnet_database_blockchain_all(struct vector *blockchain_vector_out);
int magicnet_database_get_active_blockchain_id();

int magincet_database_save_transaction_group(struct block_transaction_group *transaction_group);


void magicnet_database_close();

#endif