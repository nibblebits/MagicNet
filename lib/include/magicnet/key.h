#ifndef MAGICNET_KEY_H
#define MAGICNET_KEY_H
#include <stddef.h>
#include <stdbool.h>
#include "config.h"
#include "sha256.h"

struct signature
{
    char pr_sig[MAGICNET_MAX_SIGNATURE_PART_LENGTH];
    char ps_sig[MAGICNET_MAX_SIGNATURE_PART_LENGTH];
};

struct key
{
    char key[MAGICNET_MAX_KEY_LENGTH];
    size_t size;
};


struct key_signature_hash
{
    // The hash of the data
    char data_hash[SHA256_STRING_LENGTH];

    // The signature proving the provided key signed the given data hash
    struct signature signature;

    // the public key of the person creating the package. The data was signed
    // with this key
    struct key key;
};


int private_sign(const char *data, size_t size, struct signature *sig_out);
int public_verify(struct key *public_key, const char *data, size_t size, struct signature *sig_in);
int public_verify_key_sig_hash(struct key_signature_hash* key_sig_hash, const char* hash_to_compare);
int private_sign_key_sig_hash(struct key_signature_hash* key_sig_hash, void* hash);
struct key* key_from_key_sig_hash(struct key_signature_hash* key_sig_hash);

/**
 * @brief Returns true if the signature is NULL i.e no signature.
 * 
 * @param signature 
 * @return true 
 * @return false 
 */
bool MAGICNET_nulled_signature(struct signature* signature);
void MAGICNET_load_keypair();
struct key *MAGICNET_public_key();
struct key *MAGICNET_private_key();
bool key_cmp(struct key *key, struct key *key2);
bool key_loaded(struct key *key);

const char* MAGICNET_key_to_string(struct key* key, char* key_str_out, size_t size);
struct key MAGICNET_key_from_string(const char* key);
bool MAGICNET_key_valid(struct key *key);


#endif