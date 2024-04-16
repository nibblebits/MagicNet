#include "key.h"

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <stdbool.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <pthread.h>
#include "log.h"
#include "config.h"
#include "sha256.h"
#include "misc.h"
#include "string.h"
#include "database.h"

pthread_mutex_t key_lock;
struct key public_key = {};
struct key private_key = {};

void MAGICNET_keys_init()
{
    if (pthread_mutex_init(&key_lock, NULL) != 0)
    {
        magicnet_log("Failed to initialize the key lock\n");
        return;
    }
}
struct key *MAGICNET_public_key()
{
    return &public_key;
}

struct key *MAGICNET_private_key()
{
    return &private_key;
}

/**
 * Gets a key from string
*/
struct key MAGICNET_key_from_string(const char* key)
{
    struct key k;
    bzero(&k, sizeof(k));
    if (!key)
    {
        return k;
    }
    
    strncpy(k.key, key, sizeof(k.key));
    k.size = strlen(key);
    return k;
}

const char* MAGICNET_key_to_string(struct key* key, char* key_str_out, size_t size)
{
    int res = 0;        
    if (size < sizeof(key->key))
    {
        return NULL;
    }

    strncpy(key_str_out, key->key, size);
    return key_str_out;
}

bool key_loaded(struct key *key)
{
    struct key blank_key;
    bzero(&blank_key, sizeof(blank_key));
    return memcmp(key, &blank_key, sizeof(struct key)) != 0;
}

bool key_cmp(struct key *key, struct key *key2)
{
    if (!key || !key2)
        return false;

    return strncmp(key->key, key2->key, sizeof(key->key)) == 0;
}

/**
 * This function checks that the key is valid
*/
bool MAGICNET_key_valid(struct key *key)
{
    if (!key)
        return false;

    // MINIMIUM size is much higher but ill check later..
    if (key->size < 60)
        return false;

    if (key->size > sizeof(key->key))
        return false;

    if (!is_hex(key->key, sizeof(key->key)))
        return false;

    return true;
}

int public_verify(struct key *public_key, const char *data, size_t size, struct signature *sig_in)
{
    pthread_mutex_lock(&key_lock);
    int res = 0;
    ECDSA_SIG *sig = NULL;
    BIGNUM *pr_sig = NULL;
    BIGNUM *ps_sig = NULL;
    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    EC_POINT *point = EC_POINT_new(ecgroup);

    if (EC_POINT_hex2point(ecgroup, public_key->key, point, ctx) == NULL)
    {
        magicnet_log("%s failed to set point for public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_KEY_set_public_key(eckey, point) <= 0)
    {
        magicnet_log("%s failed to set public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    sig = ECDSA_SIG_new();
    if (BN_hex2bn(&pr_sig, sig_in->pr_sig) <= 0)
    {
        magicnet_log("%s failed to convert hex string back BIGINTEGER\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (BN_hex2bn(&ps_sig, sig_in->ps_sig) <= 0)
    {
        magicnet_log("%s failed to convert hex string back BIGINTEGER\n", __FUNCTION__);
        res = -1;
        goto out;
    }
    if (ECDSA_SIG_set0(sig, pr_sig, ps_sig) <= 0)
    {
        magicnet_log("%s failed to restore signature into BIGNUM\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (ECDSA_do_verify(data, size, sig, eckey) <= 0)
    {
        magicnet_log("%s bad verification with public key err=%s\n", __FUNCTION__, ERR_reason_error_string(ERR_get_error()));
        res = -1;
        goto out;
    }

out:
    if (sig)
    {
        ECDSA_SIG_free(sig);
    }
    if (ctx)
    {
        BN_CTX_free(ctx);
    }

    if (eckey)
    {
        EC_KEY_free(eckey);
    }

    if (ecgroup)
    {
        EC_GROUP_free(ecgroup);
    }

    if (point)
    {
        EC_POINT_free(point);
    }

    pthread_mutex_unlock(&key_lock);

    return res;
}

int public_verify_key_sig_hash(struct key_signature_hash *key_sig_hash, const char *hash_to_compare)
{
    int res = public_verify(&key_sig_hash->key, key_sig_hash->data_hash, sizeof(key_sig_hash->data_hash), &key_sig_hash->signature);
    if (res < 0)
    {
        return res;
    }

    // Now we have confirmed that the hash was signed correctly, we need to now ensure that
    // the hash the key signed is the same as the one we computed.
    return memcmp(hash_to_compare, &key_sig_hash->data_hash, SHA256_STRING_LENGTH) == 0 ? 0 : -1;
}

struct key *key_from_key_sig_hash(struct key_signature_hash *key_sig_hash)
{
    return &key_sig_hash->key;
}

int private_sign_key_sig_hash(struct key_signature_hash *key_sig_hash, void *hash)
{
    bzero(key_sig_hash, sizeof(struct key_signature_hash));
    strncpy(key_sig_hash->data_hash, hash, sizeof(key_sig_hash->data_hash));
    int res = private_sign(key_sig_hash->data_hash, SHA256_STRING_LENGTH, &key_sig_hash->signature);
    if (res < 0)
    {
        return res;
    }

    key_sig_hash->key = *MAGICNET_public_key();
    return res;
}

int private_sign(const char *data, size_t size, struct signature *sig_out)
{
    pthread_mutex_lock(&key_lock);
    int res = 0;
    ECDSA_SIG *sig = NULL;
    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    EC_POINT *point = EC_POINT_new(ecgroup);
    BIGNUM *pnum = NULL;
    if (BN_hex2bn(&pnum, MAGICNET_private_key()->key) <= 0)
    {
        magicnet_log("%s failed to create big number from private key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_POINT_hex2point(ecgroup, MAGICNET_public_key()->key, point, ctx) == NULL)
    {
        magicnet_log("%s failed to set point for public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_KEY_set_public_key(eckey, point) <= 0)
    {
        magicnet_log("%s failed to set public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_KEY_set_private_key(eckey, pnum) <= 0)
    {
        magicnet_log("%s failed to set private key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    sig = ECDSA_do_sign(data, size, eckey);
    if (!sig)
    {
        magicnet_log("%s failed to sign data with key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    const BIGNUM *sig_pr = NULL;
    const BIGNUM *sig_ps = NULL;
    ECDSA_SIG_get0(sig, &sig_pr, &sig_ps);

    char *pr_sig = BN_bn2hex(sig_pr);
    char *ps_sig = BN_bn2hex(sig_ps);

    bzero(sig_out, sizeof(struct signature));
    strncpy(sig_out->pr_sig, pr_sig, sizeof(sig_out->pr_sig));
    strncpy(sig_out->ps_sig, ps_sig, sizeof(sig_out->ps_sig));

    OPENSSL_free(pr_sig);
    OPENSSL_free(ps_sig);

out:
    if (sig)
    {
        ECDSA_SIG_free(sig);
    }
    if (ctx)
    {
        BN_CTX_free(ctx);
    }

    if (eckey)
    {
        EC_KEY_free(eckey);
    }

    if (ecgroup)
    {
        EC_GROUP_free(ecgroup);
    }

    if (point)
    {
        EC_POINT_free(point);
    }

    if (pnum)
    {
        BN_free(pnum);
    }

    pthread_mutex_unlock(&key_lock);

    return res;
}

const char *MAGICNET_private_key_filepath()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(MAGICNET_DATA_BASE_DIRECTORY_ENV), MAGICNET_DATA_BASE, MAGICNET_PRIVATE_KEY_FILEPATH);
    return filepath;
}

const char *MAGICNET_public_key_filepath()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(MAGICNET_DATA_BASE_DIRECTORY_ENV), MAGICNET_DATA_BASE, MAGICNET_PUBLIC_KEY_FILEPATH);
    return filepath;
}

int generate_key()
{
    int res = 0;
    int ret;
    ECDSA_SIG *sig;
    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    BN_CTX *ctx;
    ctx = BN_CTX_new();

    if (eckey == NULL)
    {
        magicnet_log("%S problem creating curve\n", __FUNCTION__);
    }
    /* error */
    if (EC_KEY_generate_key(eckey) == 0)
    {
        magicnet_log("%s problem generating key\n", __FUNCTION__);
    }

    //     if(1 != EC_KEY_set_private_key(key, prv)) handleErrors();
    // if(1 != EC_KEY_set_public_key(key, pub)) handleErrors();

    const BIGNUM *_private_key = EC_KEY_get0_private_key(eckey);
    char *priv_key_hex = BN_bn2hex(_private_key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(eckey);
    char *pub_key_hex = EC_POINT_point2hex(ecgroup, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx);
    magicnet_log("%s public_key=%s\n", __FUNCTION__, pub_key_hex);
    magicnet_log("%s private_key=%s\n", __FUNCTION__, priv_key_hex);

    memcpy(public_key.key, pub_key_hex, strlen(pub_key_hex));
    memcpy(private_key.key, priv_key_hex, strlen(priv_key_hex));
    public_key.size = strlen(pub_key_hex);
    private_key.size = strlen(priv_key_hex);

    if (magicnet_database_keys_create(&public_key, &private_key) != 0)
    {
        magicnet_log("%s issue saving the generated key\n", __FUNCTION__);
        res = -1;
    }

    if (magicnet_database_keys_set_default(&public_key) != 0)
    {
        magicnet_log("%s issue setting our key as active\n", __FUNCTION__);
        res = -1;
    }
    OPENSSL_free(priv_key_hex);
    OPENSSL_free(pub_key_hex);
    EC_KEY_free(eckey);


    magicnet_save_peer_info(&(struct magicnet_peer_information){.key=public_key,.name="Anonymous"});
    return res;
}



bool MAGICNET_nulled_signature(struct signature *signature)
{
    struct signature nulled_sig;
    bzero(&nulled_sig, sizeof(nulled_sig));
    return memcmp(signature, &nulled_sig, sizeof(nulled_sig)) == 0;
}

void MAGICNET_load_keypair()
{
    // Have we already loaded the keypair?
    if (key_loaded(&public_key))
    {
        return;
    }

    MAGICNET_keys_init();

    int res = magicnet_database_keys_get_active(&public_key, &private_key);
    if (res == MAGICNET_ERROR_NOT_FOUND)
    {
        generate_key();
    }
    else if (res < 0)
    {
        magicnet_log("%s something unexpected happend\n", __FUNCTION__);
        return;
    }
}