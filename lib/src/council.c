

/**
 * THis file is responsible for council related actions
 */

#include "magicnet.h"
#include "config.h"
#include "misc.h"
#include "log.h"
#include "database.h"
#include "sha256.h"
#include "key.h"
#include <stdlib.h>
#include <string.h>

static struct magicnet_council *central_council = NULL;
int magicnet_council_init()
{
    int res = 0;

    // Obviously we want to load the council from the database
    // we are simulating many actions here as we continue to build on the council funtionality
    central_council = magicnet_council_create(MAGICNET_MASTER_COUNCIL_NAME, 2, time(NULL));

    return res;
}

struct magicnet_council_certificate *magicnet_council_certificate_create()
{
    return calloc(1, sizeof(struct magicnet_council_certificate));
}
void magicnet_council_certificate_free(struct magicnet_council_certificate *certificate);

void magincet_council_certificate_vote_free_data(struct council_certificate_transfer_vote *certificate_vote)
{

}

void magicnet_council_certificate_transfer_free_data(struct council_certificate_transfer *certificate_transfer)
{

    if (certificate_transfer->voters)
    {
        for (int i = 0; i < certificate_transfer->total_voters; i++)
        {
            magincet_council_certificate_vote_free_data(&certificate_transfer->voters[i]);
        }
        free(certificate_transfer->voters);
    }
}
void magicnet_council_certificate_free_data(struct magicnet_council_certificate *certificate)
{
    magicnet_council_certificate_transfer_free_data(&certificate->signed_data.transfer);
}
void magicnet_council_certificate_free(struct magicnet_council_certificate *certificate)
{
    magicnet_council_certificate_free_data(certificate);
    free(certificate);
}

int magicnet_council_certificate_sign(struct magicnet_council_certificate *certificate)
{
    int res = 0;
    res = private_sign(certificate->hash, sizeof(certificate->hash), &certificate->signature);
    if (res < 0)
    {
        goto out;
    }

    certificate->owner_key = *MAGICNET_public_key();

out:
    return res;
}

struct magicnet_council_certificate* magicnet_council_certificate_load(const char* certificate_hash)
{
    // Pretend to load from the database for noww... At the moment we aren't loading anything. Just
    // simulate it

    // Just load the first certificate from the central council, we all playign simulation games right now..
    struct magicnet_council_certificate* certificate = magicnet_council_certificate_clone(&central_council->signed_data.certificates[0]);
    return certificate;
}

void magicnet_council_certificate_hash(struct magicnet_council_certificate *certificate, char *out_hash)
{
    struct buffer *certificate_signed_data_buf = buffer_create();
    buffer_write_int(certificate_signed_data_buf, certificate->signed_data.id);
    buffer_write_int(certificate_signed_data_buf, certificate->signed_data.flags);
    buffer_write_bytes(certificate_signed_data_buf, certificate->signed_data.council_id_hash, sizeof(certificate->signed_data.council_id_hash));
    buffer_write_long(certificate_signed_data_buf, certificate->signed_data.expires_at);
    buffer_write_long(certificate_signed_data_buf, certificate->signed_data.valid_from);
    sha256_data(buffer_ptr(certificate_signed_data_buf), out_hash, buffer_len(certificate_signed_data_buf));
    buffer_free(certificate_signed_data_buf);
}

/**
 * Verifies the certificate is signed correctly, however does not check whatsoever if the certificate
 * is legally valid.
 */
int magicnet_council_certificate_verify_signature(struct magicnet_council_certificate *certificate)
{
    int res = 0;
    char hash[SHA256_STRING_LENGTH];
    magicnet_council_certificate_hash(certificate, hash);

    if (strncmp(hash, certificate->hash, sizeof(hash)) != 0)
    {
        magicnet_log("%s council certificate verification failed for hash %s, hash mismatch\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    res = public_verify(&certificate->owner_key, hash, sizeof(hash), &certificate->signature);
    if (res < 0)
    {
        magicnet_log("%s council certificate verification failed for hash %s, signature is invalid\n", __FUNCTION__, hash);
        goto out;
    }
out:
    return res;
}

int magicnet_council_certificate_verify(struct magicnet_council_certificate* certificate)
{
    int res = 0;
    res = magicnet_council_certificate_verify_signature(certificate);
    if (res < 0)
    {
        goto out;
    }


    // Next we need to loop back and verify through all the certificate transfers to ensure this certificate
    // is legitimate..
    // TODO Later..

out:
    return res;
}

void magicnet_council_certificate_clone_signed_data(struct council_certificate_transfer *transfer_out, struct council_certificate_transfer *transfer_in)
{
    // TODO
}

struct magicnet_council_certificate *magicnet_council_certificate_clone(struct magicnet_council_certificate *certificate)
{
    struct magicnet_council_certificate *certificate_out = calloc(1, sizeof(struct magicnet_council_certificate));
    if (!certificate_out)
    {
        goto out;
    }

    memcpy(certificate_out, certificate, sizeof(struct magicnet_council_certificate));
    magicnet_council_certificate_clone_signed_data(&certificate_out->signed_data.transfer, &certificate->signed_data.transfer);

    // Verify the integrety of what we have copied
    int res = magicnet_council_certificate_verify_signature(certificate_out);
    if (res < 0)
    {
        magicnet_log("%s We had an issue copying the council certificate correctly or the input certificate was invalid", __FUNCTION__);
        magicnet_council_certificate_free(certificate_out);
        certificate_out = NULL;
        goto out;
    }
out:
    return certificate_out;
}

int magicnet_council_build_certificate(struct magicnet_council *council, int id_no, int flags, time_t valid_from, time_t expires_at, struct magicnet_council_certificate *certificate_out)
{
    int res = 0;
    strncpy(certificate_out->signed_data.council_id_hash, council->signed_data.id_hash, sizeof(certificate_out->signed_data.council_id_hash));
    certificate_out->signed_data.id = id_no;
    certificate_out->signed_data.flags = flags;
    certificate_out->signed_data.expires_at = expires_at;
    certificate_out->signed_data.valid_from = valid_from;
    magicnet_council_certificate_hash(certificate_out, certificate_out->hash);
    res = magicnet_council_certificate_sign(certificate_out);
    if (res < 0)
    {
        goto out;
    }
out:
    return res;
}

void magicnet_council_hash(struct magicnet_council *council, char *out_hash)
{
    struct magicnet_council_signed_data *signed_data = &council->signed_data;

    struct buffer *council_hash_buf = buffer_create();
    buffer_write_bytes(council_hash_buf, signed_data->id_hash, sizeof(signed_data->id_hash));
    for (size_t i = 0; i < council->signed_data.id_signed_data.total_certificates; i++)
    {
        // Hash will work since signed data was signed.
        buffer_write_bytes(council_hash_buf, council->signed_data.certificates[i].hash, sizeof(council->signed_data.certificates[i].hash));
        buffer_write_bytes(council_hash_buf, &council->signed_data.certificates[i].signature, sizeof(council->signed_data.certificates[i].signature));
        buffer_write_bytes(council_hash_buf, &council->signed_data.certificates[i].owner_key, sizeof(council->signed_data.certificates[i].owner_key));
    }
    sha256_data(buffer_ptr(council_hash_buf), out_hash, buffer_len(council_hash_buf));
    buffer_free(council_hash_buf);
}

int magicnet_council_sign(struct magicnet_council *council)
{
    int res = 0;
    res = private_sign(council->hash, sizeof(council->hash), &council->creator.signature);
    if (res < 0)
    {
        goto out;
    }

    council->creator.key = *MAGICNET_public_key();

out:
    return res;
}
/**
 * Hashes the council ID
 */
void magicnet_council_id_hash(struct magicnet_council *council, char *out_hash)
{
    struct magicnet_council_id_signed_data *signed_data = &council->signed_data.id_signed_data;

    struct buffer *id_hash_buf = buffer_create();
    buffer_write_bytes(id_hash_buf, signed_data->name, MAGICNET_COUNCIL_NAME_LENGTH);
    buffer_write_long(id_hash_buf, signed_data->total_certificates);
    buffer_write_long(id_hash_buf, signed_data->creation_time);

    sha256_data(buffer_ptr(id_hash_buf), out_hash, buffer_len(id_hash_buf));
    buffer_free(id_hash_buf);
}

void magicnet_council_free(struct magicnet_council *council)
{
    // Implement free funtionaliuty...
}

struct magicnet_council *magicnet_council_create(const char *name, size_t total_certificates, time_t creation_time)
{
    // Must have at least one certificate.
    if (total_certificates <= 0)
    {
        return NULL;
    }

    int res = 0;
    struct magicnet_council *council = calloc(1, sizeof(struct magicnet_council));
    struct magicnet_council_certificate *certificates = calloc(total_certificates, sizeof(struct magicnet_council_certificate));
    council->signed_data.certificates = certificates;

    strncpy(council->signed_data.id_signed_data.name, name, sizeof(council->signed_data.id_signed_data.name));
    council->signed_data.id_signed_data.total_certificates = total_certificates;
    council->signed_data.id_signed_data.creation_time = creation_time;

    // We must calculate the hash ID of this council that will be used to reference it throughout the system
    magicnet_council_id_hash(council, council->signed_data.id_hash);

    time_t one_year_later = creation_time + (86400 * 365);
    // First certificate will be given to the creator of the council and will expire in one year
    magicnet_council_build_certificate(council, 0, MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS, creation_time, one_year_later, &certificates[0]);

    for (size_t i = 1; i < total_certificates; i++)
    {
        // Other certificates will be expires by default requiring the council creator to send them out
        res = magicnet_council_build_certificate(council, i, MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS, 0, 0, &certificates[i]);
        if (res < 0)
        {
            goto out;
        }
    }

    magicnet_council_hash(council, council->hash);
    res = magicnet_council_sign(council);
    if (res < 0)
    {
        goto out;
    }
out:
    if (res < 0)
    {
        magicnet_council_free(council);
        council = NULL;
    }
    return council;
}
