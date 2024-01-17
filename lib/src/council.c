

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

/**
 * A vector of loaded councils
*/

struct loaded_council_vector
{
    struct vector* vector;
    pthread_mutex_t lock;
} loaded_council;



void magicnet_council_certificate_free(struct magicnet_council_certificate *certificate);
void magicnet_council_certificate_free_data(struct magicnet_council_certificate *certificate);

int magicnet_council_certificate_verify_signed_data(struct magicnet_council_certificate *certificate, struct signature *signature, const char *hash)
{
    int res = 0;
    res = public_verify(&certificate->owner_key, hash, SHA256_STRING_LENGTH, signature);
    if (res < 0)
    {
        magicnet_log("%s council certificate verification failed for hash %s, signature is invalid\n", __FUNCTION__, hash);
        goto out;
    }

out:
    return res;
}

int magicnet_council_vector_init()
{
    int res = 0;
    loaded_council.vector = vector_create(sizeof(struct magicnet_council*));
    if (!loaded_council.vector)
    {
        res = -1;
        goto out;
    }
    pthread_mutex_init(&loaded_council.lock, NULL);

out:
    return res;
}

int magicnet_council_vector_deallocate()
{
    int res  = 0;
    pthread_mutex_lock(&loaded_council.lock);
    vector_set_peek_pointer(loaded_council.vector, 0);
    struct magicnet_council* council = vector_peek_ptr(loaded_council.vector);
    while(council)
    {
        magicnet_council_free(council);
        council = vector_peek_ptr(loaded_council.vector);
    }
    
    vector_free(loaded_council.vector);
    loaded_council.vector = NULL;
    pthread_mutex_unlock(&loaded_council.lock);
    pthread_mutex_destroy(&loaded_council.lock);
    return res;
}

int magicnet_council_vector_add(struct magicnet_council *council)
{
    int res = 0;
    pthread_mutex_lock(&loaded_council.lock);
    vector_push(loaded_council.vector, &council);
    pthread_mutex_unlock(&loaded_council.lock);
    return res;
}

int magicnet_council_load(const char* council_id_hash, struct magicnet_council** council_out)
{
    int res = 0;
    pthread_mutex_lock(&loaded_council.lock);

    // Check if we already have this council loaded
    vector_set_peek_pointer(loaded_council.vector, 0);
    struct magicnet_council* council = vector_peek_ptr(loaded_council.vector);
    while(council)
    {
        if (strncmp(council->signed_data.id_hash, council_id_hash, sizeof(council->signed_data.id_hash)) == 0)
        {
            // We already have this council loaded
            *council_out = council;
            goto out;
        }
        vector_set_peek_pointer(loaded_council.vector, 1);
        council = vector_peek_ptr(loaded_council.vector);
    }


    // Still no council? Then load from the database
    council = calloc(1, sizeof(struct magicnet_council));
    if (!council)
    {
        res = -1;
        goto out;
    }

    res = magicnet_database_load_council(council_id_hash, council);
    if (res < 0)
    {
        goto out;
    }

    res = magicnet_council_verify(council);
    if (res < 0)
    {
        goto out;
    }
    
    // Lets add the council to the vector so it remains cached
    res = magicnet_council_vector_add(council);
    if (res < 0)
    {
        goto out;
    }
out:
    pthread_mutex_unlock(&loaded_council.lock);
    return res;
}

bool magicnet_council_is_genesis_certificate(struct magicnet_council* council, struct magicnet_council_certificate* certificate)
{
    bool res = false;
    if (!(certificate->signed_data.flags & MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS))
    {
        res = false;
        goto out;
    }

    if (council->signed_data.id_signed_data.total_certificates < certificate->signed_data.id)
    {
        res = false;
        goto out;
    }

    struct magicnet_council_certificate* council_cert = &council->signed_data.certificates[certificate->signed_data.id];
    if (memcmp(council_cert->hash, certificate->hash, sizeof(council_cert->hash)) == 0)
    {
        res = true;
        goto out;
    }
out:
    return res;
}

int magicnet_council_init()
{
    int res = 0;

    // INitialize the council vector cache
    res = magicnet_council_vector_init();
    if (res < 0)
    {
        goto out;
    }

    // Obviously we want to load the council from the database
    // we are simulating many actions here as we continue to build on the council funtionality
    central_council = magicnet_council_create(MAGICNET_MASTER_COUNCIL_NAME, 2, time(NULL));
    if (!central_council)
    {
        res = -1;
        goto out;
    }

    res = magicnet_council_save(central_council);

out:
    return res;
}


void magicnet_council_free(struct magicnet_council *council)
{
    // Implement free funtionaliuty...
}

int magicnet_council_save(struct magicnet_council *council)
{
    int res = 0;
    res = magicnet_council_verify(council);
    if (res < 0)
    {
        magicnet_log("%s council verification failed for hash %s, council is invalid\n", __FUNCTION__, council->hash);
        goto out;
    }

    res = magicnet_database_write_council(council);
    if (res < 0)
    {
        magicnet_log("%s council verification failed for hash %s, council is invalid\n", __FUNCTION__, council->hash);
        goto out;
    }
out:
    return res;
}


void magicnet_council_certificate_many_free(struct magicnet_council_certificate *certificates_ptr, size_t amount)
{
    for (size_t i = 0; i < amount; i++)
    {
        magicnet_council_certificate_free_data(&certificates_ptr[i]);
    }
    free(certificates_ptr);
}

struct magicnet_council_certificate *magicnet_council_certificate_create_many(size_t total)
{
    return calloc(total, sizeof(struct magicnet_council_certificate));
}

struct magicnet_council_certificate *magicnet_council_certificate_create()
{
    return magicnet_council_certificate_create_many(1);
}

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

int magicnet_council_certificate_sign_and_take_ownership(struct magicnet_council_certificate *certificate)
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

struct magicnet_council_certificate *magicnet_council_certificate_load(const char *certificate_hash)
{
    // Pretend to load from the database for noww... At the moment we aren't loading anything. Just
    // simulate it

    // Just load the first certificate from the central council, we all playign simulation games right now..
    struct magicnet_council_certificate *certificate = magicnet_council_certificate_clone(&central_council->signed_data.certificates[0]);
    return certificate;
}

void magicnet_council_certificate_transfer_vote_hash(struct council_certificate_transfer_vote *vote, char *out_hash)
{
    struct buffer *certificate_transfer_vote_buf = buffer_create();
    char voting_certificate_hash[SHA256_STRING_LENGTH] = {0};

    buffer_write_bytes(certificate_transfer_vote_buf, &vote->signed_data.certificate_to_transfer_hash, sizeof(vote->signed_data.certificate_to_transfer_hash));
    buffer_write_long(certificate_transfer_vote_buf, vote->signed_data.total_voters);
    buffer_write_long(certificate_transfer_vote_buf, vote->signed_data.total_for_vote);
    buffer_write_long(certificate_transfer_vote_buf, vote->signed_data.total_against_vote);
    buffer_write_long(certificate_transfer_vote_buf, vote->signed_data.certificate_expires_at);
    buffer_write_long(certificate_transfer_vote_buf, vote->signed_data.certificate_valid_from);

    buffer_write_bytes(certificate_transfer_vote_buf, &vote->signed_data.new_owner_key, sizeof(vote->signed_data.new_owner_key));
    buffer_write_bytes(certificate_transfer_vote_buf, &vote->signed_data.winning_key, sizeof(vote->signed_data.winning_key));

    sha256_data(buffer_ptr(certificate_transfer_vote_buf), out_hash, buffer_len(certificate_transfer_vote_buf));
    buffer_free(certificate_transfer_vote_buf);
}

int magicnet_council_certificate_transfer_vote_verify(struct magicnet_council_certificate* certificate, struct council_certificate_transfer_vote *vote)
{
    int res = 0;
    char hash[SHA256_STRING_LENGTH];

    if (vote->signed_data.total_for_vote + vote->signed_data.total_against_vote != vote->signed_data.total_voters)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, total voters does not match total for and against votes\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    if (certificate->signed_data.transfer.total_voters != vote->signed_data.total_voters)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, total voters does not equal the same amount of voters in the transfer\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    if (certificate->signed_data.expires_at != vote->signed_data.certificate_expires_at 
        || certificate->signed_data.valid_from != vote->signed_data.certificate_valid_from)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, certificate expiry or valid from does not match the transfer\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    magicnet_council_certificate_transfer_vote_hash(vote, hash);
    if (memcmp(hash, vote->hash, sizeof(hash)) != 0)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, hash mismatch\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    res = magicnet_council_certificate_verify_signed_data(vote->voter_certificate, &vote->signature, hash);
    if (res < 0)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, signature is invalid\n", __FUNCTION__, hash);
        goto out;
    }

    // Verify the voting certificate
    res = magicnet_council_certificate_verify(vote->voter_certificate);
    if (res < 0)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, voting certificate is invalid\n", __FUNCTION__, hash);
        goto out;
    }

out:
    return res;
}

void magicnet_council_certificate_transfer_hash(struct council_certificate_transfer *transfer, char *out_hash)
{
    struct buffer *certificate_transfer_buf = buffer_create();
    if (transfer->certificate)
    {
        char certificate_hash[SHA256_STRING_LENGTH];
        magicnet_council_certificate_hash(transfer->certificate, certificate_hash);
        buffer_write_bytes(certificate_transfer_buf, certificate_hash, sizeof(certificate_hash));
    }
    buffer_write_bytes(certificate_transfer_buf, &transfer->new_owner, sizeof(transfer->new_owner));
    buffer_write_long(certificate_transfer_buf, transfer->total_voters);
    for (int i = 0; i < transfer->total_voters; i++)
    {
        char vote_hash[SHA256_STRING_LENGTH];
        magicnet_council_certificate_transfer_vote_hash(&transfer->voters[i], vote_hash);
        buffer_write_bytes(certificate_transfer_buf, vote_hash, sizeof(vote_hash));
    }
    sha256_data(buffer_ptr(certificate_transfer_buf), out_hash, buffer_len(certificate_transfer_buf));
    buffer_free(certificate_transfer_buf);
}

int magicnet_council_certificate_transfer_verify(struct magicnet_council_certificate *council_cert)
{
    int res = 0;
    
    struct council_certificate_transfer* transfer = &council_cert->signed_data.transfer;
    if (council_cert->signed_data.flags & MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS && transfer->certificate)
    {
        // This is marked as a genesis certificate but has a previous certificate
        magicnet_log("%s council certificate transfer verification failed for hash %s, genesis certificate cannot have a previous certificate\n", __FUNCTION__, council_cert->hash);
        res = -1;
        goto out;
    }

    // Now we check to see if the genesis flag is not set but we have no certificate
    if (!(council_cert->signed_data.flags & MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS) && !transfer->certificate)
    {
        magicnet_log("%s council certificate transfer verification failed for hash %s, non genesis certificate must have a previous certificate\n", __FUNCTION__, council_cert->hash);
        res = -1;
        goto out;
    }

    // No previous transfer certificate? Then we should check with the council to see if this is a genesis certificate
    if (!transfer->certificate)
    {
        // We need to check with the council to see if this is a genesis certificate
        if (!magicnet_council_is_genesis_certificate(council_cert->council, council_cert))
        {
            magicnet_log("%s council certificate transfer verification failed for hash %s, certificate is not a genesis certificate\n", __FUNCTION__, council_cert->hash);
            res = -1;
            goto out;
        }
    }

    // Verify the previous certificate is valid
    if (transfer->certificate)
    {
        res = magicnet_council_certificate_verify(transfer->certificate);
        if (res < 0)
        {
            magicnet_log("%s council certificate transfer verification failed for hash %s, certificate is invalid\n", __FUNCTION__, transfer->certificate->hash);
            goto out;
        }

        // Additionally we need to ensure the certificate belongs to the same council as ourselves and has the same local id
        // to prove a transfer did take place
        if (strncmp(transfer->certificate->signed_data.council_id_hash, council_cert->signed_data.council_id_hash, sizeof(transfer->certificate->signed_data.council_id_hash)) != 0)
        {
            magicnet_log("%s council certificate transfer verification failed for hash %s, certificate is not for the same council\n", __FUNCTION__, transfer->certificate->hash);
            res = -1;
            goto out;
        }

        if (transfer->certificate->signed_data.id != council_cert->signed_data.id)
        {
            magicnet_log("%s council certificate transfer verification failed for hash %s, certificate is not for the previous certificate\n", __FUNCTION__, transfer->certificate->hash);
            res = -1;
            goto out;
        }
    }


    for (size_t i = 0; i < transfer->total_voters; i++)
    {
        res = magicnet_council_certificate_transfer_vote_verify(council_cert, &transfer->voters[i]);
        if (res < 0)
        {
            magicnet_log("%s council certificate transfer verification failed for hash %s, vote is invalid\n", __FUNCTION__, transfer->certificate->hash);
            goto out;
        }
    }

out:

    return res;
}
void magicnet_council_certificate_hash(struct magicnet_council_certificate *certificate, char *out_hash)
{
    char transfer_hash[SHA256_STRING_LENGTH] = {0};
    struct buffer *certificate_signed_data_buf = buffer_create();
    buffer_write_int(certificate_signed_data_buf, certificate->signed_data.id);
    buffer_write_int(certificate_signed_data_buf, certificate->signed_data.flags);
    buffer_write_bytes(certificate_signed_data_buf, certificate->signed_data.council_id_hash, sizeof(certificate->signed_data.council_id_hash));
    buffer_write_long(certificate_signed_data_buf, certificate->signed_data.expires_at);
    buffer_write_long(certificate_signed_data_buf, certificate->signed_data.valid_from);

    magicnet_council_certificate_transfer_hash(&certificate->signed_data.transfer, transfer_hash);
    buffer_write_bytes(certificate_signed_data_buf, transfer_hash, sizeof(transfer_hash));

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

int magicnet_council_certificate_verify(struct magicnet_council_certificate *certificate)
{
    int res = 0;
    if (certificate->memory_flags & MAGICNET_COUNCIL_CERTIFICATE_MEMORY_FLAG_VERIFIED)
    {
        // We have already verified this certificate, so we can skip the verification process
        goto out;
    }

    struct magicnet_council* council = certificate->council;
    if (!council)
    {
        // Council is not loaded? Let's try to load the council, theres a chance it might not exist yet
        // if that is the case it may be a bit difficult ot verify the council at this stage
        magicnet_council_load(certificate->signed_data.council_id_hash, &certificate->council);
        council = certificate->council;
    }

    
    // Check the certificate is expiry and valid from dates are valid.
    if (certificate->signed_data.expires_at < certificate->signed_data.valid_from)
    {
        magicnet_log("%s council certificate with hash %s is invalid or corrupted, certificate has expiry that is before the valid from datetime.\n", __FUNCTION__, certificate->hash);
        res = -1;
        goto out;
    }
    
    if (council)
    {
        // Check the certificate is for this council
        if (strncmp(certificate->signed_data.council_id_hash, council->signed_data.id_hash, sizeof(certificate->signed_data.council_id_hash)) != 0)
        {
            magicnet_log("%s council certificate with hash %s is invalid or corrupted, certificate is not for this council.\n", __FUNCTION__, certificate->hash);
            res = -1;
            goto out;
        }
    }

    
    res = magicnet_council_certificate_transfer_verify(certificate);
    if (res < 0)
    {
        magicnet_log("%s council certificate with hash %s is invalid or corrupted, certificate transfer is invalid.\n", __FUNCTION__, certificate->hash);
        goto out;
    }
    
    res = magicnet_council_certificate_verify_signature(certificate);
    if (res < 0)
    {
        goto out;
    }

    certificate->memory_flags |= MAGICNET_COUNCIL_CERTIFICATE_MEMORY_FLAG_VERIFIED;

out:
    return res;
}

int magicnet_council_certificates_verify(struct magicnet_council *council)
{
    int res = 0;
    for (int i = 0; i < council->signed_data.id_signed_data.total_certificates; i++)
    {
        res = magicnet_council_certificate_verify(&council->signed_data.certificates[i]);
        if (res < 0)
        {
            goto out;
        }
    }

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


void magicnet_council_hash(struct magicnet_council *council, char *out_hash)
{
    char id_hash[SHA256_STRING_LENGTH] = {0};
    struct magicnet_council_signed_data *signed_data = &council->signed_data;

    struct buffer *council_hash_buf = buffer_create();
    magicnet_council_id_hash(council, id_hash);

    buffer_write_bytes(council_hash_buf, id_hash, sizeof(id_hash));
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

int magicnet_council_verify(struct magicnet_council *council)
{
    int res = 0;
    if (council->memory_flags & MAGICNET_COUNCIL_MEMORY_FLAG_COUNCIL_WAS_VERIFIED)
    {
        // We have already verified this council, so we can skip the verification process
        goto out;
    }

    res = magicnet_council_certificates_verify(council);
    if (res < 0)
    {
        goto out;
    }

    council->memory_flags |= MAGICNET_COUNCIL_MEMORY_FLAG_COUNCIL_WAS_VERIFIED;
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
    res = magicnet_council_certificate_sign_and_take_ownership(certificate_out);
    if (res < 0)
    {
        goto out;
    }

    certificate_out->council = council;
out:
    return res;
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
