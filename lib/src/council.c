

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
    struct vector *vector;
    pthread_mutex_t lock;
} loaded_council;

void magicnet_council_certificate_free(struct magicnet_council_certificate *certificate);
void magicnet_council_certificate_free_data(struct magicnet_council_certificate *certificate);
int magicnet_council_stream_write_certificate_transfer(struct buffer *buffer_out, struct council_certificate_transfer *transfer);
struct magicnet_council_certificate* magicnet_council_certificate_create();

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
    loaded_council.vector = vector_create(sizeof(struct magicnet_council *));
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
    int res = 0;
    pthread_mutex_lock(&loaded_council.lock);
    vector_set_peek_pointer(loaded_council.vector, 0);
    struct magicnet_council *council = vector_peek_ptr(loaded_council.vector);
    while (council)
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

int magicnet_council_vector_add_no_locks(struct magicnet_council *council)
{
    int res = 0;
    vector_push(loaded_council.vector, &council);
    return res;
}

int magicnet_council_vector_add(struct magicnet_council *council)
{
    int res = 0;
    pthread_mutex_lock(&loaded_council.lock);
    res = magicnet_council_vector_add_no_locks(council);
    pthread_mutex_unlock(&loaded_council.lock);

    return res;
}
int magicnet_council_stream_write_certificate_vote_signed_data(struct buffer *buffer_out, struct council_certificate_transfer_vote_signed_data *signed_data)
{
    int res = 0;

    res = buffer_write_bytes(buffer_out, signed_data->certificate_to_transfer_hash, sizeof(signed_data->certificate_to_transfer_hash));
    if (res < 0)
        return res;

    res = buffer_write_long(buffer_out, signed_data->total_voters);
    if (res < 0)
        return res;

    res = buffer_write_long(buffer_out, signed_data->total_for_vote);
    if (res < 0)
        return res;

    res = buffer_write_long(buffer_out, signed_data->total_against_vote);
    if (res < 0)
        return res;

    res = buffer_write_long(buffer_out, signed_data->certificate_expires_at);
    if (res < 0)
        return res;

    res = buffer_write_long(buffer_out, signed_data->certificate_valid_from);
    if (res < 0)
        return res;

    res = buffer_write_bytes(buffer_out, &signed_data->new_owner_key, sizeof(signed_data->new_owner_key));
    if (res < 0)
        return res;

    res = buffer_write_bytes(buffer_out, &signed_data->winning_key, sizeof(signed_data->winning_key));
    if (res < 0)
        return res;

    return res;
}

int magicnet_council_stream_write_certificate_vote(struct buffer *buffer_out, struct council_certificate_transfer_vote *vote)
{
    int res = 0;

    res = magicnet_council_stream_write_certificate_vote_signed_data(buffer_out, &vote->signed_data);
    if (res < 0)
        return res;

    res = buffer_write_bytes(buffer_out, vote->hash, sizeof(vote->hash));
    if (res < 0)
        return res;

    res = buffer_write_bytes(buffer_out, &vote->signature, sizeof(vote->signature));
    if (res < 0)
        return res;

    res = magicnet_council_stream_write_certificate(buffer_out, vote->voter_certificate);
    if (res < 0)
        return res;

    return res;
}

int magicnet_council_stream_write_certificate_signed_data(struct buffer *buffer_out, struct council_certificate_signed_data *signed_data)
{
    int res = 0;

    // Write the ID
    res = buffer_write_int(buffer_out, signed_data->id);
    if (res < 0)
        return res;

    // Write the flags
    res = buffer_write_int(buffer_out, signed_data->flags);
    if (res < 0)
        return res;

    // Write the council ID hash
    res = buffer_write_bytes(buffer_out, signed_data->council_id_hash, sizeof(signed_data->council_id_hash));
    if (res < 0)
        return res;

    // Write the expiration timestamp
    res = buffer_write_long(buffer_out, signed_data->expires_at);
    if (res < 0)
        return res;

    // Write the valid from timestamp
    res = buffer_write_long(buffer_out, signed_data->valid_from);
    if (res < 0)
        return res;

    // Write the transfer data
    res = magicnet_council_stream_write_certificate_transfer(buffer_out, &signed_data->transfer);
    if (res < 0)
        return res;

    return res;
}
int magicnet_council_stream_write_certificate_transfer(struct buffer *buffer_out, struct council_certificate_transfer *transfer)
{
    int res = 0;

    // Write byte to determine if we have certificate or not
    res = buffer_write_int(buffer_out, transfer->certificate != NULL);
    if (res < 0)
        return res;

    // If we have certificate write it.
    if (transfer->certificate)
    {
        // Write the nested council certificate
        res = magicnet_council_stream_write_certificate(buffer_out, transfer->certificate);
        if (res < 0)
            return res;
    }

    // Write the new owner data
    res = buffer_write_bytes(buffer_out, &transfer->new_owner, sizeof(transfer->new_owner));
    if (res < 0)
        return res;

    // Write the total number of voters
    res = buffer_write_long(buffer_out, transfer->total_voters);
    if (res < 0)
        return res;

    // Loop through and send all the votes
    for (int i = 0; i < transfer->total_voters; i++)
    {
        res = magicnet_council_stream_write_certificate_vote(buffer_out, &transfer->voters[i]);
        if (res < 0)
            return res;
    }

    return res;
}

int magicnet_council_stream_write_certificate(struct buffer *buffer_out, struct magicnet_council_certificate *certificate)
{
    int res = 0;

    // Write the hash of the council certificate
    res = buffer_write_bytes(buffer_out, certificate->hash, sizeof(certificate->hash));
    if (res < 0)
        return res;

    // Write the owner key
    res = buffer_write_bytes(buffer_out, &certificate->owner_key, sizeof(certificate->owner_key));
    if (res < 0)
        return res;

    // Write the signature
    res = buffer_write_bytes(buffer_out, &certificate->signature, sizeof(certificate->signature));
    if (res < 0)
        return res;

    // Write the certificate signed data
    res = magicnet_council_stream_write_certificate_signed_data(buffer_out, &certificate->signed_data);
    if (res < 0)
        return res;

    return res;
}

int magicnet_council_stream_read_certificate_vote_signed_data(struct buffer *buffer_in, struct council_certificate_transfer_vote_signed_data *signed_data)
{
    int res = 0;

    res = buffer_read_bytes(buffer_in, signed_data->certificate_to_transfer_hash, sizeof(signed_data->certificate_to_transfer_hash));
    if (res < 0)
        return res;

    res = buffer_read_long(buffer_in, &signed_data->total_voters);
    if (res < 0)
        return res;

    res = buffer_read_long(buffer_in, &signed_data->total_for_vote);
    if (res < 0)
        return res;

    res = buffer_read_long(buffer_in, &signed_data->total_against_vote);
    if (res < 0)
        return res;

    res = buffer_read_long(buffer_in, &signed_data->certificate_expires_at);
    if (res < 0)
        return res;

    res = buffer_read_long(buffer_in, &signed_data->certificate_valid_from);
    if (res < 0)
        return res;

    res = buffer_read_bytes(buffer_in, &signed_data->new_owner_key, sizeof(signed_data->new_owner_key));
    if (res < 0)
        return res;

    res = buffer_read_bytes(buffer_in, &signed_data->winning_key, sizeof(signed_data->winning_key));
    if (res < 0)
        return res;

    return res;
}

int magicnet_council_stream_read_certificate_vote(struct buffer *buffer_in, struct council_certificate_transfer_vote *vote)
{
    int res = 0;

    res = magicnet_council_stream_read_certificate_vote_signed_data(buffer_in, &vote->signed_data);
    if (res < 0)
        return res;

    res = buffer_read_bytes(buffer_in, vote->hash, sizeof(vote->hash));
    if (res < 0)
        return res;

    res = buffer_read_bytes(buffer_in, &vote->signature, sizeof(vote->signature));
    if (res < 0)
        return res;

    res = magicnet_council_stream_read_certificate(buffer_in, vote->voter_certificate);
    if (res < 0)
        return res;

    return res;
}

int magicnet_council_stream_read_certificate_transfer(struct buffer *buffer_in, struct council_certificate_transfer *transfer)
{
    int res = 0;

    // Read byte to determine if we have certificate or not
    int has_certificate = 0;
    res = buffer_read_int(buffer_in, &has_certificate);
    if (res < 0)
        return res;

    // If we have certificate, read it
    if (has_certificate)
    {
        transfer->certificate = (struct magicnet_council_certificate *)malloc(sizeof(struct magicnet_council_certificate));
        if (!transfer->certificate)
            return -1; // Allocation failed

        res = magicnet_council_stream_read_certificate(buffer_in, transfer->certificate);
        if (res < 0)
            return res;
    }
    else
    {
        transfer->certificate = NULL;
    }

    // Read the new owner data
    res = buffer_read_bytes(buffer_in, &transfer->new_owner, sizeof(transfer->new_owner));
    if (res < 0)
        return res;

    // Read the total number of voters
    res = buffer_read_long(buffer_in, &transfer->total_voters);
    if (res < 0)
        return res;

    // Allocate memory for voters
    transfer->voters = (struct council_certificate_transfer_vote *)malloc(transfer->total_voters * sizeof(struct council_certificate_transfer_vote));
    if (!transfer->voters)
        return -1; // Allocation failed

    // Loop through and read all the votes
    for (int i = 0; i < transfer->total_voters; i++)
    {
        res = magicnet_council_stream_read_certificate_vote(buffer_in, &transfer->voters[i]);
        if (res < 0)
            return res;
    }

    return res;
}

int magicnet_council_stream_read_certificate_signed_data(struct buffer *buffer_in, struct council_certificate_signed_data *signed_data)
{
    int res = 0;

    // Read the ID
    res = buffer_read_int(buffer_in, &signed_data->id);
    if (res < 0)
        return res;

    // Read the flags
    res = buffer_read_int(buffer_in, &signed_data->flags);
    if (res < 0)
        return res;

    // Read the council ID hash
    res = buffer_read_bytes(buffer_in, signed_data->council_id_hash, sizeof(signed_data->council_id_hash));
    if (res < 0)
        return res;

    // Read the expiration timestamp
    res = buffer_read_long(buffer_in, &signed_data->expires_at);
    if (res < 0)
        return res;

    // Read the valid from timestamp
    res = buffer_read_long(buffer_in, &signed_data->valid_from);
    if (res < 0)
        return res;

    // Read the transfer data
    res = magicnet_council_stream_read_certificate_transfer(buffer_in, &signed_data->transfer);
    if (res < 0)
        return res;

    return res;
}

int magicnet_council_stream_read_certificate(struct buffer *buffer_in, struct magicnet_council_certificate *certificate)
{
    int res = 0;

    // Read the hash of the council certificate
    res = buffer_read_bytes(buffer_in, certificate->hash, sizeof(certificate->hash));
    if (res < 0)
        return res;

    // Read the owner key
    res = buffer_read_bytes(buffer_in, &certificate->owner_key, sizeof(certificate->owner_key));
    if (res < 0)
        return res;

    // Read the signature
    res = buffer_read_bytes(buffer_in, &certificate->signature, sizeof(certificate->signature));
    if (res < 0)
        return res;

    // Read the certificate signed data
    res = magicnet_council_stream_read_certificate_signed_data(buffer_in, &certificate->signed_data);
    if (res < 0)
        return res;

out:

    return res;
}

int magicnet_council_stream_alloc_and_read_certificate(struct buffer *buffer_in, struct magicnet_council_certificate **certificate)
{
    *certificate = magicnet_council_certificate_create();
    if (!*certificate)
        return -1; // Allocation failed
    
    return magicnet_council_stream_read_certificate(buffer_in, *certificate);
}

int magicnet_council_load(const char *council_id_hash, struct magicnet_council **council_out)
{
    int res = 0;
    pthread_mutex_lock(&loaded_council.lock);

    // Check if we already have this council loaded
    vector_set_peek_pointer(loaded_council.vector, 0);
    struct magicnet_council *council = vector_peek_ptr(loaded_council.vector);
    while (council)
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
        magicnet_log("%s failed to load council from database\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_council_verify(council);
    if (res < 0)
    {
        magicnet_log("%s council verification failed for hash %s, council is invalid\n", __FUNCTION__, council->hash);
        goto out;
    }

    // Lets add the council to the vector so it remains cached
    res = magicnet_council_vector_add_no_locks(council);
    if (res < 0)
    {
        magicnet_log("%s failed to add council to vector\n", __FUNCTION__);
        goto out;
    }

    // Load this clients default certificate for this council
    magicnet_council_default_certificate_for_key(council, MAGICNET_public_key(), &council->my_certificate);

out:
    *council_out = council;
    pthread_mutex_unlock(&loaded_council.lock);
    return res;
}

bool magicnet_council_certificate_is_mine(const char *certificate_hash)
{
    bool res = false;
    struct magicnet_council_certificate *certificate = magicnet_council_certificate_load(certificate_hash);
    if (!certificate)
    {
        res = false;
        goto out;
    }

    if (key_cmp(&certificate->owner_key, MAGICNET_public_key()))
    {
        res = true;
        goto out;
    }
out:
    return res;
}

bool magicnet_council_is_genesis_certificate(struct magicnet_council *council, struct magicnet_council_certificate *certificate)
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

    struct magicnet_council_certificate *council_cert = &council->signed_data.certificates[certificate->signed_data.id];
    if (memcmp(council_cert->hash, certificate->hash, sizeof(council_cert->hash)) == 0)
    {
        res = true;
        goto out;
    }
out:
    return res;
}

int magicnet_council_certificates_for_key(struct magicnet_council *council, struct key *key, struct vector *certificate_vec)
{
    int res = 0;
    res = magicnet_database_load_council_certificates_of_key(council->signed_data.id_hash, key, certificate_vec);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_council_my_certificate(struct magicnet_council *council, struct magicnet_council_certificate **certificate_out)
{
    int res = 0;

    // No council provided? default to the central council
    if (!council)
    {
        council = central_council;
    }

    if (council->my_certificate)
    {
        *certificate_out = magicnet_council_certificate_clone(council->my_certificate);
    }
    else
    {
        res = magicnet_council_default_certificate_for_key(council, MAGICNET_public_key(), certificate_out);
    }

out:
    return res;
}
int magicnet_council_default_certificate_for_key(struct magicnet_council *council, struct key *key, struct magicnet_council_certificate **certificate_out)
{
    int res = 0;
    *certificate_out = NULL;
    if (!council)
    {
        council = central_council;
    }

    struct vector *certificate_vec = vector_create(sizeof(struct magicnet_council_certificate));
    if (!certificate_vec)
    {
        res = -1;
        goto out;
    }

    res = magicnet_council_certificates_for_key(council, key, certificate_vec);
    if (res < 0)
    {
        goto out;
    }

    if (vector_count(certificate_vec) == 0)
    {
        res = -1;
        goto out;
    }

    *certificate_out = vector_peek_ptr(certificate_vec);
out:
    // Free every certificate except the one we plucked
    struct magicnet_council_certificate *cert = vector_peek_ptr(certificate_vec);
    while (cert)
    {
        if (cert != *certificate_out)
        {
            magicnet_council_certificate_free(cert);
        }
        cert = vector_peek_ptr(certificate_vec);
    }

    vector_free(certificate_vec);
    return res;
}

int magicnet_council_create_master()
{
    int res = 0;
    time_t council_creation_time = time(NULL);
    // Obviously we want to load the council from the database
    // we are simulating many actions here as we continue to build on the council funtionality
    central_council = magicnet_council_create(MAGICNET_MASTER_COUNCIL_NAME, MAGICNET_MASTER_COUNCIL_TOTAL_CERTIFICATES, council_creation_time);
    if (!central_council)
    {
        res = -1;
        goto out;
    }

    res = magicnet_council_save(central_council);
    if (res < 0)
    {
        goto out;
    }

    struct magicnet_council_certificate *new_certificate = NULL;
    res = magicnet_council_certificate_self_transfer(&central_council->signed_data.certificates[0], &new_certificate, MAGICNET_public_key(), council_creation_time, council_creation_time + (86400 * 65));
    if (res < 0)
    {
        magicnet_log("%s failed to self transfer certificate\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_council_certificate_self_transfer_claim(new_certificate);
    if (res < 0)
    {
        magicnet_log("%s failed to self transfer claim certificate\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_council_certificate_save(new_certificate);
    if (res < 0)
    {
        magicnet_log("%s failed to save certificate\n", __FUNCTION__);
        goto out;
    }

    res = magicnet_setting_set(MAGICNET_MASTER_COUNCIL_NAME, central_council->signed_data.id_hash);
    if (res < 0)
    {
        magicnet_log("%s failed to save master council hash\n", __FUNCTION__);
        goto out;
    }

out:
    return res;
}

/**
 * Gets a council certificate and writes it into the output
 */
int magicnet_council_reqres_handler(struct request_and_respond_input_data *input_data, struct request_and_respond_output_data **output_data_out)
{
    int res = 0;
    struct request_and_respond_output_data *output_data = NULL;
    struct buffer *buffer_out = buffer_create();
    if (!buffer_out)
    {
        res = -1;
        goto out;
    }

    struct magicnet_council_certificate *certificate = magicnet_council_certificate_load(input_data->input);
    if (!certificate)
    {
        res = -1;
        goto out;
    }

    res = magicnet_council_stream_write_certificate(buffer_out, certificate);
    if (res < 0)
    {
        goto out;
    }

    output_data = magicnet_reqres_output_data_create(buffer_ptr(buffer_out), buffer_len(buffer_out));
    if (!output_data)
    {
        res = -1;
        goto out;
    }

out:
    if (buffer_out)
    {
        buffer_free(buffer_out);
    }

    if (certificate)
    {
        magicnet_council_certificate_free(certificate);
    }

    *output_data_out = output_data;
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

    // We should register the request response handler to allow local clients to request council certificates
    // from the local server instance.
    reqres_register_handler(magicnet_council_reqres_handler, MAGICNET_REQRES_HANDLER_GET_COUNCIL_CERTIFICATE);

    if (magicnet_setting_exists(MAGICNET_MASTER_COUNCIL_NAME))
    {
        // We have a master council, lets load it
        char council_hash[MAGICNET_MAX_SETTING_VALUE_SIZE] = {0};
        res = magicnet_setting_get(MAGICNET_MASTER_COUNCIL_NAME, council_hash);
        if (res < 0)
        {
            goto out;
        }

        res = magicnet_council_load(council_hash, &central_council);
        if (res < 0)
        {
            goto out;
        }
    }
    else
    {
        // We need to create the master council
        res = magicnet_council_create_master();
        if (res < 0)
        {
            goto out;
        }

        // Setup my default certificate on the council
        magicnet_council_default_certificate_for_key(central_council, MAGICNET_public_key(), &central_council->my_certificate);
    }

out:
    return res;
}

void magicnet_council_free(struct magicnet_council *council)
{
    // Implement free funtionaliuty...
    // Free the council certificate
    if (council->my_certificate)
    {
        magicnet_council_certificate_free(council->my_certificate);
        council->my_certificate = NULL;
    }

    free(council);
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

int magicnet_council_certificate_save(struct magicnet_council_certificate *certificate)
{
    int res = 0;
    res = magicnet_council_certificate_verify(certificate, 0);
    if (res < 0)
    {
        magicnet_log("%s council certificate verification failed for hash %s, certificate is invalid\n", __FUNCTION__, certificate->hash);
        goto out;
    }

    // Check if the certificate already exists
    if (magicnet_council_certificate_exists(certificate->hash))
    {
        magicnet_log("%s council certificate with hash %s already exists\n", __FUNCTION__, certificate->hash);
        res = -1;
        goto out;
    }

    res = magicnet_database_write_certificate(certificate);
    if (res < 0)
    {
        magicnet_log("%s council certificate verification failed for hash %s, certificate is invalid\n", __FUNCTION__, certificate->hash);
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


void magincet_council_certificate_vote_free_data(struct council_certificate_transfer_vote *certificate_vote)
{
    if (!certificate_vote || !certificate_vote->voter_certificate)
    {
        return;
    }
    magicnet_council_certificate_free(certificate_vote->voter_certificate);
}

void magicnet_council_certificate_transfer_free_data(struct council_certificate_transfer *certificate_transfer)
{
    if (!certificate_transfer)
    {
        return;
    }

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

bool magicnet_council_certificate_exists(const char *certificate_hash)
{
    // TODO: Update this method to check the database for the certificate rather than loading it
    bool res = false;
    struct magicnet_council_certificate *certificate = magicnet_council_certificate_load(certificate_hash);
    if (certificate)
    {
        res = true;
        magicnet_council_certificate_free(certificate);
    }
    return res;
}

struct magicnet_council_certificate *magicnet_council_certificate_load(const char *certificate_hash)
{
    struct magicnet_council_certificate *certificate = magicnet_council_certificate_create();
    if (!certificate)
    {
        return NULL;
    }

    int res = magicnet_database_load_certificate(certificate, certificate_hash);
    if (res < 0)
    {
        free(certificate);
        return NULL;
    }

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

/**
 * Second pass ensures the voter signed the correct total against and for votes
 */
int magicnet_council_certificate_transfer_vote_verify_second_pass(struct magicnet_council_certificate *certificate, struct council_certificate_transfer_vote *vote, size_t total_for_votes_out, size_t total_against_votes_out)
{
    int res = 0;

    if (total_for_votes_out != vote->signed_data.total_for_vote)
    {
        res = -1;
        goto out;
    }

    if (total_against_votes_out != vote->signed_data.total_against_vote)
    {
        res = -1;
        goto out;
    }

out:
    return res;
}

int magicnet_council_certificate_transfer_vote_verify(struct magicnet_council_certificate *certificate, struct council_certificate_transfer_vote *vote, size_t *total_for_votes_out, size_t *total_against_votes_out)
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

    if (certificate->signed_data.expires_at != vote->signed_data.certificate_expires_at || certificate->signed_data.valid_from != vote->signed_data.certificate_valid_from)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, certificate expiry or valid from does not match the transfer\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    // Next we need to verify that the vote was made at the time the voting certificate was valid. I.e we cant vote for certificates whose valid_from exceed our own expiry and existed before we did
    if (vote->signed_data.certificate_valid_from > vote->voter_certificate->signed_data.expires_at || vote->signed_data.certificate_valid_from < vote->voter_certificate->signed_data.valid_from)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, you cannot vote for a valid from that exceeds your certificate expiration or whose certificate existed before you\n", __FUNCTION__, hash);
        res = -1;
        goto out;
    }

    // We must ensure that the certificate to transfer hash matches the previous certificate
    if (strncmp(vote->signed_data.certificate_to_transfer_hash, certificate->signed_data.transfer.certificate->hash, sizeof(vote->signed_data.certificate_to_transfer_hash)) != 0)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, certificate to transfer hash does not match the transfer\n", __FUNCTION__, hash);
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
    res = magicnet_council_certificate_verify(vote->voter_certificate, 0);
    if (res < 0)
    {
        magicnet_log("%s council certificate transfer vote verification failed for hash %s, voting certificate is invalid\n", __FUNCTION__, hash);
        goto out;
    }

    // Did this person vote for or against the transfer?
    if (key_cmp(&vote->signed_data.new_owner_key, &certificate->owner_key))
    {
        // It seems they voted for this key
        *total_for_votes_out += 1;
    }
    else
    {
        // They voted against this key
        *total_against_votes_out += 1;
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

    struct council_certificate_transfer *transfer = &council_cert->signed_data.transfer;
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

    if (!key_cmp(&council_cert->signed_data.transfer.new_owner, &council_cert->owner_key))
    {
        magicnet_log("%s council certificate transfer verification failed for hash %s, new owner does not match the transfer\n", __FUNCTION__, council_cert->hash);
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
        res = magicnet_council_certificate_verify(transfer->certificate, 0);
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

    size_t total_found_for_votes = 0;
    size_t total_found_against_votes = 0;
    for (size_t i = 0; i < transfer->total_voters; i++)
    {
        res = magicnet_council_certificate_transfer_vote_verify(council_cert, &transfer->voters[i], &total_found_for_votes, &total_found_against_votes);
        if (res < 0)
        {
            magicnet_log("%s council certificate transfer verification failed for hash %s, vote is invalid\n", __FUNCTION__, transfer->certificate->hash);
            goto out;
        }
    }

    // Second pass with new information we obtained.
    for (size_t i = 0; i < transfer->total_voters; i++)
    {
        res = magicnet_council_certificate_transfer_vote_verify_second_pass(council_cert, &transfer->voters[i], total_found_for_votes, total_found_against_votes);
        if (res < 0)
        {
            magicnet_log("%s council certificate transfer verification failed for hash %s, vote is invalid\n", __FUNCTION__, transfer->certificate->hash);
            goto out;
        }
    }

    if (total_found_for_votes != transfer->total_voters || total_found_for_votes < total_found_against_votes)
    {
        magicnet_log("%s The owner of this certificate appears to be a fraud. cert_hash=%s\n", __FUNCTION__, transfer->certificate->hash);
        res = -1;
        goto out;
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

int magicnet_council_certificate_verify_for_council(struct magicnet_council *council, struct magicnet_council_certificate *certificate)
{

    if (strncmp(certificate->signed_data.council_id_hash, council->signed_data.id_hash, sizeof(certificate->signed_data.council_id_hash)) != 0)
    {
        magicnet_log("%s council certificate with hash %s, certificate is not for this council.\n", __FUNCTION__, certificate->hash);
        return -1;
    }

    return magicnet_council_certificate_verify(certificate, 0);
}

int magicnet_central_council_certificate_verify(struct magicnet_council_certificate *certificate)
{
    return magicnet_council_certificate_verify_for_council(central_council, certificate);
}

int magicnet_council_certificate_verify(struct magicnet_council_certificate *certificate, int flags)
{
    int res = 0;
    if (certificate->memory_flags & MAGICNET_COUNCIL_CERTIFICATE_MEMORY_FLAG_VERIFIED)
    {
        // We have already verified this certificate, so we can skip the verification process
        goto out;
    }

    struct magicnet_council *council = certificate->council;
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

    // If the ignore signature verification flag isnt set then we must
    // verify the signature.
    if (!(flags & MAGICNET_COUNCIL_CERTIFICATE_VERIFY_FLAG_IGNORE_FINAL_SIGNATURE))
    {
        res = magicnet_council_certificate_verify_signature(certificate);
        if (res < 0)
        {
            goto out;
        }
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
        res = magicnet_council_certificate_verify(&council->signed_data.certificates[i], 0);
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

void magicnet_council_certificate_transfer_votes_clone(struct magicnet_council_certificate *certificate_in, struct magicnet_council_certificate *certificate_out)
{
    certificate_out->signed_data.transfer.total_voters = certificate_in->signed_data.transfer.total_voters;
    certificate_out->signed_data.transfer.voters = calloc(certificate_out->signed_data.transfer.total_voters, sizeof(struct council_certificate_transfer_vote));
    for (size_t i = 0; i < certificate_out->signed_data.transfer.total_voters; i++)
    {
        certificate_out->signed_data.transfer.voters[i] = certificate_in->signed_data.transfer.voters[i];
        certificate_out->signed_data.transfer.voters[i].voter_certificate = magicnet_council_certificate_clone(certificate_in->signed_data.transfer.voters[i].voter_certificate);
    }
}
void magicnet_council_certificate_clone_signed_data(struct magicnet_council_certificate *certificate_in, struct magicnet_council_certificate *certificate_out)
{
    if (certificate_in->signed_data.transfer.certificate)
    {
        certificate_out->signed_data.transfer.certificate = magicnet_council_certificate_clone(certificate_in->signed_data.transfer.certificate);
    }
    magicnet_council_certificate_transfer_votes_clone(certificate_in, certificate_out);
}

struct magicnet_council_certificate* magicnet_council_certificate_create()
{
    return magicnet_council_certificate_create_many(1);
}

struct magicnet_council_certificate *magicnet_council_certificate_clone(struct magicnet_council_certificate *certificate)
{
    struct magicnet_council_certificate *certificate_out = magicnet_council_certificate_create();

    if (!certificate_out)
    {
        goto out;
    }

    memcpy(certificate_out, certificate, sizeof(struct magicnet_council_certificate));
    magicnet_council_certificate_clone_signed_data(certificate, certificate_out);

    // Verify the integrety of what we have copied
    int res = magicnet_council_certificate_verify_signature(certificate_out);
    if (res < 0)
    {
        magicnet_log("%s We had an issue copying the council certificate correctly or the input certificate was invalid\n", __FUNCTION__);
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
    certificate_out->signed_data.transfer.new_owner = *MAGICNET_public_key();

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

int magicnet_council_certificate_build_transfer_vote(struct magicnet_council_certificate *voting_certificate, struct magicnet_council_certificate *original_certificate, struct magicnet_council_certificate *new_certificate, struct key *vote_for_key, struct key *winning_key, int index, time_t valid_from, time_t valid_to)
{
    int res = 0;

    if (!key_cmp(&voting_certificate->owner_key, MAGICNET_public_key()))
    {
        magicnet_log("%s voting certificate is not the same as the logged in private key. How can we sign something with that certificate when we dont have the private keys? Use the voting certificate of the logged in key", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (new_certificate->signed_data.transfer.total_voters <= index)
    {
        res = -1;
        goto out;
    }

    struct council_certificate_transfer_vote *vote = &new_certificate->signed_data.transfer.voters[0];
    strncpy(vote->signed_data.certificate_to_transfer_hash, original_certificate->hash, sizeof(vote->signed_data.certificate_to_transfer_hash));
    vote->signed_data.total_voters = 1;
    vote->signed_data.total_for_vote = 1;
    vote->signed_data.total_against_vote = 0;
    vote->signed_data.certificate_expires_at = valid_to;
    vote->signed_data.certificate_valid_from = valid_from;
    vote->signed_data.new_owner_key = *vote_for_key;
    if (winning_key)
    {
        vote->signed_data.winning_key = *winning_key;
    }

    // Clones neccessary as the certificates get freed.
    vote->voter_certificate = magicnet_council_certificate_clone(voting_certificate);

    // Hash and sign with currently logged in private key
    magicnet_council_certificate_transfer_vote_hash(vote, vote->hash);
    res = private_sign(vote->hash, sizeof(vote->hash), &vote->signature);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}

int magicnet_council_certificate_self_transfer_claim(struct magicnet_council_certificate *certificate_to_claim)
{
    int res = 0;

    if (!key_cmp(MAGICNET_public_key(), &certificate_to_claim->owner_key))
    {
        magicnet_log("%s certificate to claim is not owned by the logged in key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // All we need to do now is sign the certificate and its claimed
    res = magicnet_council_certificate_sign_and_take_ownership(certificate_to_claim);
    if (res < 0)
    {
        goto out;
    }

    // Lets verify everything went okay
    res = magicnet_council_certificate_verify(certificate_to_claim, 0);
    if (res < 0)
    {
        goto out;
    }

out:
    return res;
}
int magicnet_council_certificate_self_transfer(struct magicnet_council_certificate *certificate, struct magicnet_council_certificate **new_certificate_out, struct key *new_owner, time_t valid_from, time_t valid_to)
{
    int res = 0;
    if (!(certificate->signed_data.flags & MAGICNET_COUNCIL_CERTIFICATE_FLAG_TRANSFERABLE_WITHOUT_VOTE))
    {
        magicnet_log("%s this certificate is not transferable without a vote\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Clone the original certificate since most properties will remain present.
    struct magicnet_council_certificate *new_certificate = magicnet_council_certificate_clone(certificate);
    if (!new_certificate)
    {
        res = -1;
        goto out;
    }

    // Let's free the voting data since its the old certificate voting data
    magicnet_council_certificate_transfer_free_data(&new_certificate->signed_data.transfer);

    // Lets now clear the transfer structure
    memset(&new_certificate->signed_data.transfer, 0, sizeof(new_certificate->signed_data.transfer));

    // Next we need to setup the voting data there will be one vote, which will be the owner of the certificate
    new_certificate->signed_data.transfer.total_voters = 1;
    new_certificate->signed_data.transfer.voters = calloc(1, sizeof(struct council_certificate_transfer_vote));
    if (!new_certificate->signed_data.transfer.voters)
    {
        res = -1;
        goto out;
    }

    // Change valid from and expiry all the rest is same as the certificate we are transfeering.
    new_certificate->signed_data.valid_from = valid_from;
    new_certificate->signed_data.expires_at = valid_to;

    // No memory flags for this buddy since this is a new certificate.
    new_certificate->memory_flags = 0;

    // We will create one transfer vote for index zero of the voters array
    // It will vote for the new owner and mark the new owner as the winner. This is valid because the certificate is self transferable.
    // Using only this vote we confirm the transfer correctly.
    res = magicnet_council_certificate_build_transfer_vote(certificate, certificate, new_certificate, new_owner, new_owner, 0, valid_from, valid_to);
    if (res < 0)
    {
        goto out;
    }

    // Great let's set the old certificate so theirs a clear transfer history, Clones neccessary as the certificates get freed.
    new_certificate->signed_data.transfer.certificate = magicnet_council_certificate_clone(certificate);

    // We will not allow infinite transfers without vote by default.. Can be overridden programmatially if required later.
    // no system wide restriction for this. Flags will remain zero no special privilage rights will be given.
    new_certificate->signed_data.flags = 0;
    new_certificate->owner_key = *new_owner;
    new_certificate->signed_data.transfer.new_owner = *new_owner;
    magicnet_council_certificate_hash(new_certificate, new_certificate->hash);

    // Now the certificate at this point needs to be signed by the receiver. Then the transfer will be completed.

out:
    if (res >= 0)
    {
        *new_certificate_out = new_certificate;
    }
    else
    {
        magicnet_council_certificate_free(new_certificate);
    }
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
    magicnet_council_build_certificate(council, 0, MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS | MAGICNET_COUNCIL_CERTIFICATE_FLAG_TRANSFERABLE_WITHOUT_VOTE, creation_time, one_year_later, &certificates[0]);

    for (size_t i = 1; i < total_certificates; i++)
    {
        // Other certificates will be expired by default requiring the council creator to send them out
        res = magicnet_council_build_certificate(council, i, MAGICNET_COUNCIL_CERITFICATE_FLAG_GENESIS | MAGICNET_COUNCIL_CERTIFICATE_FLAG_TRANSFERABLE_WITHOUT_VOTE, 0, 0, &certificates[i]);
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
