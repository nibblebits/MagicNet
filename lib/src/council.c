

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

static struct magicnet_council* central_council = NULL;
int magicnet_council_init()
{
    int res = 0;


    return res;
}
struct magicnet_council_certificate *magicnet_council_certificate_create()
{
    return calloc(1, sizeof(struct magicnet_council_certificate));
}

void magicnet_council_certificate_hash(struct magicnet_council_certificate *certificate, char *out_hash)
{
    struct buffer *certificate_signed_data_buf = buffer_create();
    buffer_write_int(certificate_signed_data_buf, certificate->signed_data.id);
    buffer_write_bytes(certificate_signed_data_buf, certificate->signed_data.council_id_hash, sizeof(certificate->signed_data.council_id_hash));
    buffer_write_long(certificate_signed_data_buf, certificate->signed_data.expires_at);
    buffer_write_long(certificate_signed_data_buf, certificate->signed_data.valid_from);
    sha256_data(buffer_ptr(certificate_signed_data_buf), out_hash, buffer_len(certificate_signed_data_buf));
    buffer_free(certificate_signed_data_buf);
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
int magicnet_council_build_certificate(struct magicnet_council *council, int id_no, time_t valid_from, time_t expires_at, struct magicnet_council_certificate *certificate_out)
{
    int res = 0;
    strncpy(certificate_out->signed_data.council_id_hash, council->signed_data.id_hash, sizeof(certificate_out->signed_data.council_id_hash));
    certificate_out->signed_data.id = id_no;
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

void magicnet_council_hash(struct magicnet_council* council, char* out_hash)
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

int magicnet_council_sign(struct magicnet_council* council)
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
    magicnet_council_build_certificate(council, 0, creation_time, one_year_later, &certificates[0]);

    for (size_t i = 1; i < total_certificates; i++)
    {
        // Other certificates will be expires by default requiring the council creator to send them out
        res = magicnet_council_build_certificate(council, i, 0, 0, &certificates[i]);
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
