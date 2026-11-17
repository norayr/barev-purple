/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "identity.h"
#include "identity-store.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

static void wipe(void *bytes, size_t length)
{
    volatile unsigned char *p = bytes;
    while (length--) *p++ = 0;
}

void barev_identity_clear(BarevIdentity *identity)
{
    if (identity) wipe(identity, sizeof(*identity));
}

static void encode(const unsigned char bytes[32], char text[65])
{
    static const char digits[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < 32; ++i) { text[i*2] = digits[bytes[i] >> 4]; text[i*2+1] = digits[bytes[i] & 15]; }
    text[64] = 0;
}

static gboolean valid_identifier(const char *text)
{
    unsigned i;
    if (!text || strlen(text) != 64) return FALSE;
    for (i = 0; i < 64; ++i)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return FALSE;
    return TRUE;
}

static gboolean public_key(const unsigned char seed[32], unsigned char output[32])
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    size_t length = 32;
    gboolean okay = key && EVP_PKEY_get_raw_public_key(key, output, &length) == 1 && length == 32;
    EVP_PKEY_free(key);
    return okay;
}

static gboolean sha256(const void *data, size_t size, unsigned char output[32])
{
    unsigned length = 0;
    return EVP_Digest(data, size, output, &length, EVP_sha256(), NULL) == 1 && length == 32;
}

gboolean barev_identity_identifier(const BarevIdentity *identity, char output[65])
{
    if (!identity || !identity->active || !output) return FALSE;
    encode(identity->public_key, output); return TRUE;
}

gboolean barev_identity_fingerprint(const BarevIdentity *identity, char output[72])
{
    unsigned char digest[32];
    if (!identity || !identity->active || !output || !sha256(identity->public_key, 32, digest)) return FALSE;
    memcpy(output, "SHA256:", 7); encode(digest, output+7); return TRUE;
}

static int acquire(int handle, const char *name, const char *expected, BarevIdentity *identity,
    unsigned char record[72])
{
    unsigned char link[40], derived[32];
    char identifier[65], computed[65];
    unsigned difference = 0, i;
    int result = BarevIdentityFile_Read(handle, 1, name, link, 40);
    if (result < 0) return BAREV_IDENTITY_STORAGE;
    if (result == 0) {
        if (memcmp(link, "BAREVAC1", 8)) return BAREV_IDENTITY_RECORD;
        encode(link+8, identifier);
        if (*expected && strcmp(expected, identifier)) return BAREV_IDENTITY_MISMATCH;
    } else if (*expected) memcpy(identifier, expected, 65);
    else identifier[0] = 0;
    if (!*identifier) {
        if (RAND_priv_bytes(identity->seed, 32) != 1 || !public_key(identity->seed, identity->public_key))
            return BAREV_IDENTITY_ENTROPY;
        encode(identity->public_key, identifier);
        memcpy(record, "BAREVID1", 8); memcpy(record+8, identity->seed, 32);
        memcpy(record+40, identity->public_key, 32);
        if (BarevIdentityFile_Install(handle, 0, identifier, record, 72)) return BAREV_IDENTITY_STORAGE;
    } else {
        if (BarevIdentityFile_Read(handle, 0, identifier, record, 72)) return BAREV_IDENTITY_STORAGE;
        if (memcmp(record, "BAREVID1", 8)) return BAREV_IDENTITY_RECORD;
        memcpy(identity->seed, record+8, 32); memcpy(identity->public_key, record+40, 32);
        if (!public_key(identity->seed, derived)) return BAREV_IDENTITY_RECORD;
        for (i = 0; i < 32; ++i) difference |= derived[i] ^ identity->public_key[i];
        if (difference) return BAREV_IDENTITY_RECORD;
        encode(identity->public_key, computed);
        if (strcmp(computed, identifier)) return BAREV_IDENTITY_RECORD;
    }
    if (result == 1) {
        memcpy(link, "BAREVAC1", 8); memcpy(link+8, identity->public_key, 32);
        if (BarevIdentityFile_Install(handle, 1, name, link, 40)) return BAREV_IDENTITY_STORAGE;
    }
    identity->active = TRUE; return BAREV_IDENTITY_OK;
}

int barev_identity_open(const char *profile, const char *account, const char *expected, BarevIdentity *identity)
{
    static const char prefix[] = "Barev account v1\n";
    unsigned char input[273], digest[32], record[72];
    char name[65];
    size_t length;
    int handle, result;
    if (!identity) return BAREV_IDENTITY_RECORD;
    barev_identity_clear(identity);
    if (!expected || (*expected && !valid_identifier(expected))) return BAREV_IDENTITY_IDENTIFIER;
    if (!account || !(length = strlen(account)) || length > 256) return BAREV_IDENTITY_ACCOUNT;
    memcpy(input, prefix, sizeof(prefix)-1); memcpy(input+sizeof(prefix)-1, account, length);
    if (!sha256(input, length+sizeof(prefix)-1, digest)) return BAREV_IDENTITY_RECORD;
    encode(digest, name);
    handle = BarevIdentityFile_Open(profile);
    if (handle == -2) return BAREV_IDENTITY_UNSUPPORTED;
    if (handle < 0) return BAREV_IDENTITY_STORAGE;
    result = acquire(handle, name, expected, identity, record);
    BarevIdentityFile_Close(handle); wipe(record, sizeof(record));
    if (result) barev_identity_clear(identity);
    return result;
}
