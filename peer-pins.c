/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "peer-pins.h"
#include "address.h"
#include <openssl/evp.h>
#include <string.h>

static gboolean decode(const char *text, unsigned char bytes[32])
{
    unsigned i;
    if (!text || strlen(text) != 64) return FALSE;
    for (i = 0; i < 32; ++i) {
        int hi = g_ascii_xdigit_value(text[2*i]), lo = g_ascii_xdigit_value(text[2*i+1]);
        if (hi < 0 || lo < 0) return FALSE;
        bytes[i] = (unsigned char)(hi*16+lo);
    }
    return TRUE;
}

static void encode(const unsigned char bytes[32], char text[65])
{
    static const char digits[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < 32; ++i) { text[2*i] = digits[bytes[i] >> 4]; text[2*i+1] = digits[bytes[i] & 15]; }
    text[64] = 0;
}

static gboolean hash(const void *data, size_t size, unsigned char bytes[32])
{
    unsigned length = 0;
    return EVP_Digest(data, size, bytes, &length, EVP_sha256(), NULL) == 1 && length == 32;
}

gboolean barev_pin_describe(const char *text, char normalized[65], char fingerprint[72])
{
    unsigned char bytes[32], digest[32];
    if (!normalized || !fingerprint || !decode(text, bytes) || !hash(bytes, 32, digest)) return FALSE;
    encode(bytes, normalized); memcpy(fingerprint, "SHA256:", 7); encode(digest, fingerprint+7);
    return TRUE;
}

static char *locate(const char *profile, const char *own, const char *peer,
                    unsigned char own_bytes[32], unsigned char name[32])
{
    static const char prefix[] = "Barev peer pin v1\n";
    unsigned char input[sizeof(prefix)-1+32+384];
    char encoded[65], *canonical, *filename, *path;
    size_t length;
    if (!profile || profile[0] != '/' || strlen(profile) > 3900 || !decode(own, own_bytes) ||
        !peer || !(canonical = barev_address_identity(peer, FALSE))) return NULL;
    length = strlen(canonical);
    if (length >= 384) { g_free(canonical); return NULL; }
    memcpy(input, prefix, sizeof(prefix)-1); memcpy(input+sizeof(prefix)-1, own_bytes, 32);
    memcpy(input+sizeof(prefix)-1+32, canonical, length); g_free(canonical);
    if (!hash(input, sizeof(prefix)-1+32+length, name)) return NULL;
    encode(name, encoded); filename = g_strdup_printf("peer-%s.pin", encoded);
    path = g_build_filename(profile, "barev", filename, NULL); g_free(filename);
    return path;
}

static int read_pin(const char *path, const unsigned char own[32], const unsigned char name[32], char key[65])
{
    char *record = NULL;
    gsize length = 0;
    GError *error = NULL;
    int status;
    key[0] = 0;
    if (g_file_test(path, G_FILE_TEST_IS_SYMLINK) ||
        (g_file_test(path, G_FILE_TEST_EXISTS) && !g_file_test(path, G_FILE_TEST_IS_REGULAR))) return BAREV_PIN_STORAGE;
    if (!g_file_get_contents(path, &record, &length, &error)) {
        status = error && error->domain == G_FILE_ERROR && error->code == G_FILE_ERROR_NOENT
            ? BAREV_PIN_UNPINNED : BAREV_PIN_STORAGE;
        g_clear_error(&error); return status;
    }
    status = BAREV_PIN_INVALID;
    if (length == 104 && !memcmp(record, "BAREVPN1", 8) && !memcmp(record+8, own, 32) && !memcmp(record+40, name, 32)) {
        encode((unsigned char *)record+72, key); status = BAREV_PIN_OK;
    }
    g_free(record); return status;
}

int barev_pin_load(const char *profile, const char *own, const char *peer, char key[65], char fingerprint[72])
{
    unsigned char own_bytes[32], name[32];
    char *path;
    int status;
    key[0] = fingerprint[0] = 0;
    path = locate(profile, own, peer, own_bytes, name);
    if (!path) return BAREV_PIN_INVALID;
    status = read_pin(path, own_bytes, name, key); g_free(path);
    if (status == BAREV_PIN_OK && !barev_pin_describe(key, key, fingerprint)) return BAREV_PIN_INVALID;
    return status;
}

int barev_pin_save(const char *profile, const char *own, const char *peer, const char *expected, const char *replacement)
{
    unsigned char own_bytes[32], name[32], bytes[32], old[32], record[104];
    char current[65], wanted[65], *path;
    int status;
    if (!expected || !decode(replacement, bytes) || (*expected && !decode(expected, old))) return BAREV_PIN_INVALID;
    if (*expected) encode(old, wanted); else wanted[0] = 0;
    path = locate(profile, own, peer, own_bytes, name);
    if (!path) return BAREV_PIN_INVALID;
    status = read_pin(path, own_bytes, name, current);
    if (status != BAREV_PIN_OK && status != BAREV_PIN_UNPINNED) goto done;
    if (strcmp(current, wanted)) { status = BAREV_PIN_CHANGED; goto done; }
    encode(bytes, current);
    if (!strcmp(current, wanted)) { status = BAREV_PIN_OK; goto done; }
    memcpy(record, "BAREVPN1", 8); memcpy(record+8, own_bytes, 32);
    memcpy(record+40, name, 32); memcpy(record+72, bytes, 32);
    status = g_file_set_contents(path, (char *)record, sizeof(record), NULL) ? BAREV_PIN_OK : BAREV_PIN_STORAGE;
done:
    g_free(path); return status;
}
