/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_IDENTITY_H
#define BAREV_IDENTITY_H
#include <glib.h>

enum {
    BAREV_IDENTITY_OK = 0, BAREV_IDENTITY_STORAGE = 1, BAREV_IDENTITY_RECORD = 2,
    BAREV_IDENTITY_ACCOUNT = 3, BAREV_IDENTITY_IDENTIFIER = 4,
    BAREV_IDENTITY_ENTROPY = 5, BAREV_IDENTITY_MISMATCH = 6,
    BAREV_IDENTITY_UNSUPPORTED = 7
};
typedef struct {
    unsigned char seed[32], public_key[32];
    gboolean active;
} BarevIdentity;

int barev_identity_open(const char *profile, const char *account, const char *expected, BarevIdentity *identity);
void barev_identity_clear(BarevIdentity *identity);
gboolean barev_identity_identifier(const BarevIdentity *identity, char output[65]);
gboolean barev_identity_fingerprint(const BarevIdentity *identity, char output[72]);
#endif
