/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_ADDRESS_H
#define BAREV_ADDRESS_H

#include <stddef.h>
#include <glib.h>

/* Local RFC 4648 base32 conversion, with the v6.alt interior-zero compression.
 * Encoding requires at least 40 bytes for the hostname and its terminator. */
gboolean barev_address_encode(const unsigned char ip[16], char *host, size_t size);
gboolean barev_address_decode(const char *host, unsigned char ip[16]);
/* Return a newly allocated numeric or encoded identity for a Yggdrasil peer. */
char *barev_address_identity(const char *name, gboolean encoded);

#endif
