/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_TLS_H
#define BAREV_TLS_H
#include "identity.h"

typedef struct BarevTLS BarevTLS;
enum { BAREV_TLS_ERROR_BYTES = 128, BAREV_TLS_WOULD_BLOCK = -2 };

/* The connected descriptor remains owned by the caller. */
BarevTLS *barev_tls_new(const BarevIdentity *identity, const unsigned char *pin,
    size_t pin_length, int fd, gboolean server, char error[BAREV_TLS_ERROR_BYTES]);
void barev_tls_free(BarevTLS *tls);
int barev_tls_handshake(BarevTLS *tls); /* 1 authenticated, 0 pending, -1 failed */
gboolean barev_tls_authenticated(const BarevTLS *tls);
gboolean barev_tls_wants_write(const BarevTLS *tls);
gboolean barev_tls_pending(const BarevTLS *tls);
/* Copies the public DER certificate; zero means that the output did not fit. */
size_t barev_tls_certificate(const BarevTLS *tls, unsigned char *bytes, size_t capacity);
int barev_tls_read(BarevTLS *tls, void *bytes, size_t length);
/* A blocked write must be retried with the same unconsumed prefix. */
int barev_tls_write(BarevTLS *tls, const void *bytes, size_t length);
const char *barev_tls_error(const BarevTLS *tls);
#endif
