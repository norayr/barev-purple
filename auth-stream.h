/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_AUTH_STREAM_H
#define BAREV_AUTH_STREAM_H
#include <glib.h>
#include <libpurple/xmlnode.h>

enum {
    BAREV_AUTH_FAILED = -1, BAREV_AUTH_NONE = 0, BAREV_AUTH_TLS_FEATURES,
    BAREV_AUTH_STARTTLS, BAREV_AUTH_PROCEED, BAREV_AUTH_BEGIN_TLS,
    BAREV_AUTH_RESTART_TLS, BAREV_AUTH_EXTERNAL_FEATURES, BAREV_AUTH_EXTERNAL,
    BAREV_AUTH_SUCCESS, BAREV_AUTH_RESTART_SASL, BAREV_AUTH_FINAL_FEATURES,
    BAREV_AUTH_READY
};
typedef struct { unsigned phase; int output; gboolean server; } BarevAuth;

void barev_auth_init(BarevAuth *, gboolean server);
int barev_auth_fail(BarevAuth *);
int barev_auth_opened(BarevAuth *);
int barev_auth_sent(BarevAuth *);
int barev_auth_secured(BarevAuth *, gboolean verified);
int barev_auth_receive(BarevAuth *, const xmlnode *);
const char *barev_auth_output(const BarevAuth *);
gboolean barev_auth_ready(const BarevAuth *);
gboolean barev_auth_handshaking(const BarevAuth *);
gboolean barev_auth_writing(const BarevAuth *);
#endif
