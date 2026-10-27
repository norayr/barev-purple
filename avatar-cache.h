/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_AVATAR_CACHE_H
#define BAREV_AVATAR_CACHE_H
#include <glib.h>
#include <libpurple/blist.h>

#define BAREV_AVATAR_MAX_BYTES 65535
typedef struct {
    gchar *id, *hash;
    gint64 deadline;
} BarevAvatarRequest;

gboolean barev_avatar_hash_valid(const char *hash);
gboolean barev_avatar_cache_matches(PurpleBuddy *buddy, const char *hash);
void barev_avatar_request_clear(BarevAvatarRequest *request);
gboolean barev_avatar_request_pending(BarevAvatarRequest *request, gint64 now);
void barev_avatar_request_begin(BarevAvatarRequest *request, const char *id, const char *hash, gint64 now);
#endif
