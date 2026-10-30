/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include <libpurple/buddyicon.h>
#include "avatar-cache.h"

gboolean barev_avatar_hash_valid(const char *hash)
{
    unsigned i;
    if (!hash || strlen(hash) != 40) return FALSE;
    for (i = 0; i < 40; ++i) if (!g_ascii_isxdigit(hash[i])) return FALSE;
    return TRUE;
}

gboolean barev_avatar_cache_matches(PurpleBuddy *buddy, const char *hash)
{
    PurpleBuddyIcon *icon;
    gconstpointer data;
    gchar *expected;
    size_t length;
    gboolean matches = FALSE;
    if (!buddy || !barev_avatar_hash_valid(hash)) return FALSE;
    expected = g_ascii_strdown(hash, -1);
    icon = purple_buddy_icons_find(purple_buddy_get_account(buddy), purple_buddy_get_name(buddy));
    if (!icon) { g_free(expected); return FALSE; }
    data = purple_buddy_icon_get_data(icon, &length);
    if (data && length && length <= BAREV_AVATAR_MAX_BYTES) {
        gchar *actual = g_compute_checksum_for_data(G_CHECKSUM_SHA1, data, length);
        matches = !strcmp(actual, expected);
        g_free(actual);
    }
    purple_buddy_icon_unref(icon);
    g_free(expected);
    return matches;
}

void barev_avatar_request_clear(BarevAvatarRequest *request)
{
    g_free(request->id); g_free(request->hash);
    memset(request, 0, sizeof(*request));
}

gboolean barev_avatar_request_pending(BarevAvatarRequest *request, gint64 now)
{
    if (request->id && now >= request->deadline) barev_avatar_request_clear(request);
    return request->id != NULL;
}

void barev_avatar_request_begin(BarevAvatarRequest *request, const char *id, const char *hash, gint64 now)
{
    barev_avatar_request_clear(request);
    request->id = g_strdup(id); request->hash = g_ascii_strdown(hash, -1);
    request->deadline = now+15*G_USEC_PER_SEC;
}
