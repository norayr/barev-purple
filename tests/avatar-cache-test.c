/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <libpurple/account.h>
#include <libpurple/blist.h>
#include <libpurple/buddyicon.h>
#include <libpurple/core.h>
#include <libpurple/eventloop.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "../avatar-cache.h"

static unsigned checks;
#define CHECK(value) do { ++checks; if (!(value)) g_error("avatar cache check %u failed", checks); } while (0)

static PurpleBuddy *cached(PurpleAccount *account, const char *name, const char *bytes, gsize length, const char *checksum)
{
    PurpleBuddy *buddy = purple_buddy_new(account, name, NULL);
    char *path = g_build_filename(purple_buddy_icons_get_cache_dir(), name, NULL);
    purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    g_mkdir_with_parents(purple_buddy_icons_get_cache_dir(), 0700);
    CHECK(g_file_set_contents(path, bytes, length, NULL));
    purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "buddy_icon", name);
    purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "icon_checksum", checksum);
    g_free(path);
    return buddy;
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
                                   .timeout_add_seconds = g_timeout_add_seconds};
    PurpleAccount *account;
    PurpleBuddy *buddy;
    BarevAvatarRequest request = {0};
    gsize length;
    guchar *image;
    gchar *hash, *upper;
    PurplePlugin *plugin;
    if (argc != 3) return 2;
    purple_util_set_user_dir(argv[1]);
    purple_eventloop_set_ui_ops(&events);
    CHECK(purple_core_init("barev-avatar-test"));
    purple_set_blist(purple_blist_new());
    plugin = purple_plugin_probe(argv[2]);
    CHECK(plugin && !plugin->unloadable && purple_plugin_load(plugin));
    purple_plugins_probe("barev-test-no-scan");
    account = purple_account_new("fixture", "prpl-barev");
    purple_accounts_add(account);
    image = g_base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGMQVDL+DwACFAFmBODefwAAAABJRU5ErkJggg==", &length);
    hash = g_compute_checksum_for_data(G_CHECKSUM_SHA1, image, length);
    upper = g_ascii_strup(hash, -1);
    CHECK(barev_avatar_hash_valid(hash)); CHECK(barev_avatar_hash_valid(upper));
    CHECK(!barev_avatar_hash_valid(NULL)); CHECK(!barev_avatar_hash_valid("short"));
    CHECK(!barev_avatar_hash_valid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
    buddy = cached(account, "valid.png", (char *)image, length, hash);
    CHECK(barev_avatar_cache_matches(buddy, hash));
    CHECK(barev_avatar_cache_matches(buddy, upper));
    CHECK(!barev_avatar_cache_matches(buddy, "0000000000000000000000000000000000000000"));
    buddy = cached(account, "metadata.png", (char *)image, length, "0000000000000000000000000000000000000000");
    CHECK(barev_avatar_cache_matches(buddy, hash));
    buddy = cached(account, "stale.png", "corrupted", 9, hash);
    CHECK(!barev_avatar_cache_matches(buddy, hash));
    {
        gchar *oversized = g_malloc0(BAREV_AVATAR_MAX_BYTES+1);
        buddy = cached(account, "oversized.png", oversized, BAREV_AVATAR_MAX_BYTES+1, hash);
        CHECK(!barev_avatar_cache_matches(buddy, hash));
        g_free(oversized);
    }
    buddy = cached(account, "empty.png", "", 0, hash);
    CHECK(!barev_avatar_cache_matches(buddy, hash));
    buddy = purple_buddy_new(account, "missing.png", NULL);
    purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "buddy_icon", "not-present.png");
    purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "icon_checksum", hash);
    CHECK(!barev_avatar_cache_matches(buddy, hash));
    CHECK(!barev_avatar_request_pending(&request, 1));
    barev_avatar_request_begin(&request, "request", upper, 100);
    CHECK(barev_avatar_request_pending(&request, 101));
    CHECK(!g_strcmp0(request.hash, hash));
    CHECK(barev_avatar_request_pending(&request, 100+15*G_USEC_PER_SEC-1));
    CHECK(!barev_avatar_request_pending(&request, 100+15*G_USEC_PER_SEC));
    CHECK(!request.id && !request.hash);
    barev_avatar_request_begin(&request, "another", hash, 200);
    barev_avatar_request_clear(&request);
    CHECK(!barev_avatar_request_pending(&request, 201));
    g_free(image); g_free(hash); g_free(upper);
    purple_core_quit();
    g_print("Barev C avatar cache checks passed: %u\n", checks);
    return 0;
}
