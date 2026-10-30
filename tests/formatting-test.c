/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <gmodule.h>
#include <libpurple/account.h>
#include <libpurple/blist.h>
#include <libpurple/connection.h>
#include <libpurple/conversation.h>
#include <libpurple/core.h>
#include <libpurple/eventloop.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "../jabber.h"

static unsigned checks, starts;
#define CHECK(value) do { ++checks; if (!(value)) g_error("formatting check %u failed", checks); } while (0)

/* The executable exports this replacement to the dynamically loaded plugin.
 * Stop login before opening listeners or starting contact connections. */
G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{
    (void)data;
    ++starts;
    return -1;
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
                                   .timeout_add_seconds = g_timeout_add_seconds};
    PurpleAccount *account;
    PurpleConnection *connection;
    PurpleConversation *conversation;
    PurplePlugin *plugin;
    GModule *process;
    gpointer replacement = NULL;
    if (argc != 3) return 2;
    process = g_module_open(NULL, 0);
    CHECK(process && g_module_symbol(process, "bonjour_jabber_start", &replacement));
    CHECK(replacement == (gpointer)bonjour_jabber_start);
    g_module_close(process);
    purple_util_set_user_dir(argv[1]);
    purple_eventloop_set_ui_ops(&events);
    CHECK(purple_core_init("barev-formatting-test"));
    purple_set_blist(purple_blist_new());
    /* Replace any system-installed copy discovered during core startup. */
    plugin = purple_plugins_find_with_id("prpl-barev");
    if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]);
    CHECK(plugin && !plugin->unloadable && purple_plugin_load(plugin));
    purple_plugins_probe("barev-test-no-scan");
    account = purple_account_new("fixture", "prpl-barev");
    purple_accounts_add(account);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    CHECK(starts == 1);
    connection = purple_account_get_connection(account);
    CHECK(connection != NULL);
    CHECK(purple_connection_get_prpl(connection) == plugin);
    CHECK(purple_connection_get_protocol_data(connection) == NULL);
    CHECK(connection->flags & PURPLE_CONNECTION_HTML);
    conversation = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, "peer@200::2");
    CHECK(conversation != NULL);
    CHECK(purple_conversation_get_features(conversation) & PURPLE_CONNECTION_HTML);
    purple_account_disconnect(account);
    CHECK(purple_account_is_disconnected(account));
    purple_core_quit();
    g_print("Barev C formatting capability checks passed: %u\n", checks);
    return 0;
}
