/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <gmodule.h>
#include <libpurple/account.h>
#include <libpurple/blist.h>
#include <libpurple/connection.h>
#include <libpurple/core.h>
#include <libpurple/eventloop.h>
#include <libpurple/notify.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "barev.h"

static unsigned checks, starts, popups;
static char *shown_ipv6, *shown_address;
#define CHECK(value) do { ++checks; if (!(value)) g_error("address check %u failed", checks); } while (0)

/* Stop login before any listener or peer connection is opened. */
G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ (void)data; ++starts; return -1; }

static void *show_info(PurpleConnection *gc, const char *who, PurpleNotifyUserInfo *info)
{
    GList *item;
    (void)gc; (void)who;
    g_free(shown_ipv6); g_free(shown_address);
    shown_ipv6 = shown_address = NULL;
    for (item = purple_notify_user_info_get_entries(info); item; item = item->next) {
        const char *label = purple_notify_user_info_entry_get_label(item->data);
        const char *value = purple_notify_user_info_entry_get_value(item->data);
        if (!g_strcmp0(label, "IPv6")) shown_ipv6 = g_strdup(value);
        if (!g_strcmp0(label, "Barev address")) shown_address = g_strdup(value);
    }
    ++popups;
    return NULL;
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
                                   .timeout_add_seconds = g_timeout_add_seconds};
    PurpleNotifyUiOps notify = {.notify_userinfo = show_info};
    PurpleAccount *account;
    PurpleConnection *gc;
    PurplePlugin *plugin;
    PurplePluginProtocolInfo *protocol;
    PurpleBuddy *buddy, *bare, *restored;
    BonjourBuddy *bb;
    BonjourData *data;
    GList *actions;
    PurplePluginAction *action;
    char *path, *saved = NULL;
    GModule *module;
    void (*load_buddies)(PurpleAccount *);
    gpointer symbol;
    if (argc != 3) return 2;
    purple_util_set_user_dir(argv[1]);
    purple_eventloop_set_ui_ops(&events);
    purple_notify_set_ui_ops(&notify);
    CHECK(purple_core_init("barev-address-test"));
    purple_set_blist(purple_blist_new());
    plugin = purple_plugins_find_with_id("prpl-barev");
    if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]);
    CHECK(plugin && !plugin->unloadable && purple_plugin_load(plugin));
    purple_plugins_probe("barev-test-no-scan");
    protocol = PURPLE_PLUGIN_PROTOCOL_INFO(plugin);
    account = purple_account_new("fixture", "prpl-barev");
    purple_accounts_add(account);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    CHECK(starts == 1);
    gc = purple_account_get_connection(account);
    CHECK(gc && !purple_connection_get_protocol_data(gc));
    data = g_new0(BonjourData, 1);
    data->jid = g_strdup("fixture@200::1");
    purple_connection_set_protocol_data(gc, data);
    path = g_build_filename(g_get_home_dir(), ".purple", NULL);
    CHECK(!g_mkdir_with_parents(path, 0700)); g_free(path);

    buddy = purple_buddy_new(account, "Bob@AI-E.BAREV.V6.ALT.", "My chosen alias");
    purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    protocol->add_buddy(gc, buddy, purple_buddy_get_group(buddy));
    CHECK(!strcmp(purple_buddy_get_name(buddy), "Bob@200::1"));
    CHECK(!strcmp(purple_buddy_get_local_buddy_alias(buddy), "My chosen alias"));
    CHECK(purple_find_buddy(account, "Bob@0200::1") == buddy);
    CHECK(purple_find_buddy(account, "Bob@ai-e.barev.v6.alt") == buddy);
    CHECK(purple_find_buddy(account, "bob@200::1") == NULL);
    bb = purple_buddy_get_protocol_data(buddy);
    CHECK(bb && bb->ips && !strcmp(bb->ips->data, "200::1") && bb->port_p2pj == 1337);
    CHECK(!strcmp(purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "barev_ip"), "200::1"));
    protocol->get_info(gc, "Bob@ai-e.barev.v6.alt");
    CHECK(popups == 1 && !g_strcmp0(shown_ipv6, "200::1"));
    CHECK(!g_strcmp0(shown_address, "Bob@ai-e.barev.v6.alt"));
    actions = plugin->info->actions(plugin, gc);
    CHECK(actions && !actions->next);
    action = actions->data;
    CHECK(!strcmp(action->label, "My Barev address"));
    action->context = gc; action->plugin = plugin;
    action->callback(action);
    CHECK(popups == 2 && !g_strcmp0(shown_address, "fixture@ai-e.barev.v6.alt"));
    purple_plugin_action_free(action); g_list_free(actions);
    path = g_build_filename(g_get_home_dir(), ".purple", "barev-contacts-fixture.conf", NULL);
    CHECK(g_file_get_contents(path, &saved, NULL, NULL));
    CHECK(!strcmp(saved, "Bob@200::1\n")); g_free(saved); g_free(path);

    /* Exercise actual message serialization over a private Unix socket pair. */
    {
        BonjourJabber jabber = {.account = account};
        BonjourJabberConversation conversation = {.account = account, .sent_stream_start = STREAM_FULLY_SENT,
                                                   .recv_stream_start = TRUE};
        int sockets[2];
        char wire[4096];
        ssize_t count;
        xmlnode *message;
        CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
        conversation.socket = sockets[0]; conversation.tx_buf = purple_circ_buffer_new(0);
        bb->conversation = &conversation; data->jabber_data = &jabber;
        CHECK(protocol->send_im(gc, "Bob@ai-e.barev.v6.alt", "<i>encoded contact</i>", PURPLE_MESSAGE_SEND) > 0);
        count = recv(sockets[1], wire, sizeof(wire), 0);
        CHECK(count > 0);
        message = xmlnode_from_str(wire, count);
        CHECK(message && !g_strcmp0(xmlnode_get_attrib(message, "to"), "Bob@200::1"));
        CHECK(!g_strcmp0(xmlnode_get_attrib(message, "from"), "fixture@200::1"));
        xmlnode_free(message);
        bb->conversation = NULL; data->jabber_data = NULL;
        purple_circ_buffer_destroy(conversation.tx_buf);
        close(sockets[0]); close(sockets[1]);
    }

    /* Reconnect restoration keeps aliases and Haze's bare-nickname identity. */
    bare = purple_buddy_new(account, "legacy", "Legacy alias");
    purple_blist_add_buddy(bare, NULL, NULL, NULL);
    purple_blist_node_set_string(PURPLE_BLIST_NODE(bare), "barev_ip", "200::2");
    purple_blist_node_set_int(PURPLE_BLIST_NODE(bare), "barev_port", 1444);
    restored = purple_buddy_new(account, "again@ai-i.barev.v6.alt", "Restored alias");
    purple_blist_add_buddy(restored, NULL, NULL, NULL);
    purple_blist_node_set_string(PURPLE_BLIST_NODE(restored), "barev_ip", "200::2");
    module = g_module_open(argv[2], G_MODULE_BIND_LAZY);
    CHECK(module && g_module_symbol(module, "bonjour_buddies_load_from_blist", &symbol));
    memcpy(&load_buddies, &symbol, sizeof(load_buddies)); load_buddies(account);
    CHECK(!strcmp(purple_buddy_get_name(restored), "again@200::2"));
    CHECK(!strcmp(purple_buddy_get_local_buddy_alias(restored), "Restored alias"));
    bb = purple_buddy_get_protocol_data(bare);
    CHECK(bb && bb->ips && !strcmp(bb->ips->data, "200::2") && bb->port_p2pj == 1444);
    protocol->get_info(gc, "legacy");
    CHECK(!g_strcmp0(shown_address, "legacy@ai-i.barev.v6.alt"));
    protocol->add_buddy(gc, buddy, purple_buddy_get_group(buddy));
    CHECK(!strcmp(purple_buddy_get_local_buddy_alias(buddy), "My chosen alias"));
    g_module_close(module);
    g_free(data->jid); data->jid = NULL;
    purple_account_disconnect(account);
    CHECK(purple_account_is_disconnected(account));
    g_free(shown_ipv6); g_free(shown_address);
    purple_core_quit();
    g_print("Barev C address UI and persistence checks passed: %u\n", checks);
    return 0;
}
