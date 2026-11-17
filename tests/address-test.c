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
#include <libpurple/request.h>
#include <libpurple/util.h>
#include "barev.h"

static unsigned checks, starts, popups;
static char *shown_ipv6, *shown_address, *shown_public_key, *shown_fingerprint, *shown_authentication;
static unsigned errors;
static char *last_error;
static char *shown_peer_key, *shown_pin_status, *pin_description;
static PurpleRequestInputCb pin_input;
static PurpleRequestActionCb pin_choices[2];
static gpointer pin_input_data, pin_action_data;
static int pin_input_handle, pin_action_handle;
#define CHECK(value) do { ++checks; if (!(value)) g_error("address check %u failed", checks); } while (0)

/* Stop login before any listener or peer connection is opened. */
G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ (void)data; ++starts; return -1; }

static void *show_message(PurpleNotifyMsgType type, const char *title, const char *primary, const char *secondary)
{
    (void)title;
    if (type == PURPLE_NOTIFY_MSG_ERROR) {
        ++errors; g_free(last_error); last_error = g_strdup_printf("%s\n%s", primary, secondary);
    }
    return NULL;
}

static unsigned buddy_count(PurpleAccount *account)
{
    PurpleBlistNode *node;
    unsigned count = 0;
    for (node = purple_blist_get_root(); node; node = purple_blist_node_next(node, TRUE))
        if (PURPLE_BLIST_NODE_IS_BUDDY(node) && purple_buddy_get_account((PurpleBuddy *)node) == account) ++count;
    return count;
}

static void *show_info(PurpleConnection *gc, const char *who, PurpleNotifyUserInfo *info)
{
    GList *item;
    (void)gc; (void)who;
    g_free(shown_ipv6); g_free(shown_address);
    g_free(shown_public_key); g_free(shown_fingerprint); g_free(shown_authentication);
    g_free(shown_peer_key); g_free(shown_pin_status); shown_peer_key = shown_pin_status = NULL;
    shown_ipv6 = shown_address = NULL;
    shown_public_key = shown_fingerprint = shown_authentication = NULL;
    for (item = purple_notify_user_info_get_entries(info); item; item = item->next) {
        const char *label = purple_notify_user_info_entry_get_label(item->data);
        const char *value = purple_notify_user_info_entry_get_value(item->data);
        if (!g_strcmp0(label, "IPv6")) shown_ipv6 = g_strdup(value);
        if (!g_strcmp0(label, "Barev address")) shown_address = g_strdup(value);
        if (!g_strcmp0(label, "Ed25519 public key")) shown_public_key = g_strdup(value);
        if (!g_strcmp0(label, "Identity fingerprint")) shown_fingerprint = g_strdup(value);
        if (!g_strcmp0(label, "Chat authentication")) shown_authentication = g_strdup(value);
        if (!g_strcmp0(label, "Pinned Ed25519 public key")) shown_peer_key = g_strdup(value);
        if (!g_strcmp0(label, "Peer key pin")) shown_pin_status = g_strdup(value);
    }
    ++popups;
    return NULL;
}

static void *request_pin_input(const char *title, const char *primary, const char *secondary,
    const char *value, gboolean multiline, gboolean masked, gchar *hint, const char *ok, GCallback yes,
    const char *cancel, GCallback no, PurpleAccount *purple, const char *who,
    PurpleConversation *conversation, void *data)
{
    (void)title; (void)primary; (void)secondary; (void)value; (void)multiline; (void)masked; (void)hint;
    (void)ok; (void)cancel; (void)no; (void)purple; (void)who; (void)conversation;
    pin_input = (PurpleRequestInputCb)yes; pin_input_data = data; return &pin_input_handle;
}
static void *request_pin_action(const char *title, const char *primary, const char *secondary,
    int selected, PurpleAccount *purple, const char *who, PurpleConversation *conversation,
    void *data, size_t count, va_list choices)
{
    unsigned i;
    (void)title; (void)primary; (void)purple; (void)who; (void)conversation;
    CHECK(count == 2 && selected == 0); pin_action_data = data;
    g_free(pin_description); pin_description = g_strdup(secondary);
    for (i = 0; i < 2; ++i) { (void)va_arg(choices, const char *); pin_choices[i] = va_arg(choices, PurpleRequestActionCb); }
    return &pin_action_handle;
}
static void close_pin_request(PurpleRequestType type, void *handle)
{
    (void)handle;
    if (type == PURPLE_REQUEST_INPUT) pin_input_data = NULL;
    if (type == PURPLE_REQUEST_ACTION) pin_action_data = NULL;
}
static void enter_pin(const char *key)
{
    PurpleRequestInputCb cb = pin_input; gpointer data = pin_input_data;
    CHECK(data != NULL); purple_request_close(PURPLE_REQUEST_INPUT, &pin_input_handle); cb(data, key);
}
static void approve_pin(unsigned choice)
{
    PurpleRequestActionCb cb = pin_choices[choice]; gpointer data = pin_action_data;
    CHECK(data != NULL); purple_request_close(PURPLE_REQUEST_ACTION, &pin_action_handle); cb(data, 1-(int)choice);
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
                                   .timeout_add_seconds = g_timeout_add_seconds};
    PurpleNotifyUiOps notify = {.notify_message = show_message, .notify_userinfo = show_info};
    PurpleRequestUiOps requests = {.request_input = request_pin_input, .request_action = request_pin_action, .close_request = close_pin_request};
    PurpleAccount *account;
    PurpleConnection *gc;
    PurplePlugin *plugin;
    PurplePluginProtocolInfo *protocol;
    PurpleBuddy *buddy, *bare, *restored;
    BonjourBuddy *bb;
    BonjourData *data;
    GList *actions;
    PurplePluginAction *action;
    char *path, *saved = NULL, *store_profile;
    GModule *module;
    void (*load_buddies)(PurpleAccount *);
    gpointer symbol;
    if (argc != 3 && argc != 4) return 2;
    purple_util_set_user_dir(argv[1]);
    purple_eventloop_set_ui_ops(&events);
    purple_notify_set_ui_ops(&notify);
    purple_request_set_ui_ops(&requests);
    CHECK(purple_core_init(argc == 4 ? "telepathy-haze" : "barev-address-test"));
    store_profile = argc == 4 ? g_build_filename(g_get_home_dir(), ".purple", NULL) : g_strdup(argv[1]);
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
    {
        const char *identifier = purple_account_get_string(account, "barev_identity", "");
        char *filename = g_strdup_printf("%s.key", identifier), *record = NULL;
        gsize length = 0;
        CHECK(strlen(identifier) == 64);
        path = g_build_filename(store_profile, "barev", "identities", filename, NULL);
        CHECK(g_file_get_contents(path, &record, &length, NULL) && length == 72);
        memcpy(data->identity.seed, record+8, 32); memcpy(data->identity.public_key, record+40, 32);
        data->identity.active = TRUE;
        g_free(record); g_free(filename); g_free(path);
    }
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
    CHECK(!g_strcmp0(shown_public_key, purple_account_get_string(account, "barev_identity", "")));
    CHECK(shown_fingerprint && strlen(shown_fingerprint) == 71 && g_str_has_prefix(shown_fingerprint, "SHA256:"));
    CHECK(shown_authentication && strstr(shown_authentication, "not yet negotiated"));
    purple_plugin_action_free(action); g_list_free(actions);
    path = g_build_filename(g_get_home_dir(), ".purple", "barev-contacts-fixture.conf", NULL);
    CHECK(g_file_get_contents(path, &saved, NULL, NULL));
    CHECK(!strcmp(saved, "Bob@200::1\n")); g_free(saved); g_free(path);

    {
        const char *key = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        const char *replacement = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        GList *menu = protocol->blist_node_menu(PURPLE_BLIST_NODE(buddy));
        PurpleMenuAction *item = menu ? menu->data : NULL;
        unsigned count = buddy_count(account);
        CHECK(item && !strcmp(item->label, "Peer identity..."));
        CHECK(!g_strcmp0(shown_pin_status, NULL));
        ((void (*)(PurpleBlistNode *, gpointer))item->callback)(PURPLE_BLIST_NODE(buddy), item->data); enter_pin(key); approve_pin(0);
        protocol->get_info(gc, purple_buddy_get_name(buddy));
        CHECK(!shown_peer_key && !g_strcmp0(shown_pin_status, "No pinned key"));
        ((void (*)(PurpleBlistNode *, gpointer))item->callback)(PURPLE_BLIST_NODE(buddy), item->data); enter_pin(key);
        CHECK(pin_description && strstr(pin_description, "New fingerprint: SHA256:") && strstr(pin_description, key));
        approve_pin(1); protocol->get_info(gc, purple_buddy_get_name(buddy));
        CHECK(!g_strcmp0(shown_peer_key, key) && !g_strcmp0(shown_pin_status, "Manually pinned"));
        CHECK(buddy_count(account) == count && shown_authentication && strstr(shown_authentication, "not yet negotiated"));
        ((void (*)(PurpleBlistNode *, gpointer))item->callback)(PURPLE_BLIST_NODE(buddy), item->data); enter_pin(replacement);
        CHECK(strstr(pin_description, "Current fingerprint: SHA256:") && strstr(pin_description, replacement));
        approve_pin(1); protocol->get_info(gc, purple_buddy_get_name(buddy));
        CHECK(!g_strcmp0(shown_peer_key, replacement));
        purple_menu_action_free(item); g_list_free(menu);
    }

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

    /* Rejected Add Buddy callbacks must roll back the local insertion. */
    {
        const char *numeric = "lmd@201:5b1e:5e06:7daa:d39:e62c:356e:e5a6";
        const char *bad_names[] = {
            "lmd@lmd@201:5b1e:5e06:7daa:d39:e62c:356e:e5a6",
            "lmd@lmd@201:5b1e:5e06:7daa:d39:e62c:356e:e5a6lmd@201:5b1e:5e06:7daa:d39:e62c:356e:e5a6",
            "bad@ai-f.barev.v6.alt", "bad@ai--e.barev.v6.alt", "@200::2", "bad@"
        };
        unsigned before = buddy_count(account), i, repeat;
        for (i = 0; i < G_N_ELEMENTS(bad_names); ++i) {
            for (repeat = 0; repeat < 2; ++repeat) {
                PurpleBuddy *bad = purple_buddy_new(account, bad_names[i], "Rejected alias");
                unsigned notices = errors;
                purple_blist_add_buddy(bad, NULL, NULL, NULL);
                purple_account_add_buddy_with_invite(account, bad, NULL);
                CHECK(errors == notices+1 && last_error && strstr(last_error, "Contact not added"));
                CHECK(buddy_count(account) == before);
                CHECK(purple_find_buddy(account, bad_names[i]) == NULL);
            }
        }
        {
            PurpleBuddy *accepted = purple_buddy_new(account, numeric, "Valid full IPv6");
            unsigned notices = errors;
            purple_blist_add_buddy(accepted, NULL, NULL, NULL);
            for (repeat = 0; repeat < 3; ++repeat) {
                purple_account_add_buddy_with_invite(account, accepted, NULL);
                CHECK(errors == notices && buddy_count(account) == before+1);
                CHECK(purple_find_buddy(account, numeric) == accepted);
                CHECK(!strcmp(purple_buddy_get_local_buddy_alias(accepted), "Valid full IPv6"));
            }
            bb = purple_buddy_get_protocol_data(accepted);
            CHECK(bb && bb->ips && !strcmp(bb->ips->data, "201:5b1e:5e06:7daa:d39:e62c:356e:e5a6"));
        }
    }
    g_free(data->jid); data->jid = NULL;
    purple_account_disconnect(account);
    CHECK(purple_account_is_disconnected(account));
    g_free(shown_ipv6); g_free(shown_address); g_free(last_error);
    g_free(shown_public_key); g_free(shown_fingerprint); g_free(shown_authentication);
    g_free(shown_peer_key); g_free(shown_pin_status); g_free(pin_description);
    g_free(store_profile);
    purple_core_quit();
    g_print("Barev C address UI and persistence checks passed: %u\n", checks);
    return 0;
}
