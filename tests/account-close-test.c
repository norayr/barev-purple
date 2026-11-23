/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <gmodule.h>
#include <libpurple/core.h>
#include <libpurple/eventloop.h>
#include <libpurple/plugin.h>
#include <libpurple/request.h>
#include <libpurple/util.h>
#include "barev.h"

static unsigned checks, requests;
static int request_handle;
#define CHECK(value) do { ++checks; if (!(value)) g_error("account close check %u failed (%s:%d)", checks, __FILE__, __LINE__); } while (0)

G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ data->socket = data->socket6 = -1; return 0; }
G_MODULE_EXPORT GSList *bonjour_jabber_get_local_ips(gint fd)
{ (void)fd; return g_slist_append(NULL, g_strdup("200::1")); }
G_MODULE_EXPORT int bonjour_jabber_open_stream(BonjourJabber *data, const char *who)
{ (void)data; (void)who; return 0; }

static void *request_action(const char *title, const char *primary, const char *secondary,
    int selected, PurpleAccount *account, const char *who, PurpleConversation *conversation,
    void *data, size_t count, va_list actions)
{
    (void)title; (void)primary; (void)secondary; (void)selected; (void)account;
    (void)who; (void)conversation; (void)data; (void)count; (void)actions;
    ++requests; return &request_handle;
}
static void close_request(PurpleRequestType type, void *handle)
{ (void)type; (void)handle; }

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
        .timeout_add_seconds = g_timeout_add_seconds};
    PurpleRequestUiOps request_ops = {.request_action = request_action, .close_request = close_request};
    PurplePlugin *plugin;
    PurpleAccount *account;
    PurpleBuddy *buddy;
    GModule *module;
    gpointer symbol;
    void (*parse_offer)(PurpleConnection *, xmlnode *, PurpleBuddy *);
    unsigned round, i;
    if (argc != 3) return 2;
    purple_util_set_user_dir(argv[1]); purple_eventloop_set_ui_ops(&events);
    CHECK(purple_core_init("barev-account-close-test"));
    purple_set_blist(purple_blist_new());
    plugin = purple_plugins_find_with_id("prpl-barev"); if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]); CHECK(plugin && purple_plugin_load(plugin));
    purple_plugins_probe("barev-test-no-scan");
    module = g_module_open(argv[2], G_MODULE_BIND_LOCAL); CHECK(module != NULL);
    CHECK(g_module_symbol(module, "xep_si_parse", &symbol)); memcpy(&parse_offer, &symbol, sizeof(parse_offer));
    account = purple_account_new("alice", "prpl-barev"); purple_accounts_add(account);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    CHECK(purple_account_is_connected(account));
    buddy = purple_buddy_new(account, "bob@200::2", NULL); purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->add_buddy(account->gc, buddy, NULL);
    purple_request_set_ui_ops(&request_ops);
    for (round = 0; round < 8; ++round) {
        PurpleXfer *held[4];
        unsigned count = 0;
        BonjourData *data = purple_connection_get_protocol_data(account->gc);
        if (round & 1) {
            for (i = 0; i < 2; ++i) {
                held[count] = PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->new_xfer(account->gc, "bob@200::2");
                CHECK(held[count] != NULL); purple_xfer_ref(held[count++]);
            }
        }
        if (round & 2) {
            for (i = 0; i < 2; ++i) {
                xmlnode *offer = xmlnode_from_str("<iq type='set' id='offer'><si xmlns='http://jabber.org/protocol/si' id='fixture' profile='http://jabber.org/protocol/si/profile/file-transfer'><file xmlns='http://jabber.org/protocol/si/profile/file-transfer' name='fixture.bin' size='4'/></si></iq>", -1);
                GSList *last;
                CHECK(offer != NULL); parse_offer(account->gc, offer, buddy); xmlnode_free(offer);
                last = g_slist_last(data->xfer_lists); CHECK(last != NULL);
                held[count] = last->data; CHECK(purple_xfer_get_type(held[count]) == PURPLE_XFER_RECEIVE);
                purple_xfer_ref(held[count++]);
            }
        }
        CHECK(g_slist_length(data->xfer_lists) == count);
        purple_account_disconnect(account);
        CHECK(purple_account_is_disconnected(account));
        for (i = 0; i < count; ++i) {
            CHECK(purple_xfer_is_canceled(held[i])); CHECK(held[i]->data == NULL);
            CHECK(purple_xfer_get_status(held[i]) == (purple_xfer_get_type(held[i]) == PURPLE_XFER_RECEIVE ?
                PURPLE_XFER_STATUS_CANCEL_REMOTE : PURPLE_XFER_STATUS_CANCEL_LOCAL));
            purple_xfer_unref(held[i]);
        }
        if (round < 7) { purple_account_connect(account); CHECK(purple_account_is_connected(account)); }
    }
    CHECK(requests == 8);
    purple_core_quit(); g_module_close(module);
    printf("Account close: %u checks passed\n", checks); return 0;
}
