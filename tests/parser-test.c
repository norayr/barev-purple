/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <libpurple/account.h>
#include <libpurple/blist.h>
#include <libpurple/core.h>
#include <libpurple/debug.h>
#include <libpurple/eventloop.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "parser.h"

static unsigned checks, started, matched, packets;
static PurpleBuddy *known;
static char *retired_name, *matched_log;
#define CHECK(value) do { ++checks; if (!(value)) g_error("parser check %u failed", checks); } while (0)
#define OPEN "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'"

/* Keep the parser fixture network-free. The real matcher can replace and free
 * buddy_name; poison and retain the old buffer to test that ownership change
 * deterministically, without relying on allocator reuse or a sanitizer. */
void bonjour_jabber_conv_match_by_name(BonjourJabberConversation *conversation)
{
    ++matched;
    if (g_strcmp0(conversation->buddy_name, "Bob@200::2")) return;
    CHECK(retired_name == NULL);
    retired_name = conversation->buddy_name;
    memset(retired_name, '!', strlen(retired_name));
    conversation->buddy_name = g_strdup("Bob@200::2");
    conversation->pb = known;
}

void bonjour_jabber_conv_match_by_ip(BonjourJabberConversation *conversation)
{ (void)conversation; CHECK(FALSE); }

void bonjour_jabber_stream_started(BonjourJabberConversation *conversation)
{ CHECK(conversation->pb == known); ++started; }

void async_bonjour_jabber_close_conversation(BonjourJabberConversation *conversation)
{ CHECK(conversation->in_parser); conversation->close_timeout = 1; }

void bonjour_jabber_process_packet(PurpleBuddy *buddy, xmlnode *packet)
{ CHECK(buddy == known && packet != NULL); ++packets; }

static void debug_print(PurpleDebugLevel level, const char *category, const char *message)
{
    (void)level; (void)category;
    if (g_str_has_prefix(message, "parse_from: after conv_match_by_name")) {
        g_free(matched_log);
        matched_log = g_strdup(message);
    }
}

static gboolean debug_enabled(PurpleDebugLevel level, const char *category)
{ (void)level; (void)category; return TRUE; }

static void opening(const char *text, gboolean attached, gboolean accepted, gboolean split)
{
    BonjourJabberConversation conversation = {.socket = -1, .sent_stream_start = STREAM_FULLY_SENT};
    size_t length = strlen(text);
    unsigned old_started = started, old_matched = matched, old_packets = packets;
    conversation.pb = attached ? known : NULL;
    conversation.ip = g_strdup("200::2");
    g_clear_pointer(&matched_log, g_free);
    if (split) {
        bonjour_parser_process(&conversation, text, length-1);
        CHECK(started == old_started && !conversation.close_timeout);
        bonjour_parser_process(&conversation, text+length-1, 1);
    } else bonjour_parser_process(&conversation, text, length);
    CHECK(!conversation.in_parser);
    CHECK(started == old_started + (accepted ? 1 : 0));
    CHECK((conversation.close_timeout == 0) == accepted);
    if (accepted) {
        CHECK(conversation.recv_stream_start && conversation.pb == known);
        if (!attached) {
            CHECK(matched == old_matched+1);
            CHECK(!g_strcmp0(matched_log,
                "parse_from: after conv_match_by_name for 'Bob@200::2': pb=Bob@200::2\n"));
        }
    } else {
        const char message[] = "<message><body>must not be delivered</body></message>";
        bonjour_parser_process(&conversation, message, sizeof(message)-1);
        CHECK(packets == old_packets && started == old_started);
    }
    bonjour_parser_destroy(&conversation);
    g_free(conversation.ip);
    g_free(conversation.buddy_name);
    g_clear_pointer(&retired_name, g_free);
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
                                   .timeout_add_seconds = g_timeout_add_seconds};
    PurpleDebugUiOps debug = {.print = debug_print, .is_enabled = debug_enabled};
    PurplePlugin *plugin;
    PurpleAccount *account;
    unsigned attached, split;
    if (argc != 3) return 2;
    purple_util_set_user_dir(argv[1]);
    purple_eventloop_set_ui_ops(&events);
    CHECK(purple_core_init("barev-parser-test"));
    purple_set_blist(purple_blist_new());
    plugin = purple_plugins_find_with_id("prpl-barev");
    if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]);
    CHECK(plugin && !plugin->unloadable && purple_plugin_load(plugin));
    purple_plugins_probe("barev-test-no-scan");
    account = purple_account_new("fixture", "prpl-barev");
    purple_accounts_add(account);
    known = purple_buddy_new(account, "Bob@200::2", NULL);
    purple_blist_add_buddy(known, NULL, NULL, NULL);
    purple_debug_set_ui_ops(&debug);
    for (attached = 0; attached < 2; ++attached) {
        for (split = 0; split < 2; ++split) {
            opening(OPEN ">", attached, FALSE, split);
            opening(OPEN " from=''>", attached, FALSE, split);
            opening(OPEN " xmlns:x='urn:fixture' x:from='Bob@200::2'>", attached, FALSE, split);
            opening(OPEN " from='Bob@200::2'>", attached, TRUE, split);
            opening(OPEN " xmlns:x='urn:fixture' x:from='unknown@200::3' from='Bob@200::2'>",
                    attached, TRUE, split);
        }
    }
    opening(OPEN " from='unknown@200::3'>", FALSE, FALSE, FALSE);
    purple_debug_set_ui_ops(NULL);
    g_free(matched_log);
    purple_core_quit();
    g_print("Barev C parser checks passed: %u\n", checks);
    return 0;
}
