/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <gmodule.h>
#include <libpurple/account.h>
#include <libpurple/blist.h>
#include <libpurple/core.h>
#include <libpurple/debug.h>
#include <libpurple/eventloop.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "barev.h"
#include "parser.h"

static unsigned checks, started, packets, matched, closed;
static PurpleAccount *account;
static PurpleBuddy *known, *other, *lower, *legacy;
static const char *peer_ip = "200::2", *local_ip = "200::1";
static gboolean peer_error, local_error;
static int peer_family = AF_INET6;
static void (*match_stream)(BonjourJabberConversation *);
#define CHECK(value) do { ++checks; if (!(value)) g_error("parser check %u failed (%s:%d)", checks, __FILE__, __LINE__); } while (0)
#define OPEN "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:client'"
#define VALID OPEN " from='Bob@200::2' to='fixture@200::1'>"

/* Only socket endpoints and UI/lifecycle effects are replaced. Contact matching,
 * endpoint verification, collision selection and XML parsing use production code. */
G_MODULE_EXPORT int getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    struct sockaddr_in6 value = {.sin6_family = peer_family};
    (void)fd;
    if (peer_error) return -1;
    CHECK(*length >= sizeof(value));
    CHECK(inet_pton(AF_INET6, peer_ip, &value.sin6_addr) == 1);
    memcpy(address, &value, sizeof(value)); *length = sizeof(value);
    return 0;
}

G_MODULE_EXPORT int getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    struct sockaddr_in6 value = {.sin6_family = AF_INET6};
    (void)fd;
    if (local_error) return -1;
    CHECK(*length >= sizeof(value));
    CHECK(inet_pton(AF_INET6, local_ip, &value.sin6_addr) == 1);
    memcpy(address, &value, sizeof(value)); *length = sizeof(value);
    return 0;
}

G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ (void)data; return -1; }

void bonjour_jabber_conv_match_by_name(BonjourJabberConversation *conversation)
{ ++matched; match_stream(conversation); }

const char *bonjour_jabber_get_local_jid(BonjourJabberConversation *conversation)
{ return ((BonjourData *)conversation->account->gc->proto_data)->jid; }

void bonjour_jabber_stream_started(BonjourJabberConversation *conversation)
{ CHECK(conversation->pb && conversation->recv_stream_start); ++started; }

void async_bonjour_jabber_close_conversation(BonjourJabberConversation *conversation)
{ CHECK(conversation->in_parser); conversation->close_timeout = 1; }

G_MODULE_EXPORT void bonjour_jabber_close_conversation(BonjourJabberConversation *conversation)
{ conversation->closing = TRUE; ++closed; }

void bonjour_jabber_process_packet(PurpleBuddy *buddy, xmlnode *packet)
{ CHECK(buddy && packet && !g_strcmp0(xmlnode_get_namespace(packet), "jabber:client")); ++packets; }

static PurpleBuddy *contact(const char *name, const char *saved_ip)
{
    PurpleBuddy *buddy = purple_buddy_new(account, name, NULL);
    BonjourBuddy *data = g_new0(BonjourBuddy, 1);
    purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    purple_buddy_set_protocol_data(buddy, data);
    if (saved_ip) {
        purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "barev_ip", saved_ip);
        data->ips = g_slist_prepend(NULL, g_strdup(saved_ip));
    }
    return buddy;
}

static void init(BonjourJabberConversation *conversation, gboolean incoming, PurpleBuddy *expected)
{
    memset(conversation, 0, sizeof(*conversation));
    conversation->socket = 1001;
    conversation->account = account;
    conversation->incoming = incoming;
    conversation->pb = expected;
    conversation->ip = g_strdup("200::2");
    conversation->sent_stream_start = STREAM_FULLY_SENT;
}

static void cleanup(BonjourJabberConversation *conversation)
{
    GSList *buddies = purple_find_buddies(account, NULL), *it;
    for (it = buddies; it; it = it->next) {
        BonjourBuddy *data = purple_buddy_get_protocol_data(it->data);
        if (data && data->conversation == conversation) data->conversation = NULL;
    }
    g_slist_free(buddies);
    bonjour_parser_destroy(conversation);
    g_free(conversation->ip); g_free(conversation->local_ip); g_free(conversation->buddy_name);
}

static void feed(BonjourJabberConversation *conversation, const char *text, unsigned mode)
{
    size_t length = strlen(text), at;
    if (mode == 1 && length) {
        bonjour_parser_process(conversation, text, length-1);
        bonjour_parser_process(conversation, text+length-1, 1);
    } else if (mode == 2) {
        for (at = 0; at < length; ++at) bonjour_parser_process(conversation, text+at, 1);
    } else bonjour_parser_process(conversation, text, length);
}

static void opening(const char *text, gboolean incoming, PurpleBuddy *expected,
                    PurpleBuddy *accepted, unsigned mode)
{
    BonjourJabberConversation conversation;
    unsigned old_started = started, old_packets = packets;
    init(&conversation, incoming, expected);
    feed(&conversation, text, mode);
    CHECK(!conversation.in_parser);
    CHECK((conversation.close_timeout == 0) == (accepted != NULL));
    if (accepted) {
        CHECK(conversation.recv_stream_start && conversation.pb == accepted);
        CHECK(started == old_started+1);
        CHECK(((BonjourBuddy *)purple_buddy_get_protocol_data(accepted))->conversation == &conversation);
    } else {
        CHECK(!conversation.recv_stream_start);
        feed(&conversation, "<message><body>must not be delivered</body></message>", mode);
        CHECK(started == old_started && packets == old_packets);
    }
    cleanup(&conversation);
}

static void headers(void)
{
    static const char *bad[] = {
        OPEN ">", OPEN " from=''>", OPEN " xmlns:x='urn:test' x:from='Bob@200::2'>",
        OPEN " from='Bob@200::3'>", OPEN " from='mallory@200::2'>",
        OPEN " from='Bob@::1'>", OPEN " from='Bob@200::2/resource'>",
        OPEN " from='Bob@200::2%eth0'>", OPEN " from='Bob@example.invalid'>",
        OPEN " from='Bob@200::2' to='other@200::1'>",
        OPEN " from='Bob@200::2' to='fixture@200::9'>",
        OPEN " from='Bob@200::2' to=''>", OPEN " from='Bob@200::2' version='9.9'>",
        OPEN " from='Bob@200::2' version=''>",
        OPEN " from='Bob@200::2' from='Bob@200::2'>",
        OPEN " from='Bob@200::2'/>",
        "<s:stream xmlns:s='wrong' from='Bob@200::2'>",
        "<stream from='Bob@200::2'>", "<message from='Bob@200::2'>",
        "<!DOCTYPE stream [<!ENTITY x SYSTEM 'file:///fixture'>]><stream>",
        "<!DOCTYPE s:stream>" VALID,
        "<?xml version='1.1'?>" VALID,
        "<?xml version='1.0' encoding='ISO-8859-1'?>" VALID,
        OPEN " from='Bad Nick@200::2'>", OPEN " from='Bob@200::2' to='fixture@::1'>"
    };
    unsigned incoming, mode, i;
    for (incoming = 0; incoming < 2; ++incoming) {
        for (mode = 0; mode < 3; ++mode) {
            PurpleBuddy *expected = incoming ? NULL : known;
            for (i = 0; i < G_N_ELEMENTS(bad); ++i) opening(bad[i], incoming, expected, NULL, mode);
            opening(VALID, incoming, expected, known, mode);
            opening("<?xml version='1.0' encoding='UTF-8'?>" VALID, incoming, expected, known, mode);
            opening(OPEN " from='Bob@0200:0:0:0:0:0:0:2' version='1.0'>", incoming, expected, known, mode);
            opening(OPEN " from='Bob@AI-I.BAREV.V6.ALT.' to='fixture@ai-e.barev.v6.alt'>",
                    incoming, expected, known, mode);
            opening(OPEN " from='Bob@200::2' xmlns:x='urn:test' x:from='bad' x:to='bad' x:version='9.9'>",
                    incoming, expected, known, mode);
            opening(OPEN " from='Other@200::2'>", incoming, expected, incoming ? other : NULL, mode);
            opening(OPEN " from='bob@200::2'>", incoming, expected, incoming ? lower : NULL, mode);
            opening(OPEN " from='Legacy@200::2'>", incoming, incoming ? NULL : legacy, legacy, mode);
            opening(OPEN " from='Unstored@200::2'>", incoming, expected, NULL, mode);
        }
    }
    peer_ip = "200::3"; opening(VALID, TRUE, NULL, NULL, 0); peer_ip = "200::2";
    local_ip = "200::9"; opening(VALID, TRUE, NULL, NULL, 0); local_ip = "200::1";
    peer_error = TRUE; opening(VALID, TRUE, NULL, NULL, 0); peer_error = FALSE;
    local_error = TRUE; opening(VALID, TRUE, NULL, NULL, 0); local_error = FALSE;
    peer_family = AF_INET; opening(VALID, TRUE, NULL, NULL, 0); peer_family = AF_INET6;
}

static void stanza(const char *text, gboolean rejected, unsigned delivered)
{
    BonjourJabberConversation conversation;
    unsigned old_packets, mode;
    for (mode = 0; mode < 3; ++mode) {
        init(&conversation, FALSE, known); feed(&conversation, VALID, mode);
        CHECK(!conversation.close_timeout);
        old_packets = packets;
        feed(&conversation, text, mode);
        CHECK((conversation.close_timeout != 0) == rejected);
        CHECK(packets == old_packets+delivered);
        if (rejected) {
            feed(&conversation, "<message><body>late</body></message>", mode);
            CHECK(packets == old_packets+delivered);
        }
        cleanup(&conversation);
    }
}

static void stanzas(void)
{
    stanza("<message><body>ok</body></message>", FALSE, 1);
    stanza("<presence from='Bob@200::2' to='fixture@200::1'/>", FALSE, 1);
    stanza("<presence from='Bob@AI-I.BAREV.V6.ALT.' to='fixture@0200::1'/>", FALSE, 1);
    stanza("<presence from='Other@200::2'/>", TRUE, 0);
    stanza("<presence from='Bob@200::3'/>", TRUE, 0);
    stanza("<presence from='bob@200::2'/>", TRUE, 0);
    stanza("<presence from=''/>", TRUE, 0);
    stanza("<presence to='other@200::1'/>", TRUE, 0);
    stanza("<presence to='fixture@200::9'/>", TRUE, 0);
    stanza("<presence xmlns='urn:test'/>", FALSE, 0);
    stanza("<s:features/>", FALSE, 0);
    stanza("<s:error/>", TRUE, 0);
    stanza("</s:stream>", TRUE, 0);
    stanza("<s:stream from='Bob@200::2'>", TRUE, 0);
    stanza("<message><x/></wrong>", TRUE, 0);
    stanza("<message><body><![CDATA[<hello>]]></body></message>", FALSE, 1);
    stanza("<iq><vCard xmlns='vcard-temp'/></iq>", FALSE, 1);
    stanza("<presence type='unavailable'/>", TRUE, 1);
    stanza("<message><stream xmlns='urn:test'/></message>", FALSE, 1);
}

static void selection(void)
{
    BonjourJabberConversation first, duplicate;
    BonjourBuddy *data = purple_buddy_get_protocol_data(known);
    BonjourData *own = account->gc->proto_data;
    unsigned old_closed;
    init(&first, FALSE, known); feed(&first, VALID, 0);
    init(&duplicate, TRUE, NULL); feed(&duplicate, VALID, 0);
    CHECK(duplicate.close_timeout && data->conversation == &first && !first.closing);
    cleanup(&duplicate); cleanup(&first);

    init(&first, TRUE, known); first.sent_stream_start = STREAM_NOT_SENT;
    data->conversation = &first;
    init(&duplicate, TRUE, NULL); feed(&duplicate, VALID, 0);
    CHECK(duplicate.close_timeout && data->conversation == &first && !first.closing);
    cleanup(&duplicate); cleanup(&first);

    g_free(own->jid); own->jid = g_strdup("alice@200::1");
    init(&first, FALSE, known); first.sent_stream_start = STREAM_NOT_SENT;
    data->conversation = &first;
    init(&duplicate, TRUE, NULL); feed(&duplicate, OPEN " from='Bob@200::2'>", 0);
    CHECK(duplicate.close_timeout && data->conversation == &first && !first.closing);
    cleanup(&duplicate); cleanup(&first);

    g_free(own->jid); own->jid = g_strdup("zoe@200::1");
    init(&first, FALSE, known); first.sent_stream_start = STREAM_NOT_SENT;
    data->conversation = &first; old_closed = closed;
    init(&duplicate, TRUE, NULL);
    feed(&duplicate, OPEN " from='Bob@200::2' to='zoe@200::1'>", 0);
    CHECK(!duplicate.close_timeout && data->conversation == &duplicate && first.closing);
    CHECK(closed == old_closed+1);
    cleanup(&first); CHECK(data->conversation == &duplicate); cleanup(&duplicate);

    /* Case-only nicknames still select the same direction at both ends. */
    local_ip = "200::2";
    g_free(own->jid); own->jid = g_strdup("Bob@200::2");
    init(&first, FALSE, lower); first.sent_stream_start = STREAM_NOT_SENT;
    ((BonjourBuddy *)purple_buddy_get_protocol_data(lower))->conversation = &first;
    init(&duplicate, TRUE, NULL); feed(&duplicate, OPEN " from='bob@200::2'>", 0);
    CHECK(duplicate.close_timeout && !first.closing);
    cleanup(&duplicate); cleanup(&first);
    g_free(own->jid); own->jid = g_strdup("bob@200::2");
    init(&first, FALSE, known); first.sent_stream_start = STREAM_NOT_SENT;
    data->conversation = &first;
    init(&duplicate, TRUE, NULL); feed(&duplicate, OPEN " from='Bob@200::2'>", 0);
    CHECK(!duplicate.close_timeout && first.closing && data->conversation == &duplicate);
    cleanup(&first); cleanup(&duplicate);
    local_ip = "200::1";
    g_free(own->jid); own->jid = g_strdup("fixture@200::1");
}

static void bounds(void)
{
    BonjourJabberConversation conversation;
    char *text = g_malloc0(20000);
    unsigned old_packets, i;
    size_t padding = 4096-strlen(VALID);
    memset(text, ' ', padding); memcpy(text+padding, VALID, strlen(VALID)+1);
    opening(text, TRUE, NULL, known, 0);
    memset(text, ' ', padding+1); memcpy(text+padding+1, VALID, strlen(VALID)+1);
    opening(text, TRUE, NULL, NULL, 0);
    memset(text, 0, 20000);
    memset(text, ' ', 4097);
    init(&conversation, TRUE, NULL); feed(&conversation, text, 2);
    CHECK(conversation.close_timeout); cleanup(&conversation);

    init(&conversation, TRUE, NULL);
    bonjour_parser_process(&conversation, "\xff\xfe<\0s\0", 6);
    CHECK(conversation.close_timeout); cleanup(&conversation);
    memset(text, ' ', 16385);
    init(&conversation, TRUE, NULL); bonjour_parser_process(&conversation, text, 16385);
    CHECK(conversation.close_timeout); cleanup(&conversation);

    init(&conversation, FALSE, known); feed(&conversation, VALID, 0); old_packets = packets;
    feed(&conversation, "<message large='", 0);
    memset(text, 'x', 16384);
    for (i = 0; i < 33 && !conversation.close_timeout; ++i)
        bonjour_parser_process(&conversation, text, 16384);
    CHECK(conversation.close_timeout && packets == old_packets); cleanup(&conversation);

    memset(text, 0, 20000); memcpy(text, "<message>", 9);
    for (i = 0; i < 513; ++i) memcpy(text+9+4*i, "<x/>", 4);
    memcpy(text+9+4*i, "</message>", 11);
    stanza(text, TRUE, 0);

    memset(text, 0, 20000);
    for (i = 0; i < 65; ++i) memcpy(text+11*i, "<presence/>", 11);
    init(&conversation, FALSE, known); feed(&conversation, VALID, 0); old_packets = packets;
    feed(&conversation, text, 0);
    CHECK(conversation.close_timeout && packets == old_packets+64); cleanup(&conversation);
    g_free(text);
    stanza("<message><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a><a>", TRUE, 0);

    for (i = 0; i < 2; ++i) {
        const char *prefix = "<message><body>", *suffix = "</body></message>";
        size_t size = 524288+i, at, payload = size-strlen(prefix)-strlen(suffix);
        text = g_malloc0(size+1);
        memcpy(text, prefix, strlen(prefix));
        memset(text+strlen(prefix), 'x', payload);
        memcpy(text+strlen(prefix)+payload, suffix, strlen(suffix));
        init(&conversation, FALSE, known); feed(&conversation, VALID, 0); old_packets = packets;
        for (at = 0; at < size && !conversation.close_timeout; at += 4096)
            bonjour_parser_process(&conversation, text+at, MIN((size_t)4096, size-at));
        if ((conversation.close_timeout != 0) != (i != 0))
            g_print("frame boundary: size=%zu received=%" G_GUINT64_FORMAT " end=%" G_GUINT64_FORMAT " nodes=%u delivered=%u\n",
                    size, conversation.received_bytes, conversation.frame_end, conversation.stanza_nodes, packets-old_packets);
        CHECK((conversation.close_timeout != 0) == (i != 0));
        CHECK(packets == old_packets+(i == 0 ? 1 : 0));
        cleanup(&conversation); g_free(text);
    }
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
                                   .timeout_add_seconds = g_timeout_add_seconds};
    PurplePlugin *plugin;
    BonjourData *data;
    GModule *module;
    gpointer symbol;
    if (argc != 3) return 2;
    purple_util_set_user_dir(argv[1]); purple_eventloop_set_ui_ops(&events);
    CHECK(purple_core_init("barev-parser-test")); purple_set_blist(purple_blist_new());
    plugin = purple_plugins_find_with_id("prpl-barev");
    if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]);
    CHECK(plugin && !plugin->unloadable && purple_plugin_load(plugin));
    purple_plugins_probe("barev-test-no-scan");
    module = g_module_open(argv[2], G_MODULE_BIND_LAZY);
    CHECK(module && g_module_symbol(module, "bonjour_jabber_conv_match_by_name", &symbol));
    memcpy(&match_stream, &symbol, sizeof(match_stream));
    account = purple_account_new("fixture", "prpl-barev"); purple_accounts_add(account);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    CHECK(account->gc && !account->gc->proto_data);
    data = g_new0(BonjourData, 1); data->jid = g_strdup("fixture@200::1");
    data->jabber_data = g_new0(BonjourJabber, 1); data->jabber_data->account = account;
    purple_connection_set_protocol_data(account->gc, data);
    known = contact("Bob@200::2", "200::2"); other = contact("Other@200::2", "200::2");
    lower = contact("bob@200::2", "200::2"); legacy = contact("Legacy", "200::2");
    contact("Unstored", NULL); contact("Bob@200::3", "200::3");
    headers(); stanzas(); selection(); bounds();
    CHECK(matched > 0);
    /* Process teardown independently of synthetic socket descriptors. */
    purple_connection_set_protocol_data(account->gc, NULL);
    g_free(data->jid); g_free(data->jabber_data); g_free(data);
    g_module_close(module);
    purple_core_quit();
    g_print("Barev C parser and stream checks passed: %u\n", checks);
    return 0;
}
