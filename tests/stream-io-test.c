/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <gmodule.h>
#include <libpurple/core.h>
#include <libpurple/eventloop.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "barev.h"

#define CHECK(value) do { ++checks; if (!(value)) g_error("stream I/O check %u failed (%s:%d)", checks, __FILE__, __LINE__); } while (0)
#define OPEN "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:client'"
static unsigned checks;
static const char *peer_ip = "200::2", *local_ip = "200::1";
static int peer_socket = -1;
static gboolean connect_error;
static PurpleAccount *account;
static BonjourJabber *jabber;
static PurpleBuddy *buddy;
static guint next_source;
static struct {
    gboolean active;
    guint interval;
    GSourceFunc timeout;
    PurpleInputFunction input;
    gpointer data;
    int fd;
} sources[512];

/* Private Unix socket pairs exercise actual buffered sends and receives without
 * listeners, routing or a Yggdrasil interface. Endpoint queries model IPv6. */
G_MODULE_EXPORT int socket(int domain, int type, int protocol)
{
    int pair[2];
    (void)domain; (void)type; (void)protocol;
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    if (peer_socket >= 0) close(peer_socket);
    peer_socket = pair[1];
    return pair[0];
}

G_MODULE_EXPORT int bind(int fd, const struct sockaddr *address, socklen_t length)
{ (void)fd; (void)address; (void)length; return 0; }
G_MODULE_EXPORT int listen(int fd, int count)
{ (void)fd; (void)count; return 0; }
G_MODULE_EXPORT int setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{ (void)fd; (void)level; (void)option; (void)value; (void)length; return 0; }
G_MODULE_EXPORT int connect(int fd, const struct sockaddr *address, socklen_t length)
{ (void)fd; (void)address; (void)length; if (connect_error) { errno = ECONNREFUSED; return -1; } return 0; }

G_MODULE_EXPORT int getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    struct sockaddr_in6 value = {.sin6_family = AF_INET6, .sin6_port = htons(1337)};
    (void)fd;
    CHECK(*length >= sizeof(value) && inet_pton(AF_INET6, peer_ip, &value.sin6_addr) == 1);
    memcpy(address, &value, sizeof(value)); *length = sizeof(value);
    return 0;
}

G_MODULE_EXPORT int getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    struct sockaddr_in6 value = {.sin6_family = AF_INET6, .sin6_port = htons(1337)};
    (void)fd;
    CHECK(*length >= sizeof(value) && inet_pton(AF_INET6, local_ip, &value.sin6_addr) == 1);
    memcpy(address, &value, sizeof(value)); *length = sizeof(value);
    return 0;
}

G_MODULE_EXPORT int accept(int fd, struct sockaddr *address, socklen_t *length)
{
    int result = socket(AF_INET6, SOCK_STREAM, 0);
    (void)fd;
    getpeername(result, address, length);
    return result;
}

G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ (void)data; return -1; }

static guint timeout_add(guint interval, GSourceFunc function, gpointer data)
{
    guint id = ++next_source;
    CHECK(id < G_N_ELEMENTS(sources));
    sources[id].active = TRUE; sources[id].interval = interval;
    sources[id].timeout = function; sources[id].data = data;
    return id;
}

static guint seconds_add(guint interval, GSourceFunc function, gpointer data)
{ return timeout_add(interval*1000, function, data); }

static gboolean source_remove(guint id)
{ CHECK(id < G_N_ELEMENTS(sources)); sources[id].active = FALSE; return TRUE; }

static guint input_add(int fd, PurpleInputCondition condition, PurpleInputFunction function, gpointer data)
{
    guint id = ++next_source;
    (void)condition;
    CHECK(id < G_N_ELEMENTS(sources));
    sources[id].active = TRUE; sources[id].fd = fd;
    sources[id].input = function; sources[id].data = data;
    return id;
}

static gboolean run_timer(guint id)
{
    gboolean keep;
    CHECK(sources[id].active && sources[id].timeout);
    keep = sources[id].timeout(sources[id].data);
    if (!keep) sources[id].active = FALSE;
    return keep;
}

static void receive(BonjourJabberConversation *conversation, const char *text)
{
    guint source = conversation->rx_handler;
    CHECK(source && sources[source].active);
    CHECK(send(peer_socket, text, strlen(text), 0) == (ssize_t)strlen(text));
    sources[source].input(sources[source].data, sources[source].fd, PURPLE_INPUT_READ);
}

static BonjourJabberConversation *incoming(void)
{
    guint source = jabber->watcher_id6;
    sources[source].input(sources[source].data, sources[source].fd, PURPLE_INPUT_READ);
    return jabber->pending_conversations ? jabber->pending_conversations->data : NULL;
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = timeout_add, .timeout_remove = source_remove,
        .timeout_add_seconds = seconds_add, .input_add = input_add, .input_remove = source_remove};
    PurplePlugin *plugin;
    BonjourData *data;
    BonjourBuddy *bb;
    GModule *module;
    gpointer symbol;
    gint (*start)(BonjourJabber *);
    int (*open_stream)(BonjourJabber *, const char *);
    void (*close_stream)(BonjourJabberConversation *);
    void (*stop)(BonjourJabber *);
    BonjourJabberConversation *conversation, *pending[4], *all[64];
    guint timer;
    unsigned i;
    char wire[8192];
    ssize_t length;
    if (argc != 3) return 2;
    purple_util_set_user_dir(argv[1]); purple_eventloop_set_ui_ops(&events);
    CHECK(purple_core_init("barev-stream-io-test")); purple_set_blist(purple_blist_new());
    plugin = purple_plugins_find_with_id("prpl-barev");
    if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]);
    CHECK(plugin && !plugin->unloadable && purple_plugin_load(plugin));
    purple_plugins_probe("barev-test-no-scan");
    module = g_module_open(argv[2], G_MODULE_BIND_LAZY);
    CHECK(module && g_module_symbol(module, "bonjour_jabber_start", &symbol)); memcpy(&start, &symbol, sizeof(start));
    CHECK(g_module_symbol(module, "bonjour_jabber_open_stream", &symbol)); memcpy(&open_stream, &symbol, sizeof(open_stream));
    CHECK(g_module_symbol(module, "bonjour_jabber_close_conversation", &symbol)); memcpy(&close_stream, &symbol, sizeof(close_stream));
    CHECK(g_module_symbol(module, "bonjour_jabber_stop", &symbol)); memcpy(&stop, &symbol, sizeof(stop));
    account = purple_account_new("fi&xture", "prpl-barev"); purple_accounts_add(account);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    CHECK(account->gc && !account->gc->proto_data);
    data = g_new0(BonjourData, 1); data->jid = g_strdup("fi&xture@200::1");
    jabber = g_new0(BonjourJabber, 1); jabber->account = account; jabber->port = 1337;
    data->jabber_data = jabber; purple_connection_set_protocol_data(account->gc, data);
    buddy = purple_buddy_new(account, "B&b@200::2", NULL); purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    bb = g_new0(BonjourBuddy, 1); bb->name = g_strdup("B&b@200::2");
    bb->ips = g_slist_prepend(NULL, g_strdup("200::2")); bb->port_p2pj = 1337;
    purple_buddy_set_protocol_data(buddy, bb);
    CHECK(start(jabber) == 1337);

    peer_ip = "200::9"; CHECK(!incoming()); CHECK(!jabber->pending_conversations);
    peer_ip = "::1"; CHECK(!incoming()); CHECK(!jabber->pending_conversations);
    peer_ip = "200::2";
    local_ip = "200::9"; CHECK(!incoming()); CHECK(!jabber->pending_conversations); local_ip = "200::1";
    for (i = 0; i < 4; ++i) { pending[i] = incoming(); CHECK(pending[i] != NULL); }
    CHECK(incoming() == pending[3]); CHECK(g_slist_length(jabber->pending_conversations) == 4);
    CHECK(!open_stream(jabber, "B&b@200::2") && !bb->conversation);
    for (i = 0; i < 4; ++i) close_stream(pending[i]);
    CHECK(!jabber->pending_conversations);

    for (i = 0; i < 17; ++i) {
        char *ip = g_strdup_printf("200::%x", 16+i);
        char *name = g_strdup_printf("limit@%s", ip);
        PurpleBuddy *entry = purple_buddy_new(account, name, NULL);
        BonjourBuddy *state = g_new0(BonjourBuddy, 1);
        unsigned j;
        purple_blist_add_buddy(entry, NULL, NULL, NULL);
        purple_buddy_set_protocol_data(entry, state);
        peer_ip = ip;
        if (i < 16) {
            for (j = 0; j < 4; ++j) { all[4*i+j] = incoming(); CHECK(all[4*i+j] != NULL); }
        } else CHECK(incoming() == all[63]);
        g_free(name); g_free(ip);
    }
    CHECK(g_slist_length(jabber->pending_conversations) == 64);
    peer_ip = "200::2";
    for (i = 0; i < 64; ++i) close_stream(all[i]);
    CHECK(!jabber->pending_conversations);

    conversation = incoming(); CHECK(conversation != NULL);
    timer = conversation->frame_timer; CHECK(sources[timer].interval == 1000);
    conversation->frame_started = g_get_monotonic_time()-29*G_USEC_PER_SEC; CHECK(run_timer(timer));
    conversation->frame_started = g_get_monotonic_time()-30*G_USEC_PER_SEC; CHECK(!run_timer(timer));
    CHECK(!jabber->pending_conversations);

    conversation = incoming(); CHECK(conversation != NULL);
    receive(conversation, OPEN " from='B&amp;b@200::2' to='fi&amp;xture@200::1'>");
    CHECK(conversation->recv_stream_start && conversation->sent_stream_start == STREAM_FULLY_SENT);
    CHECK(bb->conversation == conversation);
    length = recv(peer_socket, wire, sizeof(wire)-1, 0); CHECK(length > 0); wire[length] = 0;
    CHECK(strstr(wire, "from=\"fi&amp;xture@200::1\"") && strstr(wire, "to=\"B&amp;b@200::2\""));
    timer = conversation->frame_timer;
    conversation->frame_started = g_get_monotonic_time()-119*G_USEC_PER_SEC; CHECK(run_timer(timer));
    conversation->frame_started = g_get_monotonic_time()-120*G_USEC_PER_SEC; CHECK(!run_timer(timer)); CHECK(!bb->conversation);

    CHECK(open_stream(jabber, "B&b@200::2") == 1);
    conversation = bb->conversation; CHECK(conversation && conversation->connect_handler);
    {
        guint source = conversation->connect_handler;
        sources[source].input(sources[source].data, sources[source].fd, PURPLE_INPUT_WRITE);
    }
    CHECK(conversation->sent_stream_start == STREAM_FULLY_SENT && !conversation->recv_stream_start);
    length = recv(peer_socket, wire, sizeof(wire)-1, 0); CHECK(length > 0); wire[length] = 0;
    CHECK(strstr(wire, "from=\"fi&amp;xture@200::1\"") && strstr(wire, "to=\"B&amp;b@200::2\""));
    receive(conversation, OPEN " from='B&amp;b@0200::2' to='fi&amp;xture@200::1'>");
    CHECK(conversation->recv_stream_start && !conversation->close_timeout);
    receive(conversation, "<presence from='Other@200::2'/>");
    CHECK(conversation->close_timeout);
    CHECK(!run_timer(conversation->close_timeout)); CHECK(!bb->conversation);

    stop(jabber);
    if (peer_socket >= 0) close(peer_socket);
    purple_connection_set_protocol_data(account->gc, NULL);
    g_free(data->jid); g_free(jabber); g_free(data);
    g_module_close(module); purple_core_quit();
    g_print("Barev C stream I/O checks passed: %u\n", checks);
    return 0;
}
