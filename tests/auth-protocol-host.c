/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib-unix.h>
#include <gmodule.h>
#include <libpurple/core.h>
#include <libpurple/eventloop.h>
#include <libpurple/imgstore.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "barev.h"

static int peer_fd;
static GMainLoop *loop;
static PurpleBuddy *buddy;
static PurpleInputFunction accept_ready;
static gpointer accept_data;
static int accept_fd;
static gboolean dialing;
static size_t (*certificate)(const BarevTLS *, unsigned char *, size_t);
static int (*security)(void *, const char *, char[72]);

static void message_received(PurpleAccount *account, const char *sender, const char *message,
    PurpleConversation *conversation, PurpleMessageFlags flags, gpointer data)
{
    char *encoded = g_base64_encode((const guchar *)message, strlen(message));
    (void)account; (void)sender; (void)conversation; (void)flags; (void)data;
    printf("MESSAGE %s\n", encoded); g_free(encoded);
    {
        const char *at = message, *start, *end;
        GData *attributes;
        while (purple_markup_find_tag("img", at, &start, &end, &attributes)) {
            const char *value = g_datalist_get_data(&attributes, "id");
            PurpleStoredImage *image = value ? purple_imgstore_find_by_id(atoi(value)) : NULL;
            if (image) {
                encoded = g_base64_encode(purple_imgstore_get_data(image), purple_imgstore_get_size(image));
                printf("IMAGE %s\n", encoded); g_free(encoded);
            }
            g_datalist_clear(&attributes); at = end+1;
        }
    }
}

G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ (void)data; return -1; }

G_MODULE_EXPORT void purple_connection_error_reason(PurpleConnection *connection,
    PurpleConnectionError reason, const char *description)
{ (void)connection; (void)reason; (void)description; }

G_MODULE_EXPORT int socket(int domain, int type, int protocol)
{
    int pair[2];
    (void)domain; (void)type; (void)protocol;
    if (dialing) return peer_fd;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return -1;
    close(pair[1]); return pair[0];
}
G_MODULE_EXPORT int bind(int fd, const struct sockaddr *address, socklen_t length)
{ (void)fd; (void)address; (void)length; return 0; }
G_MODULE_EXPORT int listen(int fd, int backlog)
{ (void)fd; (void)backlog; return 0; }
G_MODULE_EXPORT int setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{ (void)fd; (void)level; (void)option; (void)value; (void)length; return 0; }
G_MODULE_EXPORT int connect(int fd, const struct sockaddr *address, socklen_t length)
{ (void)address; (void)length; if (dialing && fd == peer_fd) return 0; errno = ECONNREFUSED; return -1; }

G_MODULE_EXPORT int getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    struct sockaddr_in6 value = {.sin6_family = AF_INET6, .sin6_port = htons(1337)};
    (void)fd;
    if (*length < sizeof(value)) return -1;
    inet_pton(AF_INET6, "200::2", &value.sin6_addr);
    memcpy(address, &value, sizeof(value)); *length = sizeof(value); return 0;
}
G_MODULE_EXPORT int getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    if (getpeername(fd, address, length)) return -1;
    inet_pton(AF_INET6, "200::1", &((struct sockaddr_in6 *)address)->sin6_addr); return 0;
}
G_MODULE_EXPORT int accept(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    if (peer_fd < 0) { errno = EAGAIN; return -1; }
    getpeername(peer_fd, address, length);
    return peer_fd;
}

typedef struct { PurpleInputFunction function; gpointer data; } Watch;
static gboolean input_ready(gint fd, GIOCondition condition, gpointer data)
{
    Watch *watch = data;
    PurpleInputCondition flags = 0;
    if (condition & (G_IO_IN | G_IO_HUP | G_IO_ERR)) flags |= PURPLE_INPUT_READ;
    if (condition & (G_IO_OUT | G_IO_HUP | G_IO_ERR)) flags |= PURPLE_INPUT_WRITE;
    watch->function(watch->data, fd, flags); return G_SOURCE_CONTINUE;
}
static gboolean dormant(gpointer data) { (void)data; return G_SOURCE_CONTINUE; }
static guint input_add(int fd, PurpleInputCondition condition, PurpleInputFunction function, gpointer data)
{
    Watch *watch;
    if (fd != peer_fd) {
        accept_ready = function; accept_data = data; accept_fd = fd;
        return g_timeout_add_seconds(3600, dormant, NULL);
    }
    watch = g_new0(Watch, 1); watch->function = function; watch->data = data;
    return g_unix_fd_add_full(G_PRIORITY_DEFAULT, fd,
        (condition & PURPLE_INPUT_READ ? G_IO_IN : 0) | (condition & PURPLE_INPUT_WRITE ? G_IO_OUT : 0),
        input_ready, watch, g_free);
}

static gboolean command(gint fd, GIOCondition condition, gpointer data)
{
    char line[8192];
    BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);
    BonjourJabberConversation *conversation = bb ? bb->conversation : NULL;
    (void)fd; (void)condition; (void)data;
    if (!fgets(line, sizeof(line), stdin) || !strcmp(line, "quit\n")) { g_main_loop_quit(loop); return G_SOURCE_CONTINUE; }
    if (!strcmp(line, "tls-cert\n")) {
        unsigned char bytes[4096]; size_t i, length = conversation ? certificate(conversation->tls, bytes, sizeof(bytes)) : 0;
        printf("CERT "); for (i = 0; i < length; ++i) printf("%02x", bytes[i]); putchar('\n');
    } else if (!strcmp(line, "security\n")) {
        char fingerprint[72];
        int state = security(purple_buddy_get_account(buddy), purple_buddy_get_name(buddy), fingerprint);
        printf("SECURITY %d %s\n", state, fingerprint);
    } else if (!strcmp(line, "state\n")) printf("STATE %d %d\n", conversation && conversation->ready_notified, conversation != NULL);
    else if (!strcmp(line, "expire\n")) {
        if (conversation) conversation->auth_started -= 31*G_USEC_PER_SEC;
        puts("EXPIRED");
    }
    else if (g_str_has_prefix(line, "send ")) {
        gsize length;
        guchar *decoded = g_base64_decode(line+5, &length);
        char *message = g_strndup((char *)decoded, length);
        int result = serv_send_im(purple_account_get_connection(purple_buddy_get_account(buddy)),
            purple_buddy_get_name(buddy), message, PURPLE_MESSAGE_SEND);
        printf("SENT %d\n", result); g_free(message); g_free(decoded);
    }
    else if (!strcmp(line, "image-send-conversation\n")) {
        PurpleAccount *account = purple_buddy_get_account(buddy);
        char *path = g_build_filename(purple_user_dir(), "image-input.png", NULL), *bytes = NULL;
        gsize size;
        if (g_file_get_contents(path, &bytes, &size, NULL)) {
            int id = purple_imgstore_add_with_id(bytes, size, "image-input.png");
            char *markup = g_strdup_printf("<img id=\"%d\"/>", id);
            PurpleConversation *conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, purple_buddy_get_name(buddy));
            purple_conv_im_send_with_flags(PURPLE_CONV_IM(conv), markup, PURPLE_MESSAGE_IMAGES);
            g_free(markup); purple_imgstore_unref_by_id(id);
        }
        g_free(path); puts("IMAGE-SENT 0");
    }
    return G_SOURCE_CONTINUE;
}

#define LOAD(name, target) do { gpointer symbol; if (!g_module_symbol(module, name, &symbol)) return 6; memcpy(&(target), &symbol, sizeof(target)); } while (0)

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
        .timeout_add_seconds = g_timeout_add_seconds, .input_add = input_add, .input_remove = g_source_remove};
    PurplePlugin *plugin; PurpleAccount *account; BonjourData *data; BonjourBuddy *bb;
    GModule *module; guint stdin_source;
    gint (*start)(BonjourJabber *);
    int (*identity)(const char *, const char *, const char *, BarevIdentity *);
    void (*stop)(BonjourJabber *);
    int (*open_stream)(BonjourJabber *, const char *);
    BarevImages *(*new_images)(PurpleAccount *);
    if (argc != 4 && argc != 5) return 2;
    setvbuf(stdin, NULL, _IONBF, 0); setvbuf(stdout, NULL, _IONBF, 0);
    peer_fd = atoi(argv[3]);
    purple_util_set_user_dir(argv[1]); purple_eventloop_set_ui_ops(&events);
    if (!purple_core_init(g_getenv("BAREV_TEST_CORE_UI") ? g_getenv("BAREV_TEST_CORE_UI") : "barev-auth-protocol")) return 3;
    purple_set_blist(purple_blist_new());
    plugin = purple_plugins_find_with_id("prpl-barev"); if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]); if (!plugin || !purple_plugin_load(plugin)) return 4;
    purple_plugins_probe("barev-test-no-scan");
    module = g_module_open(argv[2], G_MODULE_BIND_LOCAL); if (!module) return 5;
    LOAD("bonjour_jabber_start", start); LOAD("bonjour_jabber_stop", stop);
    LOAD("bonjour_jabber_open_stream", open_stream);
    LOAD("barev_identity_open", identity); LOAD("barev_tls_certificate", certificate);
    LOAD("bonjour_jabber_security", security);
    LOAD("barev_images_new", new_images);
    account = purple_account_new("alice", "prpl-barev"); purple_accounts_add(account);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    if (!account->gc || account->gc->proto_data) return 7;
    data = g_new0(BonjourData, 1); data->jid = g_strdup("alice@200::1");
    {
        char *profile = strstr(purple_core_get_ui(), "haze") ? g_build_filename(g_get_home_dir(), ".purple", NULL) : g_strdup(argv[1]);
        int result = identity(profile, "alice", "", &data->identity);
        g_free(profile); if (result) return 8;
    }
    data->jabber_data = g_new0(BonjourJabber, 1); data->jabber_data->account = account; data->jabber_data->port = 1337;
    purple_connection_set_protocol_data(account->gc, data);
    if (g_getenv("BAREV_TEST_IMAGE_BOB"))
        purple_account_set_int(account, "image_bob_kib", atoi(g_getenv("BAREV_TEST_IMAGE_BOB")));
    data->images = new_images(account);
    account->gc->flags &= ~PURPLE_CONNECTION_NO_IMAGES;
    purple_connection_set_state(account->gc, PURPLE_CONNECTED);
    buddy = purple_buddy_new(account, "bob@200::2", NULL); purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    bb = g_new0(BonjourBuddy, 1); bb->name = g_strdup("bob@200::2");
    bb->ips = g_slist_prepend(NULL, g_strdup("200::2")); bb->port_p2pj = 1337;
    purple_buddy_set_protocol_data(buddy, bb);
    purple_signal_connect(purple_conversations_get_handle(), "received-im-msg", &loop,
        PURPLE_CALLBACK(message_received), NULL);
    if (start(data->jabber_data) != 1337 || !accept_ready) return 9;
    if (argc == 5 && !strcmp(argv[4], "client")) {
        dialing = TRUE;
        if (!open_stream(data->jabber_data, "bob@200::2")) return 10;
        dialing = FALSE;
    } else accept_ready(accept_data, accept_fd, PURPLE_INPUT_READ);
    loop = g_main_loop_new(NULL, FALSE);
    stdin_source = g_unix_fd_add(STDIN_FILENO, G_IO_IN | G_IO_HUP, command, NULL);
    puts("READY 0"); g_main_loop_run(loop);
    g_source_remove(stdin_source); stop(data->jabber_data);
    purple_signals_disconnect_by_handle(&loop);
    purple_account_disconnect(account); purple_core_quit(); g_main_loop_unref(loop);
    g_module_close(module); puts("CLEAN"); return 0;
}
