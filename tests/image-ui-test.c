/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <gmodule.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <libpurple/core.h>
#include <libpurple/connection.h>
#include <libpurple/eventloop.h>
#include <libpurple/imgstore.h>
#include <libpurple/plugin.h>
#include <libpurple/request.h>
#include <libpurple/util.h>
#include "image-ui.h"
#include "jabber.h"

static unsigned checks, sent, prompts;
static BarevImageUI *ui;
static gboolean close_on_new, synchronous;
static PurpleRequestActionCb choices[3];
static gpointer argument;
static int request_handle;
static guchar *last_bytes;
static size_t last_size;
#define CHECK(value) do { ++checks; if (!(value)) g_error("image UI check %u failed", checks); } while (0)

G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ (void)data; return -1; }

static int send_image(gpointer owner, const char *who, const guchar *bytes, size_t size, const char *name)
{
    (void)owner; (void)who; (void)name;
    ++sent; g_free(last_bytes); last_bytes = g_malloc(size); memcpy(last_bytes, bytes, size); last_size = size; return sent;
}
static gboolean accept_image(gpointer owner, const char *who, int token, gboolean yes)
{ (void)owner; (void)who; (void)token; (void)yes; return TRUE; }
static void cancel_image(gpointer owner, const char *who, int token)
{ (void)owner; (void)who; (void)token; }
static void new_xfer(PurpleXfer *xfer)
{
    (void)xfer;
    if (close_on_new) { close_on_new = FALSE; BarevImageUI_Close(ui); ui = NULL; }
}
static void added_xfer(PurpleXfer *xfer)
{ CHECK(purple_xfer_get_local_filename(xfer) != NULL); }
static void *request_action(const char *title, const char *primary, const char *secondary,
    int selected, PurpleAccount *account, const char *who, PurpleConversation *conversation,
    void *data, size_t count, va_list actions)
{
    size_t i;
    (void)title; (void)primary; (void)secondary; (void)selected; (void)account; (void)who; (void)conversation;
    CHECK(count == 3); ++prompts; argument = data;
    for (i = 0; i < count; ++i) { (void)va_arg(actions, const char *); choices[i] = va_arg(actions, PurpleRequestActionCb); }
    if (synchronous) choices[0](data, 0);
    return &request_handle;
}
static void request_close(PurpleRequestType type, void *handle)
{ (void)type; (void)handle; argument = NULL; }

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
                                   .timeout_add_seconds = g_timeout_add_seconds};
    PurpleRequestUiOps requests = {.request_action = request_action, .close_request = request_close};
    PurpleXferUiOps transfers = {.new_xfer = new_xfer, .add_xfer = added_xfer};
    BarevImageBackend backend = {NULL, send_image, accept_image, cancel_image, NULL};
    PurplePlugin *plugin;
    PurpleAccount *account;
    GdkPixbuf *pixbuf;
    gchar *bytes, *markup, *stripped = NULL;
    gsize size;
    int id;
    unsigned before;
    if (argc != 3) return 2;
    purple_util_set_user_dir(argv[1]); purple_eventloop_set_ui_ops(&events);
    CHECK(purple_core_init("barev-image-ui-test"));
    purple_set_blist(purple_blist_new());
    plugin = purple_plugins_find_with_id("prpl-barev"); if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[2]); CHECK(plugin && purple_plugin_load(plugin));
    CHECK(PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->options & OPT_PROTO_IM_IMAGE);
    purple_plugins_probe("barev-test-no-scan");
    account = purple_account_new("fixture", "prpl-barev"); purple_accounts_add(account);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    CHECK(purple_account_get_connection(account) != NULL);
    purple_request_set_ui_ops(&requests); purple_xfers_set_ui_ops(&transfers);
    pixbuf = gdk_pixbuf_new(GDK_COLORSPACE_RGB, TRUE, 8, 1600, 800);
    gdk_pixbuf_fill(pixbuf, 0x112233ff);
    CHECK(gdk_pixbuf_save_to_buffer(pixbuf, &bytes, &size, "png", NULL, NULL)); g_object_unref(pixbuf);
    id = purple_imgstore_add_with_id(bytes, size, "original.png"); CHECK(id > 0);
    markup = g_strdup_printf("caption <img id=\"%d\"/>", id);
    ui = BarevImageUI_New(account, &backend);
    CHECK(BarevImageUI_Send(ui, "peer@200::2", markup, &stripped) == 1);
    CHECK(!strcmp(stripped, "caption ")); g_free(stripped);
    CHECK(prompts == 1 && sent == 0 && argument != NULL);
    {
        PurpleRequestActionCb callback = choices[1]; gpointer data = argument;
        purple_request_close(PURPLE_REQUEST_ACTION, &request_handle); callback(data, 1);
    }
    CHECK(sent == 1 && last_size == size && !memcmp(last_bytes, bytes, size));
    synchronous = TRUE;
    CHECK(BarevImageUI_Send(ui, "peer@200::2", markup, &stripped) == 1); g_free(stripped);
    CHECK(sent == 2 && last_size <= 256*1024);
    {
        guint32 width, height;
        memcpy(&width, last_bytes+16, 4); memcpy(&height, last_bytes+20, 4);
        CHECK(GUINT32_FROM_BE(width) <= 1280 && GUINT32_FROM_BE(height) <= 1280);
    }
    synchronous = FALSE; before = sent;
    CHECK(BarevImageUI_Send(ui, "peer@200::2", markup, &stripped) == 1); g_free(stripped);
    BarevImageUI_Forget(ui, "peer@0200:0000:0000:0000:0000:0000:0000:0002"); CHECK(argument == NULL && sent == before);
    CHECK(BarevImageUI_Send(ui, "peer@200::2", markup, &stripped) == 1); g_free(stripped);
    BarevImageUI_Close(ui); CHECK(argument == NULL && sent == before);
    ui = BarevImageUI_New(account, &backend); close_on_new = TRUE;
    BarevImageUI_Event(ui, "peer@200::2", 1, 1, size, "original.png", "Picture", NULL, 0);
    CHECK(ui == NULL);
    ui = BarevImageUI_New(account, &backend);
    BarevImageUI_Event(ui, "peer@200::2", 3, 5, size, "original.png", "Picture", NULL, 0);
    BarevImageUI_Event(ui, "peer@200::2", 3, 3, size, "original.png", "", NULL, 0);
    BarevImageUI_Close(ui);
    ui = BarevImageUI_New(account, &backend); close_on_new = TRUE;
    BarevImageUI_Event(ui, "peer@200::2", 2, 5, size, "original.png", "Picture", NULL, 0);
    CHECK(ui == NULL);
    g_free(markup); purple_imgstore_unref_by_id(id); g_free(last_bytes);
    purple_account_disconnect(account); purple_core_quit();
    g_print("Barev native image UI checks passed: %u\n", checks);
    return 0;
}
