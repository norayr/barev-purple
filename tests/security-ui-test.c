/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "security-ui.h"
#include <gtkconv.h>
#include <gmodule.h>
#include <libpurple/signals.h>
#include <stdio.h>
#include <string.h>

typedef struct { GObjectClass object; } TestWidgetClass;
typedef GtkWidget TestWidget;
G_DEFINE_TYPE(TestWidget, test_widget, G_TYPE_OBJECT)
static unsigned checks, live_widgets;
static guint destroy_signal;
static GList *conversations;
static int core_handle, pidgin_handle;
static PurpleConversationUiOps ops;
static gboolean available = TRUE;
static BarevSecurityUI **close_on_show;
static BarevSecurityUI *update_on_show;
static int *state_on_show;
#define CHECK(x) do { ++checks; if (!(x)) g_error("security UI check %u failed: %s", checks, #x); } while (0)

static void widget_finalize(GObject *object)
{
    GtkWidget *widget = (GtkWidget *)object;
    CHECK(!widget->children);
    g_free(widget->tooltip); --live_widgets;
    G_OBJECT_CLASS(test_widget_parent_class)->finalize(object);
}
static void test_widget_class_init(TestWidgetClass *klass)
{
    G_OBJECT_CLASS(klass)->finalize = widget_finalize;
    destroy_signal = g_signal_new("destroy", G_TYPE_FROM_CLASS(klass), G_SIGNAL_RUN_LAST,
        0, NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);
}
static void test_widget_init(TestWidget *widget) { (void)widget; ++live_widgets; }
GtkWidget *gtk_hbox_new(gboolean homogeneous, gint spacing)
{ (void)homogeneous; (void)spacing; return g_object_new(test_widget_get_type(), NULL); }
GtkWidget *gtk_image_new_from_icon_name(const char *name, int size)
{ CHECK(!strcmp(name, "security-high") && size == GTK_ICON_SIZE_MENU); return gtk_hbox_new(FALSE, 0); }
void gtk_box_pack_start(GtkWidget *parent, GtkWidget *child, gboolean expand, gboolean fill, guint padding)
{ (void)expand; (void)fill; (void)padding; CHECK(!child->parent); child->parent = parent; parent->children = g_list_append(parent->children, child); }
void gtk_box_pack_end(GtkWidget *parent, GtkWidget *child, gboolean expand, gboolean fill, guint padding)
{ gtk_box_pack_start(parent, child, expand, fill, padding); }
void gtk_widget_set_no_show_all(GtkWidget *widget, gboolean value) { widget->no_show_all = value; }
void gtk_widget_set_tooltip_text(GtkWidget *widget, const char *text)
{ g_free(widget->tooltip); widget->tooltip = g_strdup(text); }
void gtk_widget_show(GtkWidget *widget)
{
    widget->visible = TRUE;
    if (update_on_show) {
        BarevSecurityUI *ui = update_on_show;
        update_on_show = NULL; *state_on_show = BAREV_SECURITY_DISCONNECTED;
        BarevSecurityUI_Update(ui);
    }
    if (close_on_show) {
        BarevSecurityUI **slot = close_on_show, *ui = *slot;
        close_on_show = NULL; *slot = NULL; BarevSecurityUI_Close(ui);
    }
}
void gtk_widget_hide(GtkWidget *widget) { widget->visible = FALSE; }
void gtk_widget_destroy(GtkWidget *widget)
{
    if (widget->destroyed) return;
    g_object_ref(widget); widget->destroyed = TRUE;
    g_signal_emit(widget, destroy_signal, 0);
    while (widget->children) gtk_widget_destroy(widget->children->data);
    if (widget->parent) {
        widget->parent->children = g_list_remove(widget->parent->children, widget);
        widget->parent = NULL; g_object_unref(widget);
    }
    g_object_unref(widget);
}
static void show_all(GtkWidget *widget)
{
    GList *item;
    if (!widget->no_show_all) gtk_widget_show(widget);
    for (item = widget->children; item; item = item->next) show_all(item->data);
}
G_MODULE_EXPORT GList *purple_get_conversations(void) { return conversations; }
G_MODULE_EXPORT void *purple_conversations_get_handle(void) { return &core_handle; }
G_MODULE_EXPORT PurpleConversationUiOps *pidgin_conversations_get_conv_ui_ops(void) { return available ? &ops : NULL; }
G_MODULE_EXPORT void *pidgin_conversations_get_handle(void) { return &pidgin_handle; }

typedef struct { int state; const char *fingerprint; unsigned calls; } Peer;
static int describe(void *owner, const char *who, char fingerprint[72])
{
    Peer *peer = owner;
    CHECK(!strcmp(who, "bob@200::2")); ++peer->calls;
    g_strlcpy(fingerprint, peer->fingerprint, 72); return peer->state;
}
static GtkWidget *row(GtkWidget *parent, const char *text)
{
    GList *item;
    for (item = parent->children; item; item = item->next) {
        GtkWidget *box = item->data;
        if (box->visible && box->tooltip && strstr(box->tooltip, text)) return box;
    }
    return NULL;
}
static void check_status(GtkWidget *parent, const char *label, gboolean locked)
{
    GtkWidget *box = row(parent, label), *image;
    GList *item;
    for (item = parent->children; item; item = item->next)
        CHECK(g_list_length(((GtkWidget *)item->data)->children) == 1);
    if (!locked) {
        CHECK(box == NULL);
        show_all(parent);
        for (item = parent->children; item; item = item->next) CHECK(!((GtkWidget *)item->data)->visible);
        return;
    }
    CHECK(box != NULL); image = box->children->data;
    CHECK(image->visible == locked);
    show_all(parent); CHECK(image->visible == locked);
}
int main(void)
{
    const char *fp = "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *label;
    char tooltip[384];
    PurpleAccount accounts[3] = {{0}};
    PidginConversation gtkconv = {0};
    PurpleConversation a = {.type = PURPLE_CONV_TYPE_IM, .name = "bob@200::2", .account = &accounts[0], .ui_ops = &ops, .ui_data = &gtkconv};
    PurpleConversation b = a, other = a;
    BarevSecurityUI *first, *second;
    Peer peers[2] = {{BAREV_SECURITY_DISCONNECTED, fp, 0}, {BAREV_SECURITY_AUTHENTICATED, fp, 0}};
    unsigned i;
    purple_signals_init();
    purple_signal_register(&core_handle, "conversation-created", purple_marshal_VOID__POINTER, NULL, 1, purple_value_new(PURPLE_TYPE_POINTER));
    purple_signal_register(&core_handle, "conversation-updated", purple_marshal_VOID__POINTER_UINT, NULL, 2, purple_value_new(PURPLE_TYPE_POINTER), purple_value_new(PURPLE_TYPE_UINT));
    purple_signal_register(&pidgin_handle, "conversation-switched", purple_marshal_VOID__POINTER, NULL, 1, purple_value_new(PURPLE_TYPE_POINTER));
    purple_signal_register(&pidgin_handle, "conversation-displayed", purple_marshal_VOID__POINTER, NULL, 1, purple_value_new(PURPLE_TYPE_POINTER));
    for (i = 0; i < 3; ++i) CHECK(!BarevSecurityUI_Text(i, fp, &label, tooltip));
    CHECK(BarevSecurityUI_Text(3, fp, &label, tooltip)); CHECK(strstr(tooltip, fp));
    CHECK(g_str_has_prefix(tooltip, "Pinned identity authenticated\n"));
    CHECK(!BarevSecurityUI_Text(3, "", &label, tooltip));
    CHECK(!BarevSecurityUI_Text(3, "SHA256:<b>fake</b>", &label, tooltip));
    CHECK(!BarevSecurityUI_Text(99, fp, &label, tooltip));
    available = FALSE; CHECK(!BarevSecurityUI_New(&accounts[0], describe, &peers[0])); available = TRUE;
    first = BarevSecurityUI_New(&accounts[0], describe, &peers[0]);
    second = BarevSecurityUI_New(&accounts[1], describe, &peers[1]); CHECK(first && second);
    gtkconv.infopane_hbox = gtk_hbox_new(FALSE, 0); gtkconv.active_conv = &a;
    b.account = &accounts[1]; other.account = &accounts[2];
    conversations = g_list_append(NULL, &a); conversations = g_list_append(conversations, &b); conversations = g_list_append(conversations, &other);
    purple_signal_emit(&core_handle, "conversation-created", &a);
    check_status(gtkconv.infopane_hbox, "Disconnected", FALSE);
    for (i = 1; i < 4; ++i) {
        peers[0].state = i; purple_signal_emit(&core_handle, "conversation-updated", &a, PURPLE_CONV_UPDATE_TITLE);
        check_status(gtkconv.infopane_hbox, i == 1 ? "Connecting" : i == 2 ? "Unauthenticated" : "Pinned identity authenticated", i == 3);
    }
    CHECK(strstr(row(gtkconv.infopane_hbox, "Pinned identity authenticated")->tooltip, fp));
    peers[0].fingerprint = "invalid"; BarevSecurityUI_Update(first);
    check_status(gtkconv.infopane_hbox, "Authentication status unavailable", FALSE); peers[0].fingerprint = fp;
    gtkconv.active_conv = &b; purple_signal_emit(&pidgin_handle, "conversation-switched", &b);
    check_status(gtkconv.infopane_hbox, "Pinned identity authenticated", TRUE);
    CHECK(g_list_length(gtkconv.infopane_hbox->children) == 2);
    gtkconv.active_conv = &other; purple_signal_emit(&pidgin_handle, "conversation-switched", &other);
    CHECK(!row(gtkconv.infopane_hbox, "Pinned identity authenticated")); show_all(gtkconv.infopane_hbox);
    CHECK(!row(gtkconv.infopane_hbox, "Pinned identity authenticated"));
    gtkconv.active_conv = &a; peers[0].state = 0; purple_signal_emit(&pidgin_handle, "conversation-displayed", &gtkconv);
    check_status(gtkconv.infopane_hbox, "Disconnected", FALSE);
    gtk_widget_destroy(gtkconv.infopane_hbox); g_object_unref(gtkconv.infopane_hbox);
    gtkconv.infopane_hbox = gtk_hbox_new(FALSE, 0); peers[0].state = 3;
    purple_signal_emit(&pidgin_handle, "conversation-displayed", &gtkconv);
    check_status(gtkconv.infopane_hbox, "Pinned identity authenticated", TRUE);
    update_on_show = first; state_on_show = &peers[0].state; BarevSecurityUI_Update(first);
    check_status(gtkconv.infopane_hbox, "Disconnected", FALSE);
    peers[0].state = BAREV_SECURITY_AUTHENTICATED; BarevSecurityUI_Update(first);
    close_on_show = &first; BarevSecurityUI_Update(first); CHECK(!first);
    CHECK(!gtkconv.infopane_hbox->children);
    first = BarevSecurityUI_New(&accounts[0], describe, &peers[0]); BarevSecurityUI_Update(first);
    conversations = g_list_remove(conversations, &a); BarevSecurityUI_Update(first);
    CHECK(!row(gtkconv.infopane_hbox, "Pinned identity authenticated"));
    BarevSecurityUI_Close(first); BarevSecurityUI_Close(second);
    gtk_widget_destroy(gtkconv.infopane_hbox); g_object_unref(gtkconv.infopane_hbox);
    g_list_free(conversations); purple_signals_uninit(); CHECK(live_widgets == 0);
    printf("Conversation security UI: %u checks passed\n", checks); return 0;
}
