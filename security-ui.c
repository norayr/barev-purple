/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "security-ui.h"
#include <string.h>

gboolean BarevSecurityUI_Text(int state, const char *fingerprint, const char **label,
    char tooltip[384])
{
    unsigned i;
    gboolean valid = fingerprint && strlen(fingerprint) == 71 && !strncmp(fingerprint, "SHA256:", 7);
    for (i = 7; valid && i < 71; ++i)
        valid = (fingerprint[i] >= '0' && fingerprint[i] <= '9') ||
            (fingerprint[i] >= 'a' && fingerprint[i] <= 'f');
    if (state == BAREV_SECURITY_AUTHENTICATED && valid) {
        *label = "Pinned identity authenticated";
        g_snprintf(tooltip, 384, "Pinned identity authenticated\nMutual TLS 1.3 · SASL EXTERNAL\nPeer fingerprint: %s\n"
            "Verified against the key pinned when this connection opened.\n"
            "Pin changes apply after reconnecting.\nScope: authenticated chat stream.", fingerprint);
        return TRUE;
    }
    if (state == BAREV_SECURITY_DISCONNECTED) {
        *label = "Disconnected";
        g_strlcpy(tooltip, "No active peer connection.", 384);
    } else if (state == BAREV_SECURITY_CONNECTING) {
        *label = "Connecting";
        g_strlcpy(tooltip, "The peer connection is not ready. Identity authentication has not completed.", 384);
    } else if (state == BAREV_SECURITY_LEGACY) {
        *label = "Unauthenticated";
        g_strlcpy(tooltip, "Legacy peer connection without pinned identity authentication.", 384);
    } else {
        *label = "Authentication status unavailable";
        g_strlcpy(tooltip, "An authenticated peer identity could not be confirmed.", 384);
    }
    return FALSE;
}

#ifdef BAREV_PIDGIN_UI
#include <gmodule.h>
#include <libpurple/conversation.h>
#include <libpurple/signals.h>
#include <gtkconv.h>

typedef struct View View;
struct BarevSecurityUI {
    PurpleAccount *account;
    BarevSecurityDescribe describe;
    void *owner;
    PurpleConversationUiOps *(*ui_ops)(void);
    GList *views;
    unsigned refs;
    gboolean closed, updating, again;
};
struct View {
    BarevSecurityUI *ui;
    GtkWidget *parent, *box, *image;
    unsigned refs;
    gboolean shown;
    char *tooltip;
};

static void unref(BarevSecurityUI *ui) { if (!--ui->refs) g_free(ui); }
static void view_unref(View *view)
{ if (!--view->refs) { g_free(view->tooltip); g_free(view); } }

static void destroyed(GtkWidget *widget, gpointer data)
{
    View *view = data;
    (void)widget;
    view->ui->views = g_list_remove(view->ui->views, view);
    view->box = view->image = view->parent = NULL;
    view_unref(view);
}

static View *view_for(BarevSecurityUI *ui, GtkWidget *parent)
{
    GList *item;
    View *view;
    for (item = ui->views; item; item = item->next) {
        view = item->data;
        if (view->parent == parent) { ++view->refs; return view; }
    }
    view = g_new0(View, 1); view->ui = ui; view->refs = 2; view->parent = parent;
    view->box = gtk_hbox_new(FALSE, 4);
    view->image = gtk_image_new_from_icon_name("security-high", GTK_ICON_SIZE_MENU);
    gtk_box_pack_start(GTK_BOX(view->box), view->image, FALSE, FALSE, 0);
    gtk_widget_set_no_show_all(view->image, TRUE);
    gtk_widget_set_no_show_all(view->box, TRUE);
    g_signal_connect(view->box, "destroy", G_CALLBACK(destroyed), view);
    ui->views = g_list_prepend(ui->views, view);
    gtk_box_pack_end(GTK_BOX(parent), view->box, FALSE, FALSE, 6);
    return view;
}

void BarevSecurityUI_Update(BarevSecurityUI *ui)
{
    GList *snapshot, *item;
    if (!ui || ui->closed) return;
    if (ui->updating) { ui->again = TRUE; return; }
    ++ui->refs; ui->updating = TRUE;
    for (item = ui->views; item; item = item->next) ((View *)item->data)->shown = FALSE;
    snapshot = g_list_copy(purple_get_conversations());
    for (item = snapshot; item && !ui->closed; item = item->next) {
        PurpleConversation *conv = item->data;
        PidginConversation *gtkconv;
        char fingerprint[72] = {0}, tooltip[384];
        const char *label;
        int state;
        gboolean locked;
        View *view;
        if (!g_list_find(purple_get_conversations(), conv) ||
            purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM ||
            purple_conversation_get_account(conv) != ui->account ||
            purple_conversation_get_ui_ops(conv) != ui->ui_ops()) continue;
        gtkconv = PIDGIN_CONVERSATION(conv);
        if (!gtkconv || gtkconv->active_conv != conv || !gtkconv->infopane_hbox) continue;
        state = ui->describe(ui->owner, purple_conversation_get_name(conv), fingerprint);
        fingerprint[71] = 0;
        if (ui->closed) break;
        locked = BarevSecurityUI_Text(state, fingerprint, &label, tooltip);
        view = view_for(ui, gtkconv->infopane_hbox);
        view->shown = TRUE;
        if (view->box && g_strcmp0(view->tooltip, tooltip)) {
            g_free(view->tooltip); view->tooltip = g_strdup(tooltip);
            gtk_widget_set_tooltip_text(view->box, tooltip);
        }
        if (view->image) {
            if (locked) gtk_widget_show(view->image);
            else gtk_widget_hide(view->image);
        }
        if (view->box) {
            if (locked) gtk_widget_show(view->box);
            else gtk_widget_hide(view->box);
        }
        view_unref(view);
    }
    g_list_free(snapshot);
    snapshot = g_list_copy(ui->views);
    for (item = snapshot; item; item = item->next) ++((View *)item->data)->refs;
    for (item = snapshot; item; item = item->next) {
        View *view = item->data;
        if (!ui->closed && view->box && !view->shown) gtk_widget_hide(view->box);
        view_unref(view);
    }
    g_list_free(snapshot);
    ui->updating = FALSE;
    if (ui->again && !ui->closed) { ui->again = FALSE; BarevSecurityUI_Update(ui); }
    unref(ui);
}

static void changed(gpointer conversation, gpointer data)
{ (void)conversation; BarevSecurityUI_Update(data); }
static void updated(PurpleConversation *conversation, PurpleConvUpdateType type, gpointer data)
{ (void)type; changed(conversation, data); }

BarevSecurityUI *BarevSecurityUI_New(PurpleAccount *account, BarevSecurityDescribe describe, void *owner)
{
    GModule *host;
    gpointer ops = NULL, handle = NULL;
    void *(*pidgin_handle)(void);
    BarevSecurityUI *ui;
    if (!account || !describe) return NULL;
    host = g_module_open(NULL, G_MODULE_BIND_LAZY);
    if (host) {
        g_module_symbol(host, "pidgin_conversations_get_conv_ui_ops", &ops);
        g_module_symbol(host, "pidgin_conversations_get_handle", &handle);
        g_module_close(host);
    }
    if (!ops || !handle) return NULL;
    pidgin_handle = (void *(*)(void))handle;
    if (!((PurpleConversationUiOps *(*)(void))ops)() || !pidgin_handle()) return NULL;
    ui = g_new0(BarevSecurityUI, 1);
    ui->account = account; ui->describe = describe; ui->owner = owner; ui->refs = 1;
    ui->ui_ops = (PurpleConversationUiOps *(*)(void))ops;
    purple_signal_connect(purple_conversations_get_handle(), "conversation-created", ui, PURPLE_CALLBACK(changed), ui);
    purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", ui, PURPLE_CALLBACK(updated), ui);
    purple_signal_connect(pidgin_handle(), "conversation-switched", ui, PURPLE_CALLBACK(changed), ui);
    purple_signal_connect(pidgin_handle(), "conversation-displayed", ui, PURPLE_CALLBACK(changed), ui);
    return ui;
}

void BarevSecurityUI_Close(BarevSecurityUI *ui)
{
    if (!ui || ui->closed) return;
    ui->closed = TRUE;
    purple_signals_disconnect_by_handle(ui);
    while (ui->views) gtk_widget_destroy(((View *)ui->views->data)->box);
    unref(ui);
}
#else
BarevSecurityUI *BarevSecurityUI_New(PurpleAccount *account, BarevSecurityDescribe describe, void *owner)
{ (void)account; (void)describe; (void)owner; return NULL; }
void BarevSecurityUI_Update(BarevSecurityUI *ui) { (void)ui; }
void BarevSecurityUI_Close(BarevSecurityUI *ui) { (void)ui; }
#endif
