/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_TEST_GTKCONV_H
#define BAREV_TEST_GTKCONV_H
#include <glib-object.h>
#include <libpurple/conversation.h>
typedef struct _TestWidget {
    GObject object;
    GList *children;
    struct _TestWidget *parent;
    gboolean visible, no_show_all, destroyed;
    char *tooltip;
} GtkWidget;
typedef struct { PurpleConversation *active_conv; GtkWidget *infopane_hbox; } PidginConversation;
#define PIDGIN_CONVERSATION(conv) ((PidginConversation *)(conv)->ui_data)
#define GTK_BOX(widget) (widget)
#define GTK_ICON_SIZE_MENU 1
GtkWidget *gtk_hbox_new(gboolean, gint);
GtkWidget *gtk_image_new_from_icon_name(const char *, int);
void gtk_box_pack_start(GtkWidget *, GtkWidget *, gboolean, gboolean, guint);
void gtk_box_pack_end(GtkWidget *, GtkWidget *, gboolean, gboolean, guint);
void gtk_widget_set_no_show_all(GtkWidget *, gboolean);
void gtk_widget_set_tooltip_text(GtkWidget *, const char *);
void gtk_widget_show(GtkWidget *);
void gtk_widget_hide(GtkWidget *);
void gtk_widget_destroy(GtkWidget *);
#endif
