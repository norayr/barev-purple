#define GETTEXT_PACKAGE "barev"
#define PLUGIN_XML_DIR "/usr/lib/arm-linux-gnueabihf/libaccounts-plugins/xml"

#include <glib/gi18n-lib.h>
#include <glade/glade.h>
#include <gtk/gtk.h>
#include <libaccounts-glib/accounts-glib.h>
#include <librtcom-accounts-widgets/rtcom-account-plugin.h>
#include <librtcom-accounts-widgets/rtcom-dialog-context.h>
#include <librtcom-accounts-widgets/rtcom-edit.h>
#include <librtcom-accounts-widgets/rtcom-login.h>
#include <telepathy-glib/telepathy-glib.h>

#define BAREV_PROVIDER "barev"
#define BAREV_SERVICE "haze/barev"

typedef struct _BarevPluginClass BarevPluginClass;
typedef struct _BarevPlugin BarevPlugin;

struct _BarevPlugin
{
    RtcomAccountPlugin parent_instance;
};

struct _BarevPluginClass
{
    RtcomAccountPluginClass parent_class;
};

struct _BarevPluginPrivate
{
    GtkWidget *registering_dialog;
};

typedef struct _BarevPluginPrivate BarevPluginPrivate;

ACCOUNT_DEFINE_PLUGIN_WITH_PRIVATE(BarevPlugin, barev_plugin, RTCOM_TYPE_ACCOUNT_PLUGIN);

static GtkWindow *
get_parent_window(RtcomDialogContext *context)
{
    GtkWidget *page = rtcom_dialog_context_get_start_page(context);
    return page ? GTK_WINDOW(gtk_widget_get_toplevel(page)) : NULL;
}

static void
cms_ready_cb(GObject *object, GAsyncResult *res, gpointer user_data)
{
    RtcomAccountPlugin *plugin = user_data;
    GError *error = NULL;
    GList *cms = tp_list_connection_managers_finish(res, &error);
    GList *l;

    if (error != NULL)
    {
        g_warning("Error getting list of CMs: %s", error->message);
        g_error_free(error);
    }
    else if (!cms)
        g_warning("No Telepathy connection managers found");

    for (l = cms; l; l = l->next)
    {
        if (tp_connection_manager_has_protocol(l->data, "barev"))
        {
            gchar *service_id = g_strconcat(tp_connection_manager_get_name(l->data),
                                           "/barev", NULL);

            rtcom_account_plugin_add_service(plugin, service_id);
            g_free(service_id);
        }
    }

    rtcom_account_plugin_initialized(plugin);
    g_list_free(cms);
    g_object_unref(plugin);
}

static void
barev_plugin_init(BarevPlugin *plugin)
{
    GError *error = NULL;
    TpDBusDaemon *tp_dbus = tp_dbus_daemon_dup(&error);

    if (tp_dbus)
    {
        tp_list_connection_managers_async(tp_dbus, cms_ready_cb,
                                          g_object_ref(plugin));
    }
    else
    {
        g_warning("%s: tp_dbus_daemon_dup() failed [%s]", __FUNCTION__,
                  error->message);
        g_error_free(error);
    }

    RTCOM_ACCOUNT_PLUGIN(plugin)->name = BAREV_PROVIDER;
    RTCOM_ACCOUNT_PLUGIN(plugin)->capabilities = RTCOM_PLUGIN_CAPABILITY_ALLOW_MULTIPLE;
    glade_init();
}

static void
barev_plugin_on_register_cb(RtcomDialogContext *context)
{
    GladeXML *xml = glade_xml_new(
        PLUGIN_XML_DIR "/barev-new-account.glade", NULL, GETTEXT_PACKAGE);
    GtkWidget *dialog = glade_xml_get_widget(xml, "register");

    if (dialog)
    {
        AccountItem *account = account_edit_context_get_account(ACCOUNT_EDIT_CONTEXT(context));
        GtkWidget *page = glade_xml_get_widget(xml, "page");

        gtk_dialog_add_buttons(GTK_DIALOG(dialog), "Register", GTK_RESPONSE_OK, NULL);
        rtcom_page_set_account(RTCOM_PAGE(page), RTCOM_ACCOUNT_ITEM(account));
        gtk_window_set_title(GTK_WINDOW(dialog), "New Barev Account");
        gtk_window_set_transient_for(GTK_WINDOW(dialog), get_parent_window(context));
        g_signal_connect(dialog, "response", G_CALLBACK(gtk_widget_hide), NULL);
        gtk_widget_show_all(dialog);
    }
    else
    {
        g_warning("Unable to load Register dialog");
    }
}

static void
barev_plugin_context_init(RtcomAccountPlugin *plugin, RtcomDialogContext *context)
{
    GtkWidget *page;
    gboolean editing;
    AccountItem *account;
    static const gchar *invalid_chars_re = "[:'\"<>&;#\\s]";

    editing = account_edit_context_get_editing(ACCOUNT_EDIT_CONTEXT(context));
    account = account_edit_context_get_account(ACCOUNT_EDIT_CONTEXT(context));

    if (editing)
    {
        page = g_object_new(
            RTCOM_TYPE_EDIT,
            "username-field", "account",
            "username-invalid-chars-re", invalid_chars_re,
            "items-mask", RTCOM_ACCOUNT_PLUGIN(plugin)->capabilities,
            "account", account,
            NULL);
    }
    else
    {
        page = g_object_new(
            RTCOM_TYPE_LOGIN,
            "username-field", "account",
            "username-label", "Nickname",
            "username-invalid-chars-re", invalid_chars_re,
            "items-mask", RTCOM_ACCOUNT_PLUGIN(plugin)->capabilities,
            "account", account,
            NULL);

        rtcom_login_connect_on_register(
            RTCOM_LOGIN(page), G_CALLBACK(barev_plugin_on_register_cb), context);
    }

    rtcom_dialog_context_set_start_page(context, page);
}

static void
barev_plugin_class_init(BarevPluginClass *klass)
{
    RTCOM_ACCOUNT_PLUGIN_CLASS(klass)->context_init = barev_plugin_context_init;
}