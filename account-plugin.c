#define GETTEXT_PACKAGE ""

#include <librtcom-accounts-widgets/rtcom-account-plugin.h>
#include <librtcom-accounts-widgets/rtcom-dialog-context.h>
#include <librtcom-accounts-widgets/rtcom-edit.h>
#include <librtcom-accounts-widgets/rtcom-login.h>
#include <telepathy-glib/telepathy-glib.h>

#define BAREV_TYPE_PLUGIN (barev_plugin_get_type())
#define BAREV_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), BAREV_TYPE_PLUGIN, BarevPlugin))

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

G_DEFINE_TYPE(BarevPlugin, barev_plugin, RTCOM_TYPE_ACCOUNT_PLUGIN);

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

    RTCOM_ACCOUNT_PLUGIN(plugin)->name = "barev";
    RTCOM_ACCOUNT_PLUGIN(plugin)->capabilities = RTCOM_PLUGIN_CAPABILITY_ALLOW_MULTIPLE;
}

static void
barev_plugin_context_init(RtcomAccountPlugin *plugin, RtcomDialogContext *context)
{
    gboolean editing;
    AccountItem *account;
    GtkWidget *page;
    static const gchar *invalid_chars_re = "[:'\"<>&;#\\s]";

    editing = account_edit_context_get_editing(ACCOUNT_EDIT_CONTEXT(context));
    account = account_edit_context_get_account(ACCOUNT_EDIT_CONTEXT(context));

    page = g_object_new(
        RTCOM_TYPE_LOGIN,
        "username-field", "account",
        "username-label", "Nickname",
        "username-invalid-chars-re", invalid_chars_re,
        "items-mask", RTCOM_ACCOUNT_PLUGIN(plugin)->capabilities,
        "account", account,
        NULL);

    rtcom_dialog_context_set_start_page(context, page);
}

static void
barev_plugin_class_init(BarevPluginClass *klass)
{
    RTCOM_ACCOUNT_PLUGIN_CLASS(klass)->context_init = barev_plugin_context_init;
}