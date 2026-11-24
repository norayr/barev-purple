/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib-unix.h>
#include <gmodule.h>
#include <libpurple/core.h>
#include <libpurple/eventloop.h>
#include <libpurple/plugin.h>
#include <libpurple/util.h>
#include "barev.h"

/* Keep libpurple startup confined to explicitly supplied test plugins. */
G_MODULE_EXPORT void purple_plugins_add_search_path(const char *path)
{ (void)path; }

static GMainLoop *loop;
static PurpleAccount *account;
static PurplePlugin *plugin;

/* Account discovery needs an online account, without opening peer listeners. */
G_MODULE_EXPORT gint bonjour_jabber_start(BonjourJabber *data)
{ data->socket = -1; data->socket6 = -1; return 0; }
G_MODULE_EXPORT GSList *bonjour_jabber_get_local_ips(gint fd)
{ (void)fd; return g_slist_append(NULL, g_strdup("200::1")); }

static void ready(PurpleConnection *connection, gpointer data)
{ (void)connection; (void)data; puts("READY 0"); }

static gboolean command(gint fd, GIOCondition condition, gpointer data)
{
    char line[128];
    (void)fd; (void)condition; (void)data;
    if (!fgets(line, sizeof(line), stdin) || !strcmp(line, "quit\n")) {
        g_main_loop_quit(loop); return G_SOURCE_CONTINUE;
    }
    if (!strcmp(line, "disconnect\n")) { purple_account_disconnect(account); puts("DISCONNECTED"); }
    else if (!strcmp(line, "reconnect\n")) purple_account_connect(account);
    else if (!strcmp(line, "can-unload\n")) printf("UNLOAD %d\n", plugin->info->unload(plugin));
    return G_SOURCE_CONTINUE;
}

int main(int argc, char **argv)
{
    PurpleEventLoopUiOps events = {.timeout_add = g_timeout_add, .timeout_remove = g_source_remove,
        .timeout_add_seconds = g_timeout_add_seconds};
    guint input;
    int signals;
    if (argc != 3) return 2;
    setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stdin, NULL, _IONBF, 0);
    purple_util_set_user_dir(argv[2]); purple_eventloop_set_ui_ops(&events);
    if (!purple_core_init("barev-dbus-test")) return 3;
    purple_set_blist(purple_blist_new()); purple_blist_load();
    plugin = purple_plugins_find_with_id("prpl-barev");
    if (plugin) purple_plugin_destroy(plugin);
    plugin = purple_plugin_probe(argv[1]);
    if (!plugin || !purple_plugin_load(plugin)) return 4;
    purple_plugins_probe("barev-dbus-no-scan");
    purple_signal_connect(purple_connections_get_handle(), "signed-on", &signals,
        PURPLE_CALLBACK(ready), NULL);
    account = purple_account_new("Անի", "prpl-barev"); purple_accounts_add(account);
    loop = g_main_loop_new(NULL, FALSE);
    input = g_unix_fd_add(STDIN_FILENO, G_IO_IN | G_IO_HUP, command, NULL);
    purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
    purple_account_set_status(account, "available", TRUE, NULL);
    if (!purple_account_get_connection(account)) purple_account_connect(account);
    g_main_loop_run(loop);
    g_source_remove(input); purple_signals_disconnect_by_handle(&signals);
    purple_core_quit(); g_main_loop_unref(loop);
    return 0;
}
