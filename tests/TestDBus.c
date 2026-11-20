/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <gio/gio.h>
#include <stdio.h>
#include <string.h>
#include "dbus-api.h"

static unsigned checks, signals;
static GMainLoop *loop;
static GVariant *reply;
static GError *call_error;
static gboolean appeared;
static unsigned mode;
static const char identity[] = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#define CHECK(test) do { ++checks; if (!(test)) g_error("Check %u failed: %s", checks, #test); } while (0)

static gboolean expired(gpointer data)
{ (void)data; g_error("D-Bus test timed out"); return G_SOURCE_REMOVE; }

static gboolean enumerate(void *owner, BarevDBusAddAccount add, void *sink)
{
    unsigned i, count = mode == 2 ? 64 : mode == 3 ? 65 : 1;
    char name[258], address[386];
    (void)owner;
    if (mode == 0) return TRUE;
    if (mode == 4) return FALSE;
    if (mode == 5) { add(sink, "bad", "Ani", "200::1"); return TRUE; }
    if (mode == 6) { add(sink, identity, "\xff", "200::1"); return TRUE; }
    memset(name, 'n', sizeof(name)); name[mode == 7 ? 257 : 256] = 0;
    memset(address, 'a', sizeof(address)); address[mode == 8 ? 385 : 384] = 0;
    for (i = 0; i < count; ++i)
        if (!add(sink, identity, mode >= 7 ? name : "Անի", mode >= 7 ? address : "200::1")) return FALSE;
    return TRUE;
}

static void completed(GObject *object, GAsyncResult *result, gpointer data)
{
    (void)data;
    reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, &call_error);
    g_main_loop_quit(loop);
}

static GVariant *call(GDBusConnection *connection, const char *destination, const char *path,
    const char *interface, const char *method, GVariant *parameters)
{
    reply = NULL; g_clear_error(&call_error);
    g_dbus_connection_call(connection, destination, path, interface, method, parameters,
        NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START, 3000, NULL, completed, NULL);
    g_main_loop_run(loop);
    return reply;
}

static void found(GDBusConnection *connection, const char *name, const char *owner, gpointer data)
{
    (void)connection; (void)name; (void)owner; (void)data;
    appeared = TRUE;
    g_main_loop_quit(loop);
}

static void missing(GDBusConnection *connection, const char *name, gpointer data)
{
    (void)connection; (void)name; (void)data;
    g_main_loop_quit(loop);
}

static void wait_name(GDBusConnection *connection, const char *name)
{
    guint watch;
    appeared = FALSE;
    watch = g_bus_watch_name_on_connection(connection, name, G_BUS_NAME_WATCHER_FLAGS_NONE,
        found, NULL, NULL, NULL);
    g_main_loop_run(loop);
    CHECK(appeared);
    g_bus_unwatch_name(watch);
}

static void changed(GDBusConnection *connection, const char *sender, const char *path,
    const char *interface, const char *signal, GVariant *parameters, gpointer data)
{
    (void)connection; (void)sender; (void)path; (void)interface; (void)signal; (void)data;
    CHECK(g_variant_is_of_type(parameters, G_VARIANT_TYPE("()")));
    ++signals;
    g_main_loop_quit(loop);
}

static void stop(BarevDBus **native, BarevDBus **c)
{
    BarevDBus_Stop(native); BarevDBus_Stop(c);
    CHECK(!*native && !*c);
    while (!BarevDBus_Idle()) g_main_context_iteration(NULL, TRUE);
    CHECK(BarevDBus_Idle());
}

int main(int argc, char **argv)
{
    GDBusConnection *connection;
    BarevDBus *native, *c;
    GVariant *result, *rows;
    GDBusNodeInfo *expected, *actual;
    GString *expected_xml, *actual_xml;
    GError *error = NULL;
    char *xml;
    const char *text;
    guint subscription, timeout;
    unsigned i;
    CHECK(argc == 2);
    loop = g_main_loop_new(NULL, FALSE);
    timeout = g_timeout_add_seconds(20, expired, NULL);
    CHECK(BarevDBus_Idle());
    CHECK(!BarevDBus_Start("invalid", BAREV_DBUS_NATIVE_PATH, "oberon", enumerate, NULL));
    CHECK(!BarevDBus_Start("org.barev.Native", "bad", "oberon", enumerate, NULL));
    CHECK(!BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", NULL, NULL));
    if (!strcmp(argv[1], "--no-bus")) {
        guint watch;
        native = BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", enumerate, NULL);
        c = NULL;
        watch = g_bus_watch_name(G_BUS_TYPE_SESSION, "org.barev.Native",
            G_BUS_NAME_WATCHER_FLAGS_NONE, NULL, missing, NULL, NULL);
        g_main_loop_run(loop);
        g_bus_unwatch_name(watch);
        stop(&native, &c);
        g_source_remove(timeout); g_main_loop_unref(loop);
        printf("D-Bus unavailable: %u checks passed\n", checks);
        return 0;
    }
    connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    CHECK(connection && !error);
    native = BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", enumerate, NULL);
    c = BarevDBus_Start("org.barev.C", BAREV_DBUS_C_PATH, "c", enumerate, NULL);
    CHECK(native && c && !BarevDBus_Idle());
    wait_name(connection, "org.barev.Native"); wait_name(connection, "org.barev.C");
    result = call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
        BAREV_DBUS_INTERFACE, "GetInfo", NULL);
    CHECK(result && !call_error);
    CHECK(g_variant_is_of_type(result, G_VARIANT_TYPE("(usas)")));
    rows = g_variant_get_child_value(result, 0);
    CHECK(g_variant_get_uint32(rows) == 1); g_variant_unref(rows);
    rows = g_variant_get_child_value(result, 1);
    CHECK(!strcmp(g_variant_get_string(rows, NULL), "oberon")); g_variant_unref(rows);
    rows = g_variant_get_child_value(result, 2);
    CHECK(g_variant_n_children(rows) == 1);
    g_variant_get_child(rows, 0, "&s", &text); CHECK(!strcmp(text, "accounts"));
    g_variant_unref(rows); g_variant_unref(result);
    result = call(connection, "org.barev.C", BAREV_DBUS_C_PATH, BAREV_DBUS_INTERFACE, "GetInfo", NULL);
    CHECK(result && !call_error);
    g_variant_get_child(result, 1, "&s", &text); CHECK(!strcmp(text, "c")); g_variant_unref(result);
    for (mode = 0; mode <= 9; ++mode) {
        result = call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
            BAREV_DBUS_INTERFACE, "ListAccounts", NULL);
        if (mode >= 3 && mode <= 8) {
            char *remote;
            CHECK(!result && call_error);
            remote = g_dbus_error_get_remote_error(call_error);
            CHECK(remote && !strcmp(remote, BAREV_DBUS_INTERFACE ".Unavailable")); g_free(remote);
        } else {
            CHECK(result && !call_error);
            CHECK(g_variant_is_of_type(result, G_VARIANT_TYPE("(a(sss))")));
            rows = g_variant_get_child_value(result, 0);
            CHECK(g_variant_n_children(rows) == (mode == 0 ? 0 : mode == 2 ? 64 : 1));
            if (mode == 1) {
                const char *id, *name, *address;
                g_variant_get_child(rows, 0, "(&s&s&s)", &id, &name, &address);
                CHECK(!strcmp(id, identity) && !strcmp(name, "Անի") && !strcmp(address, "200::1"));
            }
            g_variant_unref(rows); g_variant_unref(result);
        }
    }
    result = call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
        BAREV_DBUS_INTERFACE, "GetInfo", g_variant_new("(s)", "unexpected"));
    CHECK(!result && g_error_matches(call_error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS));
    result = call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
        BAREV_DBUS_INTERFACE, "UnknownOperation", NULL);
    CHECK(!result && g_error_matches(call_error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD));
    CHECK(g_file_get_contents(argv[1], &xml, NULL, &error));
    expected = g_dbus_node_info_new_for_xml(xml, &error); CHECK(expected && !error); g_free(xml);
    result = call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
        "org.freedesktop.DBus.Introspectable", "Introspect", NULL);
    CHECK(result && !call_error);
    g_variant_get(result, "(&s)", &text);
    actual = g_dbus_node_info_new_for_xml(text, &error); CHECK(actual && !error);
    expected_xml = g_string_new(NULL); actual_xml = g_string_new(NULL);
    g_dbus_interface_info_generate_xml(expected->interfaces[0], 0, expected_xml);
    g_dbus_interface_info_generate_xml(g_dbus_node_info_lookup_interface(actual, BAREV_DBUS_INTERFACE), 0, actual_xml);
    CHECK(!strcmp(expected_xml->str, actual_xml->str));
    g_string_free(expected_xml, TRUE); g_string_free(actual_xml, TRUE);
    g_dbus_node_info_unref(expected); g_dbus_node_info_unref(actual); g_variant_unref(result);
    subscription = g_dbus_connection_signal_subscribe(connection, "org.barev.Native",
        BAREV_DBUS_INTERFACE, "AccountsChanged", BAREV_DBUS_NATIVE_PATH, NULL,
        G_DBUS_SIGNAL_FLAGS_NONE, changed, NULL, NULL);
    /* A round trip ensures the daemon installs the subscription before emission. */
    result = call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH, BAREV_DBUS_INTERFACE, "GetInfo", NULL);
    CHECK(result); g_variant_unref(result);
    BarevDBus_AccountsChanged(native);
    g_main_loop_run(loop); CHECK(signals == 1);
    g_dbus_connection_signal_unsubscribe(connection, subscription);
    stop(&native, &c);
    BarevDBus_AccountsChanged(NULL); BarevDBus_Stop(&native);
    for (i = 0; i < 16; ++i) {
        native = BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", enumerate, NULL);
        CHECK(native);
        if (i % 2) wait_name(connection, "org.barev.Native");
        stop(&native, &c);
    }
    native = BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", enumerate, NULL);
    wait_name(connection, "org.barev.Native");
    CHECK(g_dbus_connection_close_sync(connection, NULL, &error)); CHECK(!error);
    stop(&native, &c);
    g_object_unref(connection); g_clear_error(&call_error);
    g_source_remove(timeout); g_main_loop_unref(loop);
    printf("D-Bus adapter: %u checks passed\n", checks);
    return 0;
}
