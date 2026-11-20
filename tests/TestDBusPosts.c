/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <gio/gio.h>
#include <stdio.h>
#include <string.h>
#include "dbus-api.h"

static const char identity[] = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static const char token[] = "00000000000040008000000000000001";
static unsigned checks, dispatched, mode, held_count, received, signals;
static GMainLoop *loop;
static GVariant *reply;
static GError *call_error;
static BarevDBusCall *held[8];
static const BarevDBusRequest *retained[8];
#define CHECK(value) do { ++checks; if (!(value)) g_error("Check %u failed: %s", checks, #value); } while (0)

static gboolean expired(gpointer data)
{ (void)data; g_error("Publishing D-Bus test timed out"); return G_SOURCE_REMOVE; }

static gboolean accounts(void *owner, BarevDBusAddAccount add, void *sink)
{ (void)owner; return add(sink, identity, "Ani", "200::1"); }

static void dispatch(void *owner, const BarevDBusRequest *request, BarevDBusCall *call)
{
    BarevDBusPost post = {"item-1", "urn:post:1", "Ani@200::1", "Բարեւ 😀", "Text <world> & friends",
        "2026-11-20T00:00:00Z", "2026-11-20T00:00:01Z", "urn:parent:1"};
    unsigned i;
    CHECK(owner == &dispatched); CHECK(!strcmp(request->account, identity)); ++dispatched;
    if (mode == 1) {
        CHECK(held_count < G_N_ELEMENTS(held)); held[held_count] = call;
        retained[held_count++] = request; return;
    }
    if (mode == 2) { CHECK(BarevDBus_Complete(call, 2, NULL, NULL)); BarevDBus_Release(call); return; }
    switch (request->method) {
    case BAREV_DBUS_STATE: CHECK(BarevDBus_Complete(call, 0, "ready", NULL)); break;
    case BAREV_DBUS_INITIALIZE: CHECK(BarevDBus_Complete(call, 0, NULL, NULL)); break;
    case BAREV_DBUS_CREATE:
        CHECK(request->model == 3 && request->name_count == 1);
        CHECK(!strcmp(request->names[0], "reader@200::2"));
        CHECK(BarevDBus_Complete(call, 0, NULL, NULL)); break;
    case BAREV_DBUS_PUBLISH:
        CHECK(!strcmp(request->token, token));
        CHECK(!strcmp(request->node, "public") && !strcmp(request->parent, "urn:parent:1"));
        CHECK(BarevDBus_Complete(call, 0, mode == 4 ? NULL : request->token, "urn:uuid:00000000-0000-4000-8000-000000000001")); break;
    case BAREV_DBUS_DESTINATIONS:
        CHECK(BarevDBus_AddDestination(call, "public", "Public", 1));
        if (mode == 3) {
            for (i = 1; i < 16; ++i) CHECK(BarevDBus_AddDestination(call, "selected", "Selected", 3));
            CHECK(!BarevDBus_AddDestination(call, "overflow", "Overflow", 1));
        } else CHECK(BarevDBus_AddDestination(call, "selected", "Selected", 3));
        CHECK(BarevDBus_Complete(call, 0, NULL, NULL)); break;
    case BAREV_DBUS_POSTS: case BAREV_DBUS_POST:
        if (mode == 3) { post.text = "\xff"; CHECK(!BarevDBus_AddPost(call, &post)); }
        else {
            CHECK(BarevDBus_AddPost(call, &post));
            if (mode == 4) CHECK(!BarevDBus_AddPost(call, &post));
        }
        CHECK(BarevDBus_Complete(call, 0, "next-token", NULL)); break;
    default: g_error("Unexpected publishing method");
    }
    CHECK(!BarevDBus_Complete(call, 0, NULL, NULL)); BarevDBus_Release(call);
}

static void completed(GObject *object, GAsyncResult *result, gpointer data)
{
    (void)data;
    reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, &call_error);
    g_main_loop_quit(loop);
}

static GVariant *call(GDBusConnection *connection, const char *method, GVariant *parameters)
{
    reply = NULL; g_clear_error(&call_error);
    g_dbus_connection_call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
        BAREV_DBUS_INTERFACE, method, parameters, NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START,
        3000, NULL, completed, NULL);
    g_main_loop_run(loop); return reply;
}

static void error_is(const char *name)
{
    char *remote = call_error ? g_dbus_error_get_remote_error(call_error) : NULL;
    char *expected = g_strconcat(BAREV_DBUS_INTERFACE ".", name, NULL);
    CHECK(!reply && remote && !strcmp(remote, expected)); g_free(remote); g_free(expected);
}

static void appeared(GDBusConnection *connection, const char *name, const char *owner, gpointer data)
{ (void)connection; (void)name; (void)owner; (void)data; g_main_loop_quit(loop); }

static void queued_done(GObject *object, GAsyncResult *result, gpointer data)
{
    GError *error = NULL;
    GVariant *value;
    char *remote;
    (void)data;
    value = g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, &error);
    remote = error ? g_dbus_error_get_remote_error(error) : NULL;
    CHECK(!value && remote && !strcmp(remote, BAREV_DBUS_INTERFACE ".Unavailable"));
    g_free(remote); g_clear_error(&error); ++received;
}

static void queue(GDBusConnection *connection, const char *method, GVariant *parameters)
{
    g_dbus_connection_call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
        BAREV_DBUS_INTERFACE, method, parameters, NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START,
        5000, NULL, queued_done, NULL);
}

static void closed_done(GObject *object, GAsyncResult *result, gpointer data)
{
    GError *error = NULL;
    GVariant *value;
    (void)data;
    value = g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, &error);
    CHECK(!value && error); g_clear_error(&error); ++received;
}

static void changed(GDBusConnection *connection, const char *sender, const char *path,
                    const char *interface, const char *signal, GVariant *parameters, gpointer data)
{
    const char *account;
    (void)connection; (void)sender; (void)path; (void)interface; (void)signal; (void)data;
    CHECK(g_variant_is_of_type(parameters, G_VARIANT_TYPE("(s)")));
    g_variant_get(parameters, "(&s)", &account); CHECK(!strcmp(account, identity));
    ++signals; g_main_loop_quit(loop);
}

int main(void)
{
    BarevDBus *service;
    GDBusConnection *connection;
    GError *error = NULL;
    GVariant *result, *rows;
    const char *value, *names[] = {"reader@200::2", NULL};
    const char *many[130];
    char large[258];
    guint timeout, watch, subscription;
    unsigned i, before;
    loop = g_main_loop_new(NULL, FALSE); timeout = g_timeout_add_seconds(20, expired, NULL);
    connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error); CHECK(connection && !error);
    service = BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", accounts, NULL); CHECK(service);
    watch = g_bus_watch_name_on_connection(connection, "org.barev.Native", G_BUS_NAME_WATCHER_FLAGS_NONE,
        appeared, NULL, NULL, NULL); g_main_loop_run(loop); g_bus_unwatch_name(watch);
    call(connection, "GetPublishingState", g_variant_new("(s)", identity)); error_is("NotSupported");
    BarevDBus_SetPublishing(service, dispatch, &dispatched);
    result = call(connection, "GetInfo", NULL); CHECK(result && !call_error);
    rows = g_variant_get_child_value(result, 2); CHECK(g_variant_n_children(rows) == 2);
    g_variant_get_child(rows, 1, "&s", &value); CHECK(!strcmp(value, "local-posts"));
    g_variant_unref(rows); g_variant_unref(result);
    result = call(connection, "GetPublishingState", g_variant_new("(s)", identity)); CHECK(result && !call_error);
    g_variant_get(result, "(&s)", &value); CHECK(!strcmp(value, "ready")); g_variant_unref(result);
    result = call(connection, "InitializePublishing", g_variant_new("(s)", identity)); CHECK(result && !call_error);
    CHECK(g_variant_is_of_type(result, G_VARIANT_TYPE("()"))); g_variant_unref(result);
    result = call(connection, "CreateDestination", g_variant_new("(sssu^as)", identity, "selected", "Selected", 3u, names));
    CHECK(result && !call_error); g_variant_unref(result);
    result = call(connection, "ListDestinations", g_variant_new("(s)", identity)); CHECK(result && !call_error);
    rows = g_variant_get_child_value(result, 0); CHECK(g_variant_n_children(rows) == 2);
    g_variant_unref(rows); g_variant_unref(result);
    result = call(connection, "Publish", g_variant_new("(ssssss)", identity, "public", token, "Բարեւ 😀", "Hello", "urn:parent:1"));
    CHECK(result && !call_error); g_variant_get_child(result, 0, "&s", &value);
    CHECK(!strcmp(value, token)); g_variant_unref(result);
    result = call(connection, "ListPosts", g_variant_new("(sssu)", identity, "public", "", 1u)); CHECK(result && !call_error);
    rows = g_variant_get_child_value(result, 0); CHECK(g_variant_n_children(rows) == 1);
    g_variant_get_child(result, 1, "&s", &value); CHECK(!strcmp(value, "next-token"));
    g_variant_unref(rows); g_variant_unref(result);
    result = call(connection, "GetPost", g_variant_new("(sss)", identity, "public", "item-1")); CHECK(result && !call_error);
    CHECK(g_variant_is_of_type(result, G_VARIANT_TYPE("((ssssssss))"))); g_variant_unref(result);
    before = dispatched;
    call(connection, "GetPublishingState", g_variant_new("(s)", "bad")); error_is("InvalidArgument");
    call(connection, "ListPosts", g_variant_new("(sssu)", identity, "public", "", 0u)); error_is("InvalidArgument");
    call(connection, "ListPosts", g_variant_new("(sssu)", identity, "public", "", 33u)); error_is("InvalidArgument");
    memset(large, 'x', sizeof(large)-1); large[sizeof(large)-1] = 0;
    call(connection, "Publish", g_variant_new("(ssssss)", identity, "public", token, large, "Text", "")); error_is("InvalidArgument");
    call(connection, "Publish", g_variant_new("(ssssss)", identity, "public", "bad", "Title", "Text", "")); error_is("InvalidArgument");
    call(connection, "Publish", g_variant_new("(ssssss)", identity, "public", "00000000000000008000000000000001", "Title", "Text", "")); error_is("InvalidArgument");
    for (i = 0; i < 129; ++i) many[i] = "reader@200::2";
    many[129] = NULL;
    call(connection, "CreateDestination", g_variant_new("(sssu^as)", identity, "selected", "Title", 3u, many)); error_is("InvalidArgument");
    CHECK(dispatched == before);
    mode = 2; call(connection, "GetPublishingState", g_variant_new("(s)", identity)); error_is("Denied");
    mode = 3; call(connection, "ListDestinations", g_variant_new("(s)", identity)); error_is("Unavailable");
    call(connection, "GetPost", g_variant_new("(sss)", identity, "public", "item-1")); error_is("Unavailable");
    mode = 4; call(connection, "Publish", g_variant_new("(ssssss)", identity, "public", token, "Title", "Text", "urn:parent:1")); error_is("Unavailable");
    call(connection, "ListPosts", g_variant_new("(sssu)", identity, "public", "", 1u)); error_is("Unavailable"); mode = 0;
    subscription = g_dbus_connection_signal_subscribe(connection, "org.barev.Native", BAREV_DBUS_INTERFACE,
        "PublishingChanged", BAREV_DBUS_NATIVE_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE, changed, NULL, NULL);
    result = call(connection, "GetInfo", NULL); CHECK(result); g_variant_unref(result);
    BarevDBus_PublishingChanged(service, "bad"); BarevDBus_PublishingChanged(service, identity);
    g_main_loop_run(loop); CHECK(signals == 1); g_dbus_connection_signal_unsubscribe(connection, subscription);

    mode = 1; queue(connection, "CreateDestination", g_variant_new("(sssu^as)", identity, "selected", "Selected", 3u, names));
    while (held_count < 1) g_main_context_iteration(NULL, TRUE);
    CHECK(retained[0]->name_count == 1 && !strcmp(retained[0]->names[0], "reader@200::2"));
    CHECK(BarevDBus_Complete(held[0], 10, NULL, NULL));
    CHECK(!BarevDBus_Complete(held[0], 0, NULL, NULL)); BarevDBus_Release(held[0]);
    while (received < 1) g_main_context_iteration(NULL, TRUE);
    held_count = 0; received = 0;
    for (i = 0; i < 8; ++i) queue(connection, "GetPublishingState", g_variant_new("(s)", identity));
    while (held_count < 8) g_main_context_iteration(NULL, TRUE);
    call(connection, "GetPublishingState", g_variant_new("(s)", identity)); error_is("Busy");
    BarevDBus_SetPublishing(service, NULL, NULL);
    while (received < 8) g_main_context_iteration(NULL, TRUE);
    CHECK(!BarevDBus_Complete(held[0], 0, "ready", NULL));
    call(connection, "GetPublishingState", g_variant_new("(s)", identity)); error_is("NotSupported");
    BarevDBus_Stop(&service); CHECK(!service && !BarevDBus_Idle());
    for (i = 0; i < 8; ++i) BarevDBus_Release(held[i]);
    while (!BarevDBus_Idle()) g_main_context_iteration(NULL, TRUE);
    CHECK(BarevDBus_Idle());
    held_count = 0; received = 0;
    service = BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", accounts, NULL); CHECK(service);
    BarevDBus_SetPublishing(service, dispatch, &dispatched);
    watch = g_bus_watch_name_on_connection(connection, "org.barev.Native", G_BUS_NAME_WATCHER_FLAGS_NONE,
        appeared, NULL, NULL, NULL); g_main_loop_run(loop); g_bus_unwatch_name(watch);
    queue(connection, "GetPublishingState", g_variant_new("(s)", identity));
    while (held_count < 1) g_main_context_iteration(NULL, TRUE);
    BarevDBus_Stop(&service); CHECK(!service && !BarevDBus_Idle());
    CHECK(!BarevDBus_Complete(held[0], 0, "ready", NULL)); BarevDBus_Release(held[0]);
    while (received < 1 || !BarevDBus_Idle()) g_main_context_iteration(NULL, TRUE);
    held_count = 0; received = 0;
    service = BarevDBus_Start("org.barev.Native", BAREV_DBUS_NATIVE_PATH, "oberon", accounts, NULL); CHECK(service);
    BarevDBus_SetPublishing(service, dispatch, &dispatched);
    watch = g_bus_watch_name_on_connection(connection, "org.barev.Native", G_BUS_NAME_WATCHER_FLAGS_NONE,
        appeared, NULL, NULL, NULL); g_main_loop_run(loop); g_bus_unwatch_name(watch);
    g_dbus_connection_call(connection, "org.barev.Native", BAREV_DBUS_NATIVE_PATH,
        BAREV_DBUS_INTERFACE, "GetPublishingState", g_variant_new("(s)", identity), NULL,
        G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, closed_done, NULL);
    while (held_count < 1) g_main_context_iteration(NULL, TRUE);
    CHECK(g_dbus_connection_close_sync(connection, NULL, &error) && !error);
    CHECK(!BarevDBus_Complete(held[0], 0, "ready", NULL));
    BarevDBus_Stop(&service); CHECK(!BarevDBus_Idle()); BarevDBus_Release(held[0]);
    while (received < 1 || !BarevDBus_Idle()) g_main_context_iteration(NULL, TRUE);
    CHECK(BarevDBus_Idle());
    g_source_remove(timeout); g_main_loop_unref(loop); g_object_unref(connection); g_clear_error(&call_error);
    printf("D-Bus publishing adapter: %u checks passed\n", checks);
    return 0;
}
