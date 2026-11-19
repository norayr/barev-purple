/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "dbus-api.h"

#ifdef BAREV_DBUS
#include <gio/gio.h>
#include <string.h>

struct BarevDBus {
    guint owner_id, registration, refs;
    GDBusConnection *connection;
    GDBusNodeInfo *info;
    char *path, *implementation;
    BarevDBusAccounts accounts;
    void *owner;
    gboolean acquired, stopping;
};
typedef struct {
    GVariantBuilder builder;
    unsigned count;
    gboolean valid;
} AccountList;
static unsigned live_services;
static const char interface_xml[] =
#include "dbus-interface.inc"
;

static gboolean add_account(void *sink, const char *identity, const char *name, const char *address)
{
    AccountList *list = sink;
    unsigned i;
    if (!list->valid) return FALSE;
    if (!identity || strlen(identity) != 64 || !name || !*name || strlen(name) > 256 ||
        !address || !*address || strlen(address) > 384 || list->count == 64 ||
        !g_utf8_validate(name, -1, NULL) || !g_utf8_validate(address, -1, NULL)) goto invalid;
    for (i = 0; i < 64; ++i)
        if (!g_ascii_isxdigit(identity[i])) goto invalid;
    g_variant_builder_add(&list->builder, "(sss)", identity, name, address);
    ++list->count;
    return TRUE;
invalid:
    list->valid = FALSE;
    return FALSE;
}

static void method_call(GDBusConnection *connection, const char *sender, const char *path,
    const char *interface, const char *method, GVariant *parameters,
    GDBusMethodInvocation *invocation, gpointer data)
{
    BarevDBus *service = data;
    (void)connection; (void)sender; (void)path; (void)interface; (void)parameters;
    if (service->stopping || !service->acquired) {
        g_dbus_method_invocation_return_dbus_error(invocation,
            BAREV_DBUS_INTERFACE ".Unavailable", "The service is unavailable.");
    } else if (!strcmp(method, "GetInfo")) {
        const char *capabilities[] = {"accounts", NULL};
        g_dbus_method_invocation_return_value(invocation,
            g_variant_new("(us^as)", 1u, service->implementation, capabilities));
    } else if (!strcmp(method, "ListAccounts")) {
        AccountList list;
        list.count = 0; list.valid = TRUE;
        g_variant_builder_init(&list.builder, G_VARIANT_TYPE("a(sss)"));
        if (!service->accounts(service->owner, add_account, &list) || !list.valid) {
            g_variant_builder_clear(&list.builder);
            g_dbus_method_invocation_return_dbus_error(invocation,
                BAREV_DBUS_INTERFACE ".Unavailable", "Cannot enumerate accounts.");
        } else {
            g_dbus_method_invocation_return_value(invocation,
                g_variant_new("(a(sss))", &list.builder));
        }
    } else {
        g_dbus_method_invocation_return_dbus_error(invocation,
            "org.freedesktop.DBus.Error.UnknownMethod", "Unknown method.");
    }
}
static const GDBusInterfaceVTable vtable = {.method_call = method_call};

static void service_unref(gpointer data)
{
    BarevDBus *service = data;
    if (--service->refs) return;
    g_dbus_node_info_unref(service->info);
    g_free(service->path);
    g_free(service->implementation);
    g_free(service);
    --live_services;
}

static void unexport(BarevDBus *service)
{
    service->acquired = FALSE;
    if (service->registration) {
        g_dbus_connection_unregister_object(service->connection, service->registration);
        service->registration = 0;
    }
    g_clear_object(&service->connection);
}

static void bus_acquired(GDBusConnection *connection, const char *name, gpointer data)
{
    BarevDBus *service = data;
    GError *error = NULL;
    (void)name;
    if (service->stopping) return;
    /* The optional desktop interface must not terminate the messaging host. */
    g_dbus_connection_set_exit_on_close(connection, FALSE);
    service->connection = g_object_ref(connection);
    ++service->refs;
    service->registration = g_dbus_connection_register_object(connection, service->path,
        service->info->interfaces[0], &vtable, service, service_unref, &error);
    if (!service->registration) service_unref(service);
    if (error) {
        g_message("Barev D-Bus registration failed: %s", error->message);
        g_error_free(error);
    }
}

static void name_acquired(GDBusConnection *connection, const char *name, gpointer data)
{
    BarevDBus *service = data;
    (void)connection; (void)name;
    if (!service->stopping && service->registration) service->acquired = TRUE;
}

static void name_lost(GDBusConnection *connection, const char *name, gpointer data)
{
    (void)connection; (void)name;
    unexport(data);
}

static void released(gpointer data)
{
    BarevDBus *service = data;
    unexport(service);
    service_unref(service);
}

BarevDBus *BarevDBus_Start(const char *bus_name, const char *path, const char *implementation,
    BarevDBusAccounts accounts, void *owner)
{
    BarevDBus *service;
    if (!bus_name || !g_dbus_is_name(bus_name) || bus_name[0] == ':' || !path ||
        !g_variant_is_object_path(path) || !implementation ||
        !g_utf8_validate(implementation, -1, NULL) || !accounts) return NULL;
    service = g_new0(BarevDBus, 1);
    service->refs = 1;
    service->path = g_strdup(path);
    service->implementation = g_strdup(implementation);
    service->accounts = accounts; service->owner = owner;
    service->info = g_dbus_node_info_new_for_xml(interface_xml, NULL);
    if (!service->info) { g_free(service->path); g_free(service->implementation); g_free(service); return NULL; }
    ++live_services;
    service->owner_id = g_bus_own_name(G_BUS_TYPE_SESSION, bus_name,
        G_BUS_NAME_OWNER_FLAGS_DO_NOT_QUEUE, bus_acquired, name_acquired, name_lost,
        service, released);
    return service;
}

void BarevDBus_AccountsChanged(BarevDBus *service)
{
    if (service && !service->stopping && service->acquired)
        g_dbus_connection_emit_signal(service->connection, NULL, service->path,
            BAREV_DBUS_INTERFACE, "AccountsChanged", NULL, NULL);
}

void BarevDBus_Stop(BarevDBus **slot)
{
    BarevDBus *service = *slot;
    *slot = NULL;
    if (!service) return;
    service->stopping = TRUE;
    service->accounts = NULL; service->owner = NULL;
    unexport(service);
    /* GIO can retain ownership callbacks until the main context runs again. */
    g_bus_unown_name(service->owner_id);
}

gboolean BarevDBus_Idle(void) { return live_services == 0; }

#else
BarevDBus *BarevDBus_Start(const char *bus_name, const char *path, const char *implementation,
    BarevDBusAccounts accounts, void *owner)
{ (void)bus_name; (void)path; (void)implementation; (void)accounts; (void)owner; return NULL; }
void BarevDBus_AccountsChanged(BarevDBus *service) { (void)service; }
void BarevDBus_Stop(BarevDBus **service) { *service = NULL; }
gboolean BarevDBus_Idle(void) { return TRUE; }
#endif
