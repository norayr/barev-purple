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
    BarevDBusPublishing publishing;
    void *publishing_owner;
    GList *calls;
    GThread *thread;
    void *owner;
    gboolean acquired, stopping;
};
typedef struct {
    GVariantBuilder builder;
    unsigned count;
    gboolean valid;
} AccountList;
struct BarevDBusCall {
    BarevDBus *service;
    GDBusMethodInvocation *invocation;
    GVariant *parameters, *names;
    GVariantBuilder builder;
    BarevDBusRequest request;
    char *sender;
    unsigned count;
    size_t bytes;
    gboolean valid, building, finished;
};
static unsigned live_services;
static const char interface_xml[] =
#include "dbus-interface.inc"
;

static void service_unref(gpointer data);

static gboolean text(const char *value, size_t maximum, gboolean empty)
{
    return value && (empty || *value) && strlen(value) <= maximum && g_utf8_validate(value, -1, NULL);
}

static gboolean identity(const char *value)
{
    unsigned i;
    if (!value || strlen(value) != 64) return FALSE;
    for (i = 0; i < 64; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return FALSE;
    return TRUE;
}

static gboolean callable(BarevDBusCall *call)
{ return call && call->service->thread == g_thread_self() && !call->finished; }

static gboolean post_token(const char *value)
{
    unsigned i;
    if (!value || strlen(value) != 32 || value[12] != '4' ||
        !(value[16] == '8' || value[16] == '9' || value[16] == 'a' || value[16] == 'b')) return FALSE;
    for (i = 0; i < 32; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return FALSE;
    return TRUE;
}

static void finish_call(BarevDBusCall *call)
{
    call->finished = TRUE;
    if (call->building) { g_variant_builder_clear(&call->builder); call->building = FALSE; }
    g_clear_object(&call->invocation);
}

static void error_call(BarevDBusCall *call, const char *name)
{
    char *error = g_strconcat(BAREV_DBUS_INTERFACE ".", name, NULL);
    g_dbus_method_invocation_return_dbus_error(call->invocation, error, "The publishing operation could not be completed.");
    g_free(error); finish_call(call);
}

static void abort_calls(BarevDBus *service)
{
    GList *item;
    for (item = service->calls; item; item = item->next) {
        BarevDBusCall *call = item->data;
        if (!call->finished) error_call(call, "Unavailable");
    }
}

void BarevDBus_SetPublishing(BarevDBus *service, BarevDBusPublishing publishing, void *owner)
{
    if (!service || service->stopping || service->thread != g_thread_self()) return;
    abort_calls(service); service->publishing = publishing; service->publishing_owner = owner;
}

gboolean BarevDBus_AddDestination(BarevDBusCall *call, const char *node, const char *title, uint32_t model)
{
    if (!callable(call)) return FALSE;
    if (!call->valid || call->request.method != BAREV_DBUS_DESTINATIONS || call->count == 16 ||
        !text(node, 128, FALSE) || !text(title, 256, FALSE) || model < 1 || model > 3) {
        call->valid = FALSE; return FALSE;
    }
    g_variant_builder_add(&call->builder, "(ssu)", node, title, model); ++call->count;
    return TRUE;
}

gboolean BarevDBus_AddPost(BarevDBusCall *call, const BarevDBusPost *post)
{
    size_t size;
    unsigned maximum;
    if (!callable(call)) return FALSE;
    maximum = call->request.method == BAREV_DBUS_POST ? 1 : call->request.maximum;
    if (!call->valid || !post || (call->request.method != BAREV_DBUS_POSTS && call->request.method != BAREV_DBUS_POST) ||
        call->count >= maximum || !text(post->item, 128, FALSE) || !text(post->id, 1024, FALSE) ||
        !text(post->author, 384, FALSE) || !text(post->title, 256, TRUE) || !text(post->text, 16384, FALSE) ||
        !text(post->published, 20, FALSE) || !text(post->updated, 20, FALSE) || !text(post->parent, 1024, TRUE)) goto invalid;
    size = strlen(post->item)+strlen(post->id)+strlen(post->author)+strlen(post->title)+strlen(post->text)+
        strlen(post->published)+strlen(post->updated)+strlen(post->parent);
    if (size > 1048576-call->bytes) goto invalid;
    g_variant_builder_add(&call->builder, "(ssssssss)", post->item, post->id, post->author,
        post->title, post->text, post->published, post->updated, post->parent);
    ++call->count; call->bytes += size;
    return TRUE;
invalid:
    call->valid = FALSE; return FALSE;
}

gboolean BarevDBus_Complete(BarevDBusCall *call, unsigned status, const char *first, const char *second)
{
    static const char *errors[] = {"Unavailable", "InvalidArgument", "Denied", "NotFound", "Conflict",
        "Full", "Stale", "StorageError", "Changed", "WireFull", "Unavailable", "Unavailable", "Busy"};
    GVariant *result = NULL, *array;
    if (!callable(call)) return FALSE;
    if (call->service->stopping || !call->service->acquired || !call->service->connection ||
        g_dbus_connection_is_closed(call->service->connection)) {
        error_call(call, "Unavailable"); return FALSE;
    }
    if (status) { error_call(call, errors[status < G_N_ELEMENTS(errors) ? status : 0]); return TRUE; }
    if (call->valid) switch (call->request.method) {
    case BAREV_DBUS_STATE:
        if (text(first, 32, FALSE)) result = g_variant_new("(s)", first);
        break;
    case BAREV_DBUS_INITIALIZE: case BAREV_DBUS_CREATE:
        result = g_variant_new("()"); break;
    case BAREV_DBUS_PUBLISH:
        if (text(first, 128, FALSE) && text(second, 1024, FALSE)) result = g_variant_new("(ss)", first, second);
        break;
    case BAREV_DBUS_DESTINATIONS:
        result = g_variant_new("(a(ssu))", &call->builder); break;
    case BAREV_DBUS_POSTS:
        if (text(first, 64, TRUE)) result = g_variant_new("(a(ssssssss)s)", &call->builder, first);
        break;
    case BAREV_DBUS_POST:
        if (call->count == 1) {
            array = g_variant_builder_end(&call->builder);
            result = g_variant_new("(@(ssssssss))", g_variant_get_child_value(array, 0));
            g_variant_unref(array);
        }
        break;
    }
    if (!result) { error_call(call, "Unavailable"); return TRUE; }
    if (call->building) call->building = FALSE;
    g_dbus_method_invocation_return_value(call->invocation, result); finish_call(call);
    return TRUE;
}

void BarevDBus_Release(BarevDBusCall *call)
{
    BarevDBus *service;
    if (!call || call->service->thread != g_thread_self()) return;
    service = call->service;
    if (!call->finished) error_call(call, "Unavailable");
    service->calls = g_list_remove(service->calls, call);
    g_free(call->request.names); g_clear_pointer(&call->names, g_variant_unref);
    g_variant_unref(call->parameters); g_free(call->sender); g_free(call);
    service_unref(service);
}

static gboolean parse_request(BarevDBusCall *call)
{
    BarevDBusRequest *r = &call->request;
    size_t i;
    switch (r->method) {
    case BAREV_DBUS_STATE: case BAREV_DBUS_INITIALIZE: case BAREV_DBUS_DESTINATIONS:
        g_variant_get(call->parameters, "(&s)", &r->account); break;
    case BAREV_DBUS_CREATE:
        g_variant_get(call->parameters, "(&s&s&su@as)", &r->account, &r->node, &r->title, &r->model, &call->names);
        r->names = g_variant_get_strv(call->names, &r->name_count);
        if (r->name_count > 128 || r->model > INT32_MAX || !text(r->title, 256, FALSE)) return FALSE;
        for (i = 0; i < r->name_count; ++i) if (!text(r->names[i], 384, FALSE)) return FALSE;
        break;
    case BAREV_DBUS_PUBLISH:
        g_variant_get(call->parameters, "(&s&s&s&s&s&s)", &r->account, &r->node, &r->token, &r->title, &r->text, &r->parent);
        if (!post_token(r->token) || !text(r->title, 256, TRUE) || !text(r->text, 16384, FALSE) || !text(r->parent, 1024, TRUE)) return FALSE;
        break;
    case BAREV_DBUS_POSTS:
        g_variant_get(call->parameters, "(&s&s&su)", &r->account, &r->node, &r->cursor, &r->maximum);
        if (!text(r->cursor, 64, TRUE) || !r->maximum || r->maximum > 32) return FALSE;
        break;
    case BAREV_DBUS_POST:
        g_variant_get(call->parameters, "(&s&s&s)", &r->account, &r->node, &r->item);
        if (!text(r->item, 128, FALSE)) return FALSE;
        break;
    }
    return identity(r->account) && (!r->node || text(r->node, 128, FALSE));
}

static void publishing_call(BarevDBus *service, unsigned method, const char *sender,
                            GVariant *parameters, GDBusMethodInvocation *invocation)
{
    BarevDBusCall *call;
    GList *item;
    unsigned count = 0, own = 0;
    if (!service->publishing) {
        g_dbus_method_invocation_return_dbus_error(invocation, BAREV_DBUS_INTERFACE ".NotSupported", "Local publishing is unavailable.");
        return;
    }
    for (item = service->calls; item; item = item->next) {
        BarevDBusCall *current = item->data;
        ++count; if (!strcmp(current->sender, sender)) ++own;
    }
    if (count >= 32 || own >= 8) {
        g_dbus_method_invocation_return_dbus_error(invocation, BAREV_DBUS_INTERFACE ".Busy", "Too many retained publishing calls."); return;
    }
    if (g_variant_get_size(parameters) > 65536) {
        g_dbus_method_invocation_return_dbus_error(invocation, BAREV_DBUS_INTERFACE ".InvalidArgument", "Publishing input exceeds the byte limit."); return;
    }
    call = g_new0(BarevDBusCall, 1); call->service = service; ++service->refs;
    call->parameters = g_variant_ref(parameters); call->invocation = g_object_ref(invocation);
    call->sender = g_strdup(sender); call->request.method = method; call->valid = TRUE;
    service->calls = g_list_prepend(service->calls, call);
    if (!parse_request(call)) { error_call(call, "InvalidArgument"); BarevDBus_Release(call); return; }
    if (method == BAREV_DBUS_DESTINATIONS || method == BAREV_DBUS_POSTS || method == BAREV_DBUS_POST) {
        g_variant_builder_init(&call->builder, G_VARIANT_TYPE(method == BAREV_DBUS_DESTINATIONS ? "a(ssu)" : "a(ssssssss)"));
        call->building = TRUE;
    }
    ++service->refs;
    service->publishing(service->publishing_owner, &call->request, call);
    service_unref(service);
}

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
    (void)connection; (void)path; (void)interface;
    if (service->stopping || !service->acquired) {
        g_dbus_method_invocation_return_dbus_error(invocation,
            BAREV_DBUS_INTERFACE ".Unavailable", "The service is unavailable.");
    } else if (!strcmp(method, "GetInfo")) {
        const char *capabilities[] = {"accounts", service->publishing ? "local-posts" : NULL, NULL};
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
    } else if (!strcmp(method, "GetPublishingState")) publishing_call(service, BAREV_DBUS_STATE, sender, parameters, invocation);
    else if (!strcmp(method, "InitializePublishing")) publishing_call(service, BAREV_DBUS_INITIALIZE, sender, parameters, invocation);
    else if (!strcmp(method, "ListDestinations")) publishing_call(service, BAREV_DBUS_DESTINATIONS, sender, parameters, invocation);
    else if (!strcmp(method, "CreateDestination")) publishing_call(service, BAREV_DBUS_CREATE, sender, parameters, invocation);
    else if (!strcmp(method, "Publish")) publishing_call(service, BAREV_DBUS_PUBLISH, sender, parameters, invocation);
    else if (!strcmp(method, "ListPosts")) publishing_call(service, BAREV_DBUS_POSTS, sender, parameters, invocation);
    else if (!strcmp(method, "GetPost")) publishing_call(service, BAREV_DBUS_POST, sender, parameters, invocation);
    else {
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
    abort_calls(service);
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
    service->thread = g_thread_self();
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

void BarevDBus_PublishingChanged(BarevDBus *service, const char *account)
{
    if (service && service->thread == g_thread_self() && !service->stopping &&
        service->acquired && service->publishing && identity(account))
        g_dbus_connection_emit_signal(service->connection, NULL, service->path,
            BAREV_DBUS_INTERFACE, "PublishingChanged", g_variant_new("(s)", account), NULL);
}

void BarevDBus_Stop(BarevDBus **slot)
{
    BarevDBus *service = *slot;
    *slot = NULL;
    if (!service) return;
    service->stopping = TRUE;
    service->accounts = NULL; service->owner = NULL;
    service->publishing = NULL; service->publishing_owner = NULL;
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
void BarevDBus_SetPublishing(BarevDBus *service, BarevDBusPublishing publishing, void *owner)
{ (void)service; (void)publishing; (void)owner; }
gboolean BarevDBus_AddDestination(BarevDBusCall *call, const char *node, const char *title, uint32_t model)
{ (void)call; (void)node; (void)title; (void)model; return FALSE; }
gboolean BarevDBus_AddPost(BarevDBusCall *call, const BarevDBusPost *post)
{ (void)call; (void)post; return FALSE; }
gboolean BarevDBus_Complete(BarevDBusCall *call, unsigned status, const char *first, const char *second)
{ (void)call; (void)status; (void)first; (void)second; return FALSE; }
void BarevDBus_Release(BarevDBusCall *call) { (void)call; }
void BarevDBus_PublishingChanged(BarevDBus *service, const char *account) { (void)service; (void)account; }
void BarevDBus_Stop(BarevDBus **service) { *service = NULL; }
gboolean BarevDBus_Idle(void) { return TRUE; }
#endif
