/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_DBUS_API_H
#define BAREV_DBUS_API_H
#include <glib.h>
#include <stdint.h>

#define BAREV_DBUS_NATIVE_PATH "/org/barev/Native/Publishing"
#define BAREV_DBUS_C_PATH "/org/barev/C/Publishing"
#define BAREV_DBUS_INTERFACE "org.barev.Publishing1"

typedef struct BarevDBus BarevDBus;
typedef struct BarevDBusCall BarevDBusCall;
enum { BAREV_DBUS_OKAY, BAREV_DBUS_INVALID, BAREV_DBUS_DENIED, BAREV_DBUS_MISSING,
       BAREV_DBUS_CONFLICT, BAREV_DBUS_FULL, BAREV_DBUS_STALE, BAREV_DBUS_STORAGE_ERROR,
       BAREV_DBUS_CHANGED, BAREV_DBUS_WIRE_FULL, BAREV_DBUS_UNAVAILABLE, BAREV_DBUS_PENDING, BAREV_DBUS_BUSY };
enum { BAREV_DBUS_STATE = 1, BAREV_DBUS_INITIALIZE, BAREV_DBUS_DESTINATIONS,
       BAREV_DBUS_CREATE, BAREV_DBUS_PUBLISH, BAREV_DBUS_POSTS, BAREV_DBUS_POST, BAREV_DBUS_RELOAD };
typedef struct {
    unsigned method;
    const char *account, *client, *node, *token, *title, *text, *parent, *cursor, *item;
    const char **names;
    uint32_t model, maximum;
    size_t name_count;
} BarevDBusRequest;
typedef struct {
    const char *item, *id, *author, *title, *text, *published, *updated, *parent;
} BarevDBusPost;
/* Dispatch owns the call until Release, including after detach or shutdown.
 * Request strings remain valid until release. Complete is owner-thread-only
 * and succeeds once; shutdown aborts replies without revoking retained handles. */
typedef void (*BarevDBusPublishing)(void *owner, const BarevDBusRequest *request, BarevDBusCall *call);
typedef gboolean (*BarevDBusAddAccount)(void *sink, const char *identity,
    const char *name, const char *address);
typedef gboolean (*BarevDBusAccounts)(void *owner, BarevDBusAddAccount add, void *sink);

BarevDBus *BarevDBus_Start(const char *bus_name, const char *path, const char *implementation,
    BarevDBusAccounts accounts, void *owner);
void BarevDBus_AccountsChanged(BarevDBus *service);
void BarevDBus_SetPublishing(BarevDBus *service, BarevDBusPublishing publishing, void *owner);
gboolean BarevDBus_AddDestination(BarevDBusCall *call, const char *node, const char *title, uint32_t model);
gboolean BarevDBus_AddPost(BarevDBusCall *call, const BarevDBusPost *post);
gboolean BarevDBus_Complete(BarevDBusCall *call, unsigned status, const char *first, const char *second);
void BarevDBus_Release(BarevDBusCall *call);
void BarevDBus_PublishingChanged(BarevDBus *service, const char *account);
void BarevDBus_Stop(BarevDBus **service);
gboolean BarevDBus_Idle(void);
#endif
