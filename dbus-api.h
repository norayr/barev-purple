/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_DBUS_API_H
#define BAREV_DBUS_API_H
#include <glib.h>

#define BAREV_DBUS_NATIVE_PATH "/org/barev/Native/Publishing"
#define BAREV_DBUS_C_PATH "/org/barev/C/Publishing"
#define BAREV_DBUS_INTERFACE "org.barev.Publishing1"

typedef struct BarevDBus BarevDBus;
typedef gboolean (*BarevDBusAddAccount)(void *sink, const char *identity,
    const char *name, const char *address);
typedef gboolean (*BarevDBusAccounts)(void *owner, BarevDBusAddAccount add, void *sink);

BarevDBus *BarevDBus_Start(const char *bus_name, const char *path, const char *implementation,
    BarevDBusAccounts accounts, void *owner);
void BarevDBus_AccountsChanged(BarevDBus *service);
void BarevDBus_Stop(BarevDBus **service);
gboolean BarevDBus_Idle(void);
#endif
