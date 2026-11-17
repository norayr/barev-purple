/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_PIN_UI_H
#define BAREV_PIN_UI_H
#include <libpurple/account.h>
#include <libpurple/notify.h>
typedef struct BarevPinUI BarevPinUI;
typedef struct {
    gpointer owner;
    int (*load)(gpointer, const char *, char [65], char [72]);
    gboolean (*describe)(gpointer, const char *, char [65], char [72]);
    int (*save)(gpointer, const char *, const char *, const char *);
} BarevPinBackend;
BarevPinUI *BarevPinUI_New(PurpleAccount *, const BarevPinBackend *);
void BarevPinUI_Close(BarevPinUI *);
void BarevPinUI_Open(BarevPinUI *, const char *);
void BarevPinUI_Info(BarevPinUI *, const char *, PurpleNotifyUserInfo *);
#endif
