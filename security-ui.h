/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_SECURITY_UI_H
#define BAREV_SECURITY_UI_H
#include <libpurple/account.h>

enum { BAREV_SECURITY_DISCONNECTED, BAREV_SECURITY_CONNECTING,
    BAREV_SECURITY_LEGACY, BAREV_SECURITY_AUTHENTICATED };
typedef struct BarevSecurityUI BarevSecurityUI;
typedef int (*BarevSecurityDescribe)(void *owner, const char *who, char fingerprint[72]);

BarevSecurityUI *BarevSecurityUI_New(PurpleAccount *, BarevSecurityDescribe, void *);
void BarevSecurityUI_Update(BarevSecurityUI *);
void BarevSecurityUI_Close(BarevSecurityUI *);
gboolean BarevSecurityUI_Text(int state, const char *fingerprint, const char **label,
    char tooltip[384]);
#endif
