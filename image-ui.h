/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_IMAGE_UI_H
#define BAREV_IMAGE_UI_H
#include <libpurple/account.h>
#include <libpurple/accountopt.h>
#include <glib.h>
#include <libpurple/ft.h>
typedef struct BarevImageUI BarevImageUI;
typedef struct {
    gpointer owner;
    int (*send)(gpointer, const char *, const guchar *, size_t, const char *);
    gboolean (*accept)(gpointer, const char *, int, gboolean);
    void (*cancel)(gpointer, const char *, int);
    int (*progress)(gpointer, const char *, int);
} BarevImageBackend;
BarevImageUI *BarevImageUI_New(PurpleAccount *, const BarevImageBackend *);
void BarevImageUI_Close(BarevImageUI *);
int BarevImageUI_Send(BarevImageUI *, const char *, const char *, char **);
char *BarevImageUI_Strip(const char *);
void BarevImageUI_Event(BarevImageUI *, const char *, int, int, size_t,
                       const char *, const char *, const guchar *, size_t);
void BarevImageUI_Progress(BarevImageUI *, const char *, int, size_t);
void BarevImageUI_Update(BarevImageUI *);
void BarevImageUI_Forget(BarevImageUI *, const char *);
void BarevImageUI_FileCompleted(BarevImageUI *, PurpleXfer *);
GList *BarevImageUI_Options(GList *);
#endif
