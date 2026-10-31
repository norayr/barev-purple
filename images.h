/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_IMAGES_H
#define BAREV_IMAGES_H
#include <libpurple/account.h>
#include <libpurple/blist.h>
#include <libpurple/xmlnode.h>
#include <libpurple/ft.h>
typedef struct BarevImages BarevImages;
BarevImages *barev_images_new(PurpleAccount *);
void barev_images_close(BarevImages *);
int barev_images_send(BarevImages *, const char *, const char *, char **);
gboolean barev_images_receive(PurpleBuddy *, xmlnode *);
void barev_images_lost(PurpleBuddy *);
void barev_images_forget(PurpleBuddy *);
void barev_images_file_completed(PurpleXfer *);
#endif
