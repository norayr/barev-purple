/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_PEER_PINS_H
#define BAREV_PEER_PINS_H
#include <glib.h>
enum { BAREV_PIN_OK = 0, BAREV_PIN_UNPINNED = 1, BAREV_PIN_INVALID = 2,
       BAREV_PIN_STORAGE = 3, BAREV_PIN_CHANGED = 4 };
gboolean barev_pin_describe(const char *, char normalized[65], char fingerprint[72]);
int barev_pin_load(const char *profile, const char *own, const char *peer,
                   char identifier[65], char fingerprint[72]);
int barev_pin_save(const char *profile, const char *own, const char *peer,
                   const char *expected, const char *replacement);
#endif
