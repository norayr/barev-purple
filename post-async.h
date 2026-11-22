/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BAREV_POST_ASYNC_H
#define BAREV_POST_ASYNC_H
#include "post-store.h"
enum { BAREV_POST_ASYNC_OKAY, BAREV_POST_ASYNC_MISSING, BAREV_POST_ASYNC_INVALID,
    BAREV_POST_ASYNC_STORAGE_ERROR, BAREV_POST_ASYNC_CHANGED,
    BAREV_POST_ASYNC_PENDING, BAREV_POST_ASYNC_BUSY };
typedef struct BarevPostContext BarevPostContext;
typedef struct BarevPostRequest BarevPostRequest;

/* Calls belong to the thread that starts the service. Request/context slots
 * initially contain NULL; loaded outputs must be empty. Cancel/close retire
 * application state while accepted opaque-byte writes may still finish. */
gboolean barev_post_async_start(void);
gboolean barev_post_async_ready(const BarevPostContext *context);
void barev_post_async_close(BarevPostContext **context);
void barev_post_async_cancel(BarevPostRequest **request);
unsigned barev_post_async_load(const char *profile, const char *owner, BarevPostRequest **request);
unsigned barev_post_async_loaded(BarevPostRequest **request, BarevPostContext **context, BarevPostStore **store);
unsigned barev_post_async_save(BarevPostContext *context, BarevPostStore *store, BarevPostRequest **request);
unsigned barev_post_async_saved(BarevPostRequest **request);
void barev_post_async_stop(void);
gboolean barev_post_async_idle(void);
#endif
