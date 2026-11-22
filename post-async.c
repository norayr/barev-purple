/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "post-async.h"
#include "post-io.h"
#include <string.h>

struct BarevPostContext {
    unsigned refs;
    char profile[3801], owner[65];
    unsigned char *image;
    size_t length;
    BarevPostStore *baseline;
    gboolean active, busy, blocked;
};
struct BarevPostRequest {
    BarevPostContext *context;
    int32_t job;
    unsigned kind;
    unsigned char *image;
    size_t length;
    BarevPostStore *baseline;
};
enum { LOADING = 1, SAVING };
static GThread *owner_thread;

static gboolean owned(void) { return owner_thread && owner_thread == g_thread_self(); }
static void unref(BarevPostContext *context) { if (!--context->refs) g_free(context); }

gboolean barev_post_async_start(void)
{
    if (owner_thread && !owned()) return FALSE;
    if (!BarevPostIO_Start()) return FALSE;
    owner_thread = g_thread_self(); return TRUE;
}
gboolean barev_post_async_ready(const BarevPostContext *context)
{ return owned() && context && context->active && !context->busy && !context->blocked; }

static void deactivate(BarevPostContext *context)
{
    context->active = FALSE;
    barev_post_store_close(&context->baseline); g_free(context->image); context->image = NULL; context->length = 0;
}

void barev_post_async_close(BarevPostContext **pointer)
{
    BarevPostContext *context;
    if (!owned() || !pointer || !(context = *pointer)) return;
    *pointer = NULL; deactivate(context); unref(context);
}

static void retire(BarevPostRequest **pointer)
{
    BarevPostRequest *request = *pointer;
    *pointer = NULL;
    BarevPostIO_Release(request->job); barev_post_store_close(&request->baseline); g_free(request->image);
    request->context->busy = FALSE; unref(request->context); g_free(request);
}

void barev_post_async_cancel(BarevPostRequest **pointer)
{
    BarevPostContext *context;
    BarevPostRequest *request;
    if (!owned() || !pointer || !(request = *pointer)) return;
    context = request->context;
    if (request->kind == LOADING) deactivate(context);
    else context->blocked = TRUE;
    retire(pointer);
}

unsigned barev_post_async_load(const char *profile, const char *owner, BarevPostRequest **pointer)
{
    BarevPostContext *context;
    BarevPostRequest *request;
    size_t n;
    if (!owned() || !pointer) return BAREV_POST_ASYNC_INVALID;
    if (*pointer) return BAREV_POST_ASYNC_BUSY;
    if (!profile || !barev_post_owner(owner, 65)) return BAREV_POST_ASYNC_INVALID;
    for (n = 0; n <= 3800 && profile[n]; ++n) {}
    if (n < 2 || n > 3800 || profile[0] != '/') return BAREV_POST_ASYNC_INVALID;
    while (n > 1 && profile[n-1] == '/') --n;
    if (n < 2) return BAREV_POST_ASYNC_INVALID;
    context = g_try_new0(BarevPostContext, 1); request = g_try_new0(BarevPostRequest, 1);
    if (!context || !request) { g_free(context); g_free(request); return BAREV_POST_ASYNC_BUSY; }
    context->refs = 1; context->active = TRUE; memcpy(context->profile, profile, n); memcpy(context->owner, owner, 65);
    request->context = context; request->kind = LOADING; request->job = BarevPostIO_Read(context->profile, context->owner);
    if (!request->job) { g_free(request); g_free(context); return BAREV_POST_ASYNC_BUSY; }
    *pointer = request; return BAREV_POST_ASYNC_PENDING;
}

unsigned barev_post_async_loaded(BarevPostRequest **pointer, BarevPostContext **output, BarevPostStore **store)
{
    BarevPostRequest *request;
    BarevPostContext *context;
    BarevPostStore *baseline = NULL, *loaded = NULL;
    unsigned char *bytes = NULL;
    int32_t status, length;
    if (!owned() || !pointer || !(request = *pointer) || request->kind != LOADING || !output || !store || *output || *store)
        return BAREV_POST_ASYNC_INVALID;
    status = BarevPostIO_Status(request->job); if (status == BAREV_POST_IO_PENDING) return BAREV_POST_ASYNC_PENDING;
    context = request->context;
    if (status == BAREV_POST_IO_OKAY) {
        length = BarevPostIO_Length(request->job);
        if (length < 4 || length > BAREV_POST_STORE_MAX_SNAPSHOT) status = BAREV_POST_IO_INVALID;
        else {
            bytes = g_try_malloc(length);
            if (!bytes || BarevPostIO_Copy(request->job, bytes, length) != length) status = BAREV_POST_IO_ERROR;
            else {
                baseline = barev_post_store_decode(bytes, length, context->owner);
                loaded = barev_post_store_decode(bytes, length, context->owner);
                if (!baseline || !loaded) status = BAREV_POST_IO_INVALID;
                else { context->image = bytes; bytes = NULL; context->length = length; context->baseline = baseline; baseline = NULL; }
            }
        }
    }
    g_free(bytes); barev_post_store_close(&baseline);
    if (status == BAREV_POST_IO_OKAY || status == BAREV_POST_IO_MISSING) {
        ++context->refs; *output = context; *store = loaded; retire(pointer);
    } else { barev_post_store_close(&loaded); barev_post_async_cancel(pointer); }
    return status;
}

unsigned barev_post_async_save(BarevPostContext *context, BarevPostStore *store, BarevPostRequest **pointer)
{
    BarevPostRequest *request;
    int32_t expected;
    if (!owned() || !pointer) return BAREV_POST_ASYNC_INVALID;
    if (*pointer) return BAREV_POST_ASYNC_BUSY;
    if (!context || !context->active || !barev_post_store_owned(store, context->owner)) return BAREV_POST_ASYNC_INVALID;
    if (context->blocked) return BAREV_POST_ASYNC_CHANGED;
    if (context->busy) return BAREV_POST_ASYNC_BUSY;
    if (context->baseline && !barev_post_store_extends(context->baseline, store)) return BAREV_POST_ASYNC_CHANGED;
    request = g_try_new0(BarevPostRequest, 1); if (!request) return BAREV_POST_ASYNC_BUSY;
    if (!barev_post_store_encode(store, &request->image, &request->length)) { g_free(request); return BAREV_POST_ASYNC_INVALID; }
    request->baseline = barev_post_store_decode(request->image, request->length, context->owner);
    if (!request->baseline) { g_free(request->image); g_free(request); return BAREV_POST_ASYNC_INVALID; }
    expected = context->image ? (int32_t)context->length : -1;
    request->job = BarevPostIO_Replace(context->profile, context->owner, context->image, expected, request->image, request->length);
    if (!request->job) { barev_post_store_close(&request->baseline); g_free(request->image); g_free(request); return BAREV_POST_ASYNC_BUSY; }
    request->kind = SAVING; request->context = context; ++context->refs;
    context->busy = TRUE; *pointer = request; return BAREV_POST_ASYNC_PENDING;
}

unsigned barev_post_async_saved(BarevPostRequest **pointer)
{
    BarevPostRequest *request;
    BarevPostContext *context;
    int32_t status;
    if (!owned() || !pointer || !(request = *pointer) || request->kind != SAVING) return BAREV_POST_ASYNC_INVALID;
    context = request->context;
    if (!context->active) { barev_post_async_cancel(pointer); return BAREV_POST_ASYNC_INVALID; }
    status = BarevPostIO_Status(request->job); if (status == BAREV_POST_IO_PENDING) return BAREV_POST_ASYNC_PENDING;
    if (status == BAREV_POST_IO_OKAY) {
        barev_post_store_close(&context->baseline); g_free(context->image);
        context->baseline = request->baseline; request->baseline = NULL;
        context->image = request->image; request->image = NULL; context->length = request->length;
    } else context->blocked = TRUE;
    retire(pointer); return status;
}

void barev_post_async_stop(void) { if (owned()) BarevPostIO_Stop(); }
gboolean barev_post_async_idle(void) { return (!owner_thread || owned()) && BarevPostIO_Idle(); }
