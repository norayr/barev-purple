/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "post-async.h"
#include "identity-store.h"
#include <stdio.h>
#include <string.h>

static const char owner[] = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static unsigned checks;
#define CHECK(value) do { ++checks; if (!(value)) g_error("Post async check %u failed: %s", checks, #value); } while (0)

static unsigned loaded(BarevPostRequest **request, BarevPostContext **context, BarevPostStore **store)
{
    gint64 end = g_get_monotonic_time()+5000000;
    unsigned status;
    while ((status = barev_post_async_loaded(request, context, store)) == BAREV_POST_ASYNC_PENDING && g_get_monotonic_time() < end) g_usleep(1000);
    return status;
}
static unsigned saved(BarevPostRequest **request)
{
    gint64 end = g_get_monotonic_time()+5000000;
    unsigned status;
    while ((status = barev_post_async_saved(request)) == BAREV_POST_ASYNC_PENDING && g_get_monotonic_time() < end) g_usleep(1000);
    return status;
}
static gboolean drain(void)
{
    gint64 end = g_get_monotonic_time()+5000000;
    while (!barev_post_async_idle() && g_get_monotonic_time() < end) g_usleep(1000);
    return barev_post_async_idle();
}
static BarevPostStore *fresh(void)
{
    BarevPostStore *store = barev_post_store_new(owner, 8, 32, 65536);
    BarevFeedPolicy *policy = barev_feed_policy_new(BAREV_FEED_OPEN, NULL, 0, 0);
    CHECK(store && policy && barev_post_store_add_node(store, "public", "Public", policy) == BAREV_POST_OKAY);
    barev_feed_policy_unref(policy); return store;
}
static void add(BarevPostStore *store, unsigned number)
{
    BarevPostHeader header = {0};
    BarevPost *post;
    memcpy(header.owner, owner, sizeof(header.owner));
    snprintf(header.item, sizeof(header.item), "post-%u", number); snprintf(header.id, sizeof(header.id), "urn:post:%u", number);
    g_strlcpy(header.author, "Անի@200::1", sizeof(header.author));
    g_strlcpy(header.title, "Բարեւ 😀", sizeof(header.title));
    g_strlcpy(header.published, "2026-11-22T00:00:00Z", sizeof(header.published)); memcpy(header.updated, header.published, sizeof(header.updated));
    post = barev_post_new(&header, "Durable text", sizeof("Durable text"));
    CHECK(post && barev_post_store_put(store, "public", post) == BAREV_POST_OKAY); barev_post_unref(post);
}
typedef struct { BarevPostContext *context; BarevPostStore *store; } Foreign;
static gpointer foreign(gpointer data)
{
    Foreign *input = data;
    BarevPostContext *context = input->context;
    BarevPostRequest *request = NULL;
    gboolean okay = !barev_post_async_start() && !barev_post_async_ready(context) && !barev_post_async_idle();
    okay = okay && barev_post_async_save(context, input->store, &request) == BAREV_POST_ASYNC_INVALID && !request;
    barev_post_async_close(&context); barev_post_async_stop();
    return GINT_TO_POINTER(okay && context == input->context);
}

static void operations(const char *profile)
{
    BarevPostRequest *request = NULL, *second_request = NULL, *jobs[5] = {0};
    BarevPostContext *context = NULL, *second = NULL;
    BarevPostStore *store = NULL, *other = NULL, *empty;
    Foreign input;
    unsigned i;
    int32_t lock;
    CHECK(barev_post_async_load("relative", owner, &request) == BAREV_POST_ASYNC_INVALID && !request);
    CHECK(barev_post_async_load("/", owner, &request) == BAREV_POST_ASYNC_INVALID && !request);
    CHECK(barev_post_async_load(profile, "bad", &request) == BAREV_POST_ASYNC_INVALID && !request);
    CHECK(barev_post_async_load(profile, owner, &request) == BAREV_POST_ASYNC_PENDING && request);
    CHECK(barev_post_async_load("relative", "bad", &request) == BAREV_POST_ASYNC_BUSY);
    CHECK(barev_post_async_saved(&request) == BAREV_POST_ASYNC_INVALID && request);
    empty = fresh();
    CHECK(barev_post_async_loaded(&request, &context, &empty) == BAREV_POST_ASYNC_INVALID && request && empty && !context);
    barev_post_store_close(&empty);
    CHECK(loaded(&request, &context, &store) == BAREV_POST_ASYNC_MISSING && !request && context && !store);
    CHECK(barev_post_async_ready(context)); store = fresh();
    input = (Foreign){context, store}; CHECK(GPOINTER_TO_INT(g_thread_join(g_thread_new("foreign-post-async", foreign, &input))));
    CHECK(barev_post_async_ready(context));
    CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_PENDING && request);
    CHECK(!barev_post_async_ready(context));
    CHECK(barev_post_async_save(context, store, &second_request) == BAREV_POST_ASYNC_BUSY && !second_request);
    add(store, 1);
    CHECK(saved(&request) == BAREV_POST_ASYNC_OKAY && !request && barev_post_async_ready(context));
    CHECK(barev_post_async_load(profile, owner, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(loaded(&request, &second, &other) == BAREV_POST_ASYNC_OKAY && barev_post_store_count(other) == 0);
    barev_post_async_close(&second); barev_post_store_close(&other);
    CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(saved(&request) == BAREV_POST_ASYNC_OKAY);
    CHECK(barev_post_async_load(profile, owner, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(loaded(&request, &second, &other) == BAREV_POST_ASYNC_OKAY && barev_post_store_count(other) == 1);
    empty = fresh(); CHECK(barev_post_async_save(context, empty, &request) == BAREV_POST_ASYNC_CHANGED && !request);
    CHECK(barev_post_async_ready(context)); barev_post_store_close(&empty);
    add(store, 2); add(other, 3);
    CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(saved(&request) == BAREV_POST_ASYNC_OKAY);
    CHECK(barev_post_async_save(second, other, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(saved(&request) == BAREV_POST_ASYNC_CHANGED && !barev_post_async_ready(second));
    CHECK(barev_post_async_save(second, other, &request) == BAREV_POST_ASYNC_CHANGED);
    barev_post_async_close(&second); barev_post_store_close(&other);
    lock = BarevIdentityFile_Open(profile); CHECK(lock >= 0); add(store, 4);
    CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(saved(&request) == BAREV_POST_ASYNC_STORAGE_ERROR && !barev_post_async_ready(context));
    BarevIdentityFile_Close(lock);
    CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_CHANGED);
    barev_post_async_close(&context); barev_post_store_close(&store);
    CHECK(barev_post_async_load(profile, owner, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(loaded(&request, &context, &store) == BAREV_POST_ASYNC_OKAY && barev_post_store_count(store) == 2);
    CHECK(!barev_post_store_get(store, "public", "post-3") && !barev_post_store_get(store, "public", "post-4"));
    add(store, 5); CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_PENDING);
    barev_post_async_cancel(&request); CHECK(!request && !barev_post_async_ready(context)); CHECK(drain());
    barev_post_async_close(&context); barev_post_store_close(&store);
    CHECK(barev_post_async_load(profile, owner, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(loaded(&request, &context, &store) == BAREV_POST_ASYNC_OKAY && barev_post_store_count(store) == 3);
    CHECK(barev_post_store_get(store, "public", "post-5"));
    add(store, 6); CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_PENDING);
    barev_post_async_close(&context); CHECK(!context);
    CHECK(saved(&request) == BAREV_POST_ASYNC_INVALID && !request); CHECK(drain()); barev_post_store_close(&store);
    CHECK(barev_post_async_load(profile, owner, &request) == BAREV_POST_ASYNC_PENDING);
    CHECK(loaded(&request, &context, &store) == BAREV_POST_ASYNC_OKAY && barev_post_store_count(store) == 4);
    CHECK(barev_post_store_get(store, "public", "post-6"));
    for (i = 0; i < 4; ++i) CHECK(barev_post_async_load(profile, owner, &jobs[i]) == BAREV_POST_ASYNC_PENDING);
    CHECK(barev_post_async_load(profile, owner, &jobs[4]) == BAREV_POST_ASYNC_BUSY && !jobs[4]);
    for (i = 0; i < 4; ++i) { barev_post_async_cancel(&jobs[i]); CHECK(!jobs[i]); }
    CHECK(drain());
    add(store, 7); CHECK(barev_post_async_save(context, store, &request) == BAREV_POST_ASYNC_PENDING);
    barev_post_async_stop(); CHECK(saved(&request) == BAREV_POST_ASYNC_INVALID && !request);
    CHECK(!barev_post_async_ready(context)); CHECK(drain());
    CHECK(barev_post_async_load(profile, owner, &request) == BAREV_POST_ASYNC_BUSY && !request);
    barev_post_async_close(&context); barev_post_store_close(&store); CHECK(barev_post_async_start());
}

int main(int argc, char **argv)
{
    BarevPostContext *context = NULL;
    BarevPostRequest *request = NULL;
    BarevPostStore *store = NULL;
    unsigned status;
    CHECK(argc == 3); CHECK(barev_post_async_idle()); CHECK(barev_post_async_start());
    if (!strcmp(argv[2], "new")) operations(argv[1]);
    CHECK(barev_post_async_load(argv[1], owner, &request) == BAREV_POST_ASYNC_PENDING);
    status = loaded(&request, &context, &store);
    if (!strcmp(argv[2], "invalid")) CHECK(status == BAREV_POST_ASYNC_INVALID && !request && !context && !store);
    else if (!strcmp(argv[2], "missing")) CHECK(status == BAREV_POST_ASYNC_MISSING && !store && barev_post_async_ready(context));
    else {
        CHECK(status == BAREV_POST_ASYNC_OKAY && !request && context && barev_post_async_ready(context));
        CHECK(barev_post_store_count(store) == 5 && barev_post_store_reserved(store) == 5);
        CHECK(barev_post_store_get(store, "public", "post-1") && barev_post_store_get(store, "public", "post-2") &&
            barev_post_store_get(store, "public", "post-5") && barev_post_store_get(store, "public", "post-6") &&
            barev_post_store_get(store, "public", "post-7"));
        CHECK(!barev_post_store_get(store, "public", "post-3") && !barev_post_store_get(store, "public", "post-4"));
    }
    barev_post_async_close(&context); barev_post_store_close(&store); barev_post_async_cancel(&request);
    CHECK(!context && !store && !request); barev_post_async_stop(); CHECK(drain());
    printf("C post async: %u checks passed\n", checks); return 0;
}
