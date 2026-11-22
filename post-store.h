/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BAREV_POST_STORE_H
#define BAREV_POST_STORE_H
#include "post.h"
#include "feed-access.h"

#define BAREV_POST_STORE_MAX_NODES 16
#define BAREV_POST_STORE_MAX_POSTS 256
#define BAREV_POST_STORE_MAX_BYTES 4194304
#define BAREV_POST_STORE_MAX_PAGE 32
#define BAREV_POST_STORE_MAX_SNAPSHOT 6291456
enum { BAREV_POST_OKAY, BAREV_POST_INVALID, BAREV_POST_DENIED, BAREV_POST_MISSING,
    BAREV_POST_CONFLICT, BAREV_POST_FULL, BAREV_POST_STALE };
typedef struct BarevPostStore BarevPostStore;
typedef struct BarevPostPage BarevPostPage;
typedef struct { char name[129], title[257]; unsigned model; } BarevPostNodeInfo;
typedef struct {
    BarevPostStore *store;
    int32_t node, generation, next;
    gboolean owner;
} BarevPostCursor;

BarevPostStore *barev_post_store_new(const char *owner, int32_t nodes, int32_t posts, int32_t bytes);
BarevPostStore *barev_post_store_copy(const BarevPostStore *source);
void barev_post_store_close(BarevPostStore **store);
gboolean barev_post_store_owned(const BarevPostStore *store, const char *owner);
unsigned barev_post_store_add_node(BarevPostStore *store, const char *name, const char *title, BarevFeedPolicy *policy);
unsigned barev_post_store_policy(BarevPostStore *store, const char *name, BarevFeedPolicy *policy);
unsigned barev_post_store_put(BarevPostStore *store, const char *node, BarevPost *post);
unsigned barev_post_store_edit(BarevPostStore *store, const char *node, const BarevPost *expected, BarevPost *replacement);
unsigned barev_post_store_retract(BarevPostStore *store, const char *node, const char *item);
/* Retrieved posts are borrowed until the next mutation/close; retain a post
 * reference when it must outlive the store. Returned pages own their posts. */
BarevPost *barev_post_store_get(const BarevPostStore *store, const char *node, const char *item);
BarevPost *barev_post_store_read_post(const BarevPostStore *store, const char *node, const char *item,
    const BarevFeedReader *reader, const BarevFeedContact *contact);
gboolean barev_post_store_node(const BarevPostStore *store, int32_t index, BarevPostNodeInfo *info);
gboolean barev_post_store_reference(const BarevPostStore *store, const char *id, BarevPostNodeInfo *info);
gboolean barev_post_store_describe(const BarevPostStore *store, const char *node,
    const BarevFeedReader *reader, const BarevFeedContact *contact, BarevPostNodeInfo *info);
uint32_t barev_post_store_count(const BarevPostStore *store);
uint32_t barev_post_store_nodes(const BarevPostStore *store);
uint32_t barev_post_store_reserved(const BarevPostStore *store);
uint32_t barev_post_store_bytes(const BarevPostStore *store);
gboolean barev_post_store_extends(const BarevPostStore *previous, const BarevPostStore *next);
/* Cursor records must initially be zeroed. Closing a store invalidates retained
 * cursors; every private page read rechecks the current reader and contact. */
void barev_post_cursor_clear(BarevPostCursor *cursor);
unsigned barev_post_store_begin(BarevPostStore *store, const char *node, BarevPostCursor *cursor);
unsigned barev_post_store_begin_read(BarevPostStore *store, const char *node,
    const BarevFeedReader *reader, const BarevFeedContact *contact, BarevPostCursor *cursor);
unsigned barev_post_store_page(BarevPostCursor *cursor, int32_t maximum, BarevPostPage **page);
unsigned barev_post_store_read_page(BarevPostCursor *cursor, const BarevFeedReader *reader,
    const BarevFeedContact *contact, int32_t maximum, BarevPostPage **page);
size_t barev_post_page_size(const BarevPostPage *page);
BarevPost *barev_post_page_post(const BarevPostPage *page, size_t index);
void barev_post_page_free(BarevPostPage *page);
gboolean barev_post_store_encode(const BarevPostStore *store, unsigned char **bytes, size_t *length);
BarevPostStore *barev_post_store_decode(const unsigned char *bytes, size_t length, const char *owner);
uint32_t barev_post_snapshot_crc(const unsigned char *bytes, size_t length);
#endif
