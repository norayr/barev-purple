/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "post-store.h"
#include <stdio.h>
#include <string.h>

static const char owner[] = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static unsigned checks;
#define CHECK(value) do { ++checks; if (!(value)) g_error("Post store check %u failed: %s", checks, #value); } while (0)

static BarevPostHeader header(unsigned number)
{
    BarevPostHeader h = {0};
    memcpy(h.owner, owner, sizeof(h.owner));
    snprintf(h.item, sizeof(h.item), "post-%u", number); snprintf(h.id, sizeof(h.id), "urn:post:%u", number);
    g_strlcpy(h.author, "Անի@0200:0:0:0:0:0:0:1", sizeof(h.author));
    g_strlcpy(h.title, "Բարեւ 😀", sizeof(h.title));
    g_strlcpy(h.published, "2026-11-20T00:00:00Z", sizeof(h.published));
    memcpy(h.updated, h.published, sizeof(h.updated)); return h;
}
static BarevPost *post(unsigned number, const char *body, const char *parent)
{
    BarevPostHeader h = header(number);
    g_strlcpy(h.parent, parent, sizeof(h.parent)); return barev_post_new(&h, body, strlen(body)+1);
}
static BarevPostStore *fixture(void)
{
    BarevPostStore *store = barev_post_store_new(owner, 8, 16, 65536);
    BarevFeedName names[1] = {"reader@200::2"}, groups[1] = {"ընկերներ"};
    BarevFeedPolicy *open = barev_feed_policy_new(BAREV_FEED_OPEN, NULL, 0, 0);
    BarevFeedPolicy *selected = barev_feed_policy_new(BAREV_FEED_WHITELIST, names, 1, 1);
    BarevFeedPolicy *roster = barev_feed_policy_new(BAREV_FEED_ROSTER, groups, 1, 1);
    BarevPost *p;
    CHECK(store && open && selected && roster);
    CHECK(barev_post_store_add_node(store, "public", "Public", open) == BAREV_POST_OKAY);
    CHECK(barev_post_store_add_node(store, "selected", "Selected", selected) == BAREV_POST_OKAY);
    CHECK(barev_post_store_add_node(store, "group", "Group", roster) == BAREV_POST_OKAY);
    barev_feed_policy_unref(open); barev_feed_policy_unref(selected); barev_feed_policy_unref(roster);
    p = post(1, "Public content", ""); CHECK(p && barev_post_store_put(store, "public", p) == BAREV_POST_OKAY); barev_post_unref(p);
    p = post(2, "Private content", ""); CHECK(p && barev_post_store_put(store, "selected", p) == BAREV_POST_OKAY); barev_post_unref(p);
    p = post(3, "Group content", ""); CHECK(p && barev_post_store_put(store, "group", p) == BAREV_POST_OKAY); barev_post_unref(p);
    p = post(4, "Retracted content", ""); CHECK(p && barev_post_store_put(store, "public", p) == BAREV_POST_OKAY); barev_post_unref(p);
    CHECK(barev_post_store_retract(store, "public", "post-4") == BAREV_POST_OKAY); return store;
}

static void records(void)
{
    BarevPostHeader h = header(1), changed;
    BarevPost *p, *q, *r;
    char body[BAREV_POST_MAX_TEXT_BYTES+2], stamp[21], small[2] = "x", item[33], id[46];
    unsigned char entropy[16];
    unsigned i;
    p = barev_post_new(&h, "Hello <world> & friends", sizeof("Hello <world> & friends")); CHECK(p);
    CHECK(!strcmp(barev_post_header(p)->author, "Անի@200::1"));
    CHECK(!strcmp(barev_post_content(p), "Hello <world> & friends"));
    CHECK(barev_post_size(p) == strlen(h.item)+strlen(h.id)+64+strlen("Անի@200::1")+strlen(h.title)+40+23);
    q = barev_post_new(&h, "Hello <world> & friends", sizeof("Hello <world> & friends")); CHECK(q && barev_post_same(p, q));
    CHECK(!barev_post_revision(p, q));
    changed = h; g_strlcpy(changed.updated, "2026-11-20T00:00:01Z", sizeof(changed.updated));
    r = barev_post_new(&changed, "Edited", 7); CHECK(r && barev_post_revision(p, r));
    CHECK(!barev_post_revision(r, p) && !barev_post_same(r, p)); barev_post_unref(r);
    g_strlcpy(changed.parent, "urn:parent:1", sizeof(changed.parent)); r = barev_post_new(&changed, "Edited", 7);
    CHECK(r && !barev_post_revision(p, r)); barev_post_unref(r);
    changed = h; memcpy(changed.parent, changed.id, sizeof(changed.parent)); CHECK(!barev_post_new(&changed, "Self", 5));
    changed = h; changed.owner[0] = 'G'; CHECK(!barev_post_new(&changed, "Owner", 6));
    changed = h; g_strlcpy(changed.author, "Ani@example.org", sizeof(changed.author)); CHECK(!barev_post_new(&changed, "Author", 7));
    changed = h; g_strlcpy(changed.id, "relative", sizeof(changed.id)); CHECK(!barev_post_new(&changed, "ID", 3));
    changed = h; g_strlcpy(changed.updated, "2026-11-19T23:59:59Z", sizeof(changed.updated)); CHECK(!barev_post_new(&changed, "Time", 5));
    CHECK(!barev_post_new(&h, "", 1)); CHECK(!barev_post_new(&h, "unterminated", 2));
    changed = h; changed.title[0] = 0; r = barev_post_new(&changed, "Untitled", 9); CHECK(r); barev_post_unref(r);
    changed = h; memset(changed.item, 'x', sizeof(changed.item)); CHECK(!barev_post_new(&changed, "Item", 5));
    changed = h; memset(changed.title, 'x', sizeof(changed.title)); CHECK(!barev_post_new(&changed, "Title", 6));
    changed = h; memset(changed.author, 'x', sizeof(changed.author)); CHECK(!barev_post_new(&changed, "Author", 7));
    memset(body, 'x', sizeof(body)); CHECK(!barev_post_new(&h, body, sizeof(body)));
    body[BAREV_POST_MAX_TEXT_BYTES+1] = 0; CHECK(!barev_post_new(&h, body, sizeof(body)));
    body[BAREV_POST_MAX_TEXT_BYTES] = 0; r = barev_post_new(&h, body, sizeof(body)); CHECK(r); barev_post_unref(r);
    for (i = 1; i < 32; ++i) {
        body[0] = i; body[1] = 0; r = barev_post_new(&h, body, sizeof(body));
        CHECK((r != NULL) == (i == 9 || i == 10 || i == 13)); barev_post_unref(r);
    }
    CHECK(!barev_post_text("\300\257", 3, 2, FALSE)); CHECK(!barev_post_text("\355\240\200", 4, 3, FALSE));
    CHECK(!barev_post_text("\357\277\276", 4, 3, FALSE)); CHECK(!barev_post_text("\364\220\200\200", 5, 4, FALSE));
    CHECK(barev_post_text("Բարեւ 😀", sizeof("Բարեւ 😀"), 32, FALSE));
    CHECK(barev_post_text("", 1, 0, TRUE) && !barev_post_text("a", 2, 0, TRUE));
    CHECK(!barev_post_text("a", 2, -1, FALSE) && !barev_post_text("a", 2, INT32_MAX, FALSE));
    CHECK(!barev_post_owner(owner, 64)); CHECK(!barev_post_timestamp(h.published, 20));
    CHECK(!barev_post_token("a", 2, -1) && !barev_post_token("a", 2, INT32_MAX));
    {
        const char *good[] = {"tag:example.org,2026:post-1", "https://example.org/posts/1?x=1#reply", "urn:post:%ff", "x:/", "x://", "x:?", "x:value#"};
        const char *bad[] = {"", "relative", "urn:", "urn:#fragment", "urn:bad id", "urn:%", "urn:%0", "urn:%00", "urn:%xx", "x:/[bad]", "x://[200::1]/", "urn:x#y#z"};
        for (i = 0; i < G_N_ELEMENTS(good); ++i) CHECK(barev_post_reference(good[i], strlen(good[i])+1, FALSE));
        for (i = 0; i < G_N_ELEMENTS(bad); ++i) CHECK(!barev_post_reference(bad[i], strlen(bad[i])+1, FALSE));
        CHECK(barev_post_reference("", 1, TRUE));
        memset(body, 'x', 1026); memcpy(body, "urn:", 4); body[1025] = 0;
        CHECK(!barev_post_reference(body, 1026, FALSE)); body[1024] = 0; CHECK(barev_post_reference(body, 1025, FALSE));
        CHECK(!barev_post_reference(body, 1024, FALSE));
    }
    CHECK(barev_post_timestamp("2000-02-29T23:59:59Z", 21)); CHECK(!barev_post_timestamp("1900-02-29T23:59:59Z", 21));
    CHECK(!barev_post_timestamp("2026-04-31T00:00:00Z", 21)); CHECK(!barev_post_timestamp("0000-01-01T00:00:00Z", 21));
    CHECK(!barev_post_timestamp("2026-01-01T00:00:60Z", 21));
    CHECK(barev_post_utc(0, stamp, sizeof(stamp)) && !strcmp(stamp, "1970-01-01T00:00:00Z"));
    CHECK(barev_post_utc(INT64_C(2147483648), stamp, sizeof(stamp)) && !strcmp(stamp, "2038-01-19T03:14:08Z"));
    CHECK(barev_post_utc(INT64_C(253402300799), stamp, sizeof(stamp)) && !strcmp(stamp, "9999-12-31T23:59:59Z"));
    CHECK(!barev_post_utc(INT64_C(253402300800), stamp, sizeof(stamp)) && !strcmp(stamp, "9999-12-31T23:59:59Z"));
    CHECK(!barev_post_utc(-1, stamp, sizeof(stamp))); CHECK(!barev_post_utc(0, small, sizeof(small)) && !strcmp(small, "x"));
    for (i = 0; i < sizeof(entropy); ++i) entropy[i] = i;
    CHECK(barev_post_identifiers(entropy, sizeof(entropy), item, sizeof(item), id, sizeof(id)));
    CHECK(!strcmp(item, "000102030405460788090a0b0c0d0e0f") && !strcmp(id, "urn:uuid:00010203-0405-4607-8809-0a0b0c0d0e0f"));
    CHECK(entropy[6] == 6 && entropy[8] == 8);
    CHECK(!barev_post_identifiers(entropy, 15, small, sizeof(small), id, sizeof(id)) && !strcmp(small, "x"));
    CHECK(!barev_post_identifiers(entropy, 16, small, sizeof(small), id, sizeof(id)) && !strcmp(small, "x"));
    r = barev_post_ref(p); CHECK(r == p); barev_post_unref(p); CHECK(barev_post_same(r, q));
    barev_post_unref(r); barev_post_unref(q); barev_post_unref(NULL);
    CHECK(!barev_post_ref(NULL) && !barev_post_header(NULL) && !barev_post_content(NULL) && !barev_post_size(NULL));
}

static void access_and_mutations(void)
{
    BarevPostStore *store = fixture(), *copy;
    BarevFeedName names[1] = {"reader@200::2"}, groups[1] = {"ընկերներ"};
    BarevFeedReader reader = {0}, anonymous = {0};
    unsigned char key[32] = {0};
    BarevFeedContact *current = barev_feed_contact_new(names[0], key, 32, TRUE, groups, 1, 1);
    BarevFeedContact *removed = barev_feed_contact_new(names[0], key, 32, TRUE, groups, 1, 0);
    BarevFeedPolicy *policy;
    BarevPostCursor cursor = {0}, private_cursor = {0};
    BarevPostPage *page = NULL, *captured;
    BarevPost *p, *expected, *replacement;
    BarevPostHeader h;
    BarevPostNodeInfo info;
    uint32_t before;
    CHECK(current && removed && barev_feed_reader_authenticate(&reader, names[0], key, 32, TRUE, TRUE));
    barev_feed_reader_anonymous(&anonymous);
    CHECK(barev_post_store_count(store) == 3 && barev_post_store_reserved(store) == 4 && barev_post_store_nodes(store) == 3);
    CHECK(barev_post_store_owned(store, owner) && !barev_post_store_owned(store, "bad"));
    CHECK(barev_post_store_read_post(store, "public", "post-1", &anonymous, NULL));
    CHECK(!barev_post_store_read_post(store, "selected", "post-2", &anonymous, current));
    CHECK(barev_post_store_read_post(store, "selected", "post-2", &reader, current));
    CHECK(barev_post_store_read_post(store, "group", "post-3", &reader, current));
    CHECK(!barev_post_store_read_post(store, "group", "post-3", &reader, removed));
    CHECK(barev_post_store_reference(store, "urn:post:4", &info) && !strcmp(info.name, "public"));
    CHECK(!barev_post_store_describe(store, "selected", &anonymous, current, &info));
    CHECK(barev_post_store_describe(store, "selected", &reader, current, &info));
    CHECK(barev_post_store_begin(store, "public", &cursor) == BAREV_POST_OKAY);
    CHECK(barev_post_store_page(&cursor, 1, &captured) == BAREV_POST_OKAY && barev_post_page_size(captured) == 1);
    CHECK(!strcmp(barev_post_header(barev_post_page_post(captured, 0))->item, "post-1"));
    CHECK(barev_post_store_begin_read(store, "group", &reader, current, &private_cursor) == BAREV_POST_OKAY);
    CHECK(barev_post_store_read_page(&private_cursor, &reader, removed, 1, &page) == BAREV_POST_DENIED && !page);
    CHECK(barev_post_store_read_page(&private_cursor, &reader, current, 1, &page) == BAREV_POST_OKAY && barev_post_page_size(page) == 1);
    barev_post_page_free(page); page = NULL;
    p = post(5, "Widened reply", "urn:post:2"); CHECK(p && barev_post_store_put(store, "public", p) == BAREV_POST_DENIED); barev_post_unref(p);
    p = post(5, "Cross-group reply", "urn:post:2"); CHECK(p && barev_post_store_put(store, "group", p) == BAREV_POST_DENIED); barev_post_unref(p);
    p = post(5, "Independent private reply", "urn:post:1"); CHECK(p && barev_post_store_put(store, "selected", p) == BAREV_POST_OKAY);
    before = barev_post_store_bytes(store); CHECK(barev_post_store_put(store, "selected", p) == BAREV_POST_OKAY && barev_post_store_bytes(store) == before);
    CHECK(barev_post_store_put(store, "public", p) == BAREV_POST_CONFLICT); barev_post_unref(p);
    CHECK(barev_post_store_page(&cursor, 0, &page) == BAREV_POST_INVALID);
    CHECK(barev_post_store_page(&cursor, 1, &page) == BAREV_POST_OKAY && !barev_post_page_size(page)); barev_post_page_free(page); page = NULL;
    p = post(6, "Public reply", "urn:post:1"); CHECK(p && barev_post_store_put(store, "public", p) == BAREV_POST_OKAY); barev_post_unref(p);
    p = post(7, "Forward reply", "urn:post:8"); CHECK(p && barev_post_store_put(store, "public", p) == BAREV_POST_OKAY); barev_post_unref(p);
    p = post(8, "Cyclic reply", "urn:post:7"); CHECK(p && barev_post_store_put(store, "public", p) == BAREV_POST_DENIED); barev_post_unref(p);
    CHECK(barev_post_store_page(&cursor, 1, &page) == BAREV_POST_STALE && !page);
    expected = barev_post_ref(barev_post_store_get(store, "public", "post-1")); CHECK(expected);
    h = *barev_post_header(expected); g_strlcpy(h.updated, "2026-11-20T00:00:01Z", sizeof(h.updated));
    replacement = barev_post_new(&h, "Edited", 7); CHECK(replacement);
    copy = barev_post_store_copy(store); CHECK(copy && barev_post_store_extends(store, copy));
    CHECK(barev_post_store_edit(copy, "public", expected, replacement) == BAREV_POST_OKAY);
    CHECK(barev_post_store_extends(store, copy) && !barev_post_store_extends(copy, store));
    CHECK(barev_post_store_edit(copy, "public", expected, replacement) == BAREV_POST_OKAY);
    CHECK(barev_post_store_edit(copy, "public", replacement, expected) == BAREV_POST_CONFLICT);
    {
        BarevPost *stale;
        g_strlcpy(h.updated, "2026-11-20T00:00:02Z", sizeof(h.updated)); stale = barev_post_new(&h, "Later", 6); CHECK(stale);
        CHECK(barev_post_store_edit(copy, "public", expected, stale) == BAREV_POST_CONFLICT); barev_post_unref(stale);
    }
    CHECK(barev_post_same(barev_post_store_get(store, "public", "post-1"), expected));
    before = barev_post_store_bytes(copy); CHECK(barev_post_store_retract(copy, "public", "post-1") == BAREV_POST_OKAY);
    CHECK(barev_post_store_bytes(copy) == before-barev_post_size(replacement)+strlen(h.item)+strlen(h.id));
    CHECK(barev_post_store_retract(copy, "public", "post-1") == BAREV_POST_OKAY);
    CHECK(barev_post_store_extends(store, copy) && !barev_post_store_extends(copy, store));
    CHECK(barev_post_store_put(copy, "public", expected) == BAREV_POST_CONFLICT);
    policy = barev_feed_policy_new(BAREV_FEED_OPEN, NULL, 0, 0); CHECK(policy);
    CHECK(barev_post_store_policy(copy, "selected", policy) == BAREV_POST_INVALID); barev_feed_policy_unref(policy);
    policy = barev_feed_policy_new(BAREV_FEED_ROSTER, NULL, 0, 0); CHECK(policy);
    CHECK(barev_post_store_policy(store, "group", policy) == BAREV_POST_OKAY); barev_feed_policy_unref(policy);
    CHECK(barev_post_store_read_page(&private_cursor, &reader, current, 1, &page) == BAREV_POST_DENIED && !page);
    CHECK(barev_post_store_retract(store, "selected", "post-2") == BAREV_POST_OKAY);
    p = post(9, "Hidden parent tombstone", "urn:post:2"); CHECK(p && barev_post_store_put(store, "public", p) == BAREV_POST_DENIED); barev_post_unref(p);
    barev_post_store_close(&copy); barev_post_store_close(&store);
    CHECK(barev_post_store_page(&cursor, 1, &page) == BAREV_POST_INVALID);
    CHECK(!strcmp(barev_post_content(barev_post_page_post(captured, 0)), "Public content"));
    barev_post_page_free(captured); barev_post_cursor_clear(&cursor); barev_post_cursor_clear(&private_cursor);
    barev_post_unref(expected); barev_post_unref(replacement); barev_feed_contact_free(current); barev_feed_contact_free(removed);
}

static void limits(void)
{
    BarevPostStore *store;
    BarevFeedPolicy *open = barev_feed_policy_new(BAREV_FEED_OPEN, NULL, 0, 0);
    BarevPost *p = post(1, "Body", "");
    BarevPostHeader h;
    unsigned i;
    char name[129];
    CHECK(open && p); CHECK(!barev_post_store_new("bad", 1, 1, 1));
    CHECK(!barev_post_store_new(owner, 0, 1, 1) && !barev_post_store_new(owner, 17, 1, 1));
    CHECK(!barev_post_store_new(owner, 1, 0, 1) && !barev_post_store_new(owner, 1, 257, 1));
    CHECK(!barev_post_store_new(owner, 1, 1, INT32_MAX));
    store = barev_post_store_new(owner, 1, 1, 6); CHECK(store);
    CHECK(barev_post_store_add_node(store, "pub", "Pub", open) == BAREV_POST_OKAY);
    CHECK(barev_post_store_put(store, "pub", p) == BAREV_POST_FULL); barev_post_store_close(&store);
    store = barev_post_store_new(owner, 16, 256, BAREV_POST_STORE_MAX_BYTES); CHECK(store);
    for (i = 0; i < 16; ++i) {
        snprintf(name, sizeof(name), "node-%u", i); CHECK(barev_post_store_add_node(store, name, "Node", open) == BAREV_POST_OKAY);
    }
    CHECK(barev_post_store_add_node(store, "extra", "Extra", open) == BAREV_POST_FULL);
    CHECK(barev_post_store_add_node(store, "node-0", "Duplicate", open) == BAREV_POST_CONFLICT);
    for (i = 1; i <= 256; ++i) {
        BarevPost *next = post(i, "Body", ""); CHECK(next);
        CHECK(barev_post_store_put(store, "node-0", next) == BAREV_POST_OKAY); barev_post_unref(next);
    }
    CHECK(barev_post_store_count(store) == 256); CHECK(barev_post_store_retract(store, "node-0", "post-1") == BAREV_POST_OKAY);
    { BarevPost *next = post(257, "Body", ""); CHECK(next && barev_post_store_put(store, "node-0", next) == BAREV_POST_FULL); barev_post_unref(next); }
    h = *barev_post_header(p); memset(h.owner, '0', 64);
    { BarevPost *next = barev_post_new(&h, "Body", 5); CHECK(next && barev_post_store_put(store, "node-0", next) == BAREV_POST_DENIED); barev_post_unref(next); }
    barev_post_store_close(&store); barev_post_unref(p); barev_feed_policy_unref(open);
    {
        char body[BAREV_POST_MAX_TEXT_BYTES+1];
        unsigned char *bytes;
        size_t length;
        unsigned status = BAREV_POST_OKAY, added = 0;
        BarevPostStore *restored;
        memset(body, 'x', sizeof(body)-1); body[sizeof(body)-1] = 0;
        open = barev_feed_policy_new(BAREV_FEED_OPEN, NULL, 0, 0);
        store = barev_post_store_new(owner, 1, 256, BAREV_POST_STORE_MAX_BYTES); CHECK(store && open);
        CHECK(barev_post_store_add_node(store, "public", "Public", open) == BAREV_POST_OKAY); barev_feed_policy_unref(open);
        for (i = 0; i < 256 && status == BAREV_POST_OKAY; ++i) {
            BarevPostHeader next_header = header(i);
            BarevPost *next = barev_post_new(&next_header, body, sizeof(body)); CHECK(next);
            status = barev_post_store_put(store, "public", next); barev_post_unref(next);
            if (status == BAREV_POST_OKAY) ++added;
        }
        CHECK(status == BAREV_POST_FULL && added > 200 && added < 256);
        CHECK(barev_post_store_bytes(store) <= BAREV_POST_STORE_MAX_BYTES && barev_post_store_count(store) == added);
        CHECK(barev_post_store_encode(store, &bytes, &length) && length > 4000000 && length <= BAREV_POST_STORE_MAX_SNAPSHOT);
        restored = barev_post_store_decode(bytes, length, owner); CHECK(restored && barev_post_store_count(restored) == added);
        CHECK(barev_post_store_extends(store, restored) && barev_post_store_extends(restored, store));
        g_free(bytes); barev_post_store_close(&restored); barev_post_store_close(&store);
    }
}

static void codec(void)
{
    BarevPostStore *store = fixture(), *restored, *copy;
    unsigned char *bytes = NULL, *other = NULL;
    size_t n = 0, m = 0, i;
    unsigned char saved;
    CHECK(barev_post_snapshot_crc((const unsigned char *)"123456789", 9) == UINT32_C(0xcbf43926));
    CHECK(barev_post_store_encode(store, &bytes, &n) && bytes && n > 100);
    restored = barev_post_store_decode(bytes, n, owner); CHECK(restored);
    CHECK(barev_post_store_count(restored) == 3 && barev_post_store_reserved(restored) == 4 && barev_post_store_nodes(restored) == 3);
    CHECK(barev_post_store_bytes(restored) == barev_post_store_bytes(store));
    CHECK(barev_post_store_extends(store, restored) && barev_post_store_extends(restored, store));
    CHECK(barev_post_store_encode(restored, &other, &m) && n == m && !memcmp(bytes, other, n));
    for (i = 0; i < n; ++i) {
        copy = barev_post_store_decode(bytes, i, owner); CHECK(!copy);
        saved = bytes[i]; bytes[i] ^= 1; copy = barev_post_store_decode(bytes, n, owner); CHECK(!copy); bytes[i] = saved;
    }
    for (i = 0; i < n-4; i += 3) {
        uint32_t crc;
        size_t j;
        saved = bytes[i]; bytes[i] ^= 128; crc = barev_post_snapshot_crc(bytes, n-4);
        for (j = 0; j < 4; ++j) bytes[n-4+j] = crc >> (24-8*j);
        copy = barev_post_store_decode(bytes, n, owner);
        if (copy) {
            BarevPostStore *again;
            unsigned char *encoded;
            size_t encoded_length;
            CHECK(barev_post_store_encode(copy, &encoded, &encoded_length));
            again = barev_post_store_decode(encoded, encoded_length, owner); CHECK(again);
            CHECK(barev_post_store_extends(copy, again) && barev_post_store_extends(again, copy));
            barev_post_store_close(&again); g_free(encoded);
        }
        barev_post_store_close(&copy); bytes[i] = saved;
    }
    saved = bytes[20]; bytes[20] ^= 1;
    { uint32_t crc = barev_post_snapshot_crc(bytes, n-4); for (i = 0; i < 4; ++i) bytes[n-4+i] = crc >> (24-8*i); }
    copy = barev_post_store_decode(bytes, n, owner); CHECK(!copy); bytes[20] = saved;
    CHECK(!barev_post_store_decode(NULL, n, owner)); CHECK(!barev_post_store_decode(bytes, n, "bad"));
    barev_post_store_close(&store); barev_post_store_close(&restored); g_free(bytes); g_free(other);
}

static void matrix(void)
{
    unsigned i, j;
    const char *prefixes[] = {"urn:x", "x:/", "x://", "x:/?", "urn:x#", "", "urn:x%"};
    char sample[64];
    puts("post-validation-v1");
    for (i = 1; i <= 255; ++i) {
        char raw[4] = {'a', (char)i, 'b', 0};
        printf("%u %u %u", i, barev_post_token(raw, sizeof(raw), 128) ? 1u : 0u,
            barev_post_text(raw, sizeof(raw), 16384, FALSE) ? 1u : 0u);
        for (j = 0; j < G_N_ELEMENTS(prefixes); ++j) {
            size_t at = strlen(prefixes[j]); memcpy(sample, prefixes[j], at); sample[at++] = i;
            g_strlcpy(sample+at, j == 5 ? ":value" : j == 6 ? "0" : "y", sizeof(sample)-at);
            printf(" %u", barev_post_reference(sample, sizeof(sample), FALSE) ? 1u : 0u);
        }
        puts("");
    }
}

int main(int argc, char **argv)
{
    BarevPostStore *store;
    unsigned char *bytes;
    char *input = NULL;
    size_t length;
    if (argc == 2 && !strcmp(argv[1], "--matrix")) { matrix(); return 0; }
    if (argc == 3 && !strcmp(argv[1], "--write")) {
        store = fixture(); CHECK(barev_post_store_encode(store, &bytes, &length));
        CHECK(g_file_set_contents(argv[2], (char *)bytes, length, NULL));
        g_free(bytes); barev_post_store_close(&store); return 0;
    }
    if ((argc == 3 && !strcmp(argv[1], "--check")) || (argc == 4 && !strcmp(argv[1], "--roundtrip"))) {
        CHECK(g_file_get_contents(argv[2], &input, &length, NULL)); store = barev_post_store_decode((unsigned char *)input, length, owner); g_free(input);
        if (argc == 3) { printf("%u\n", store ? 0u : 1u); barev_post_store_close(&store); return 0; }
        CHECK(store && barev_post_store_encode(store, &bytes, &length));
        CHECK(g_file_set_contents(argv[3], (char *)bytes, length, NULL)); g_free(bytes); barev_post_store_close(&store); return 0;
    }
    if (argc != 1) return 2;
    records(); access_and_mutations(); limits(); codec();
    printf("C post records/store: %u checks passed\n", checks); return 0;
}
