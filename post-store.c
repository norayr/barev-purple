/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "post-store.h"
#include <limits.h>
#include <string.h>

typedef struct {
    char name[129], title[257];
    BarevFeedPolicy *policy;
    int32_t generation;
} Node;
typedef struct { unsigned node; char item[129], id[1025]; BarevPost *post; } Slot;
struct BarevPostStore {
    unsigned refs;
    gboolean active;
    char owner[65];
    uint32_t node_limit, post_limit, byte_limit, nodes, used, live, bytes;
    Node destinations[BAREV_POST_STORE_MAX_NODES];
    Slot slots[BAREV_POST_STORE_MAX_POSTS];
};
struct BarevPostPage { size_t size; BarevPost *posts[BAREV_POST_STORE_MAX_PAGE]; };

static gboolean valid(const BarevPostStore *store) { return store && store->active; }
static void unref(BarevPostStore *store) { if (store && !--store->refs) g_free(store); }

BarevPostStore *barev_post_store_new(const char *owner, int32_t nodes, int32_t posts, int32_t bytes)
{
    BarevPostStore *store;
    if (!barev_post_owner(owner, 65) || nodes < 1 || nodes > BAREV_POST_STORE_MAX_NODES ||
        posts < 1 || posts > BAREV_POST_STORE_MAX_POSTS || bytes < 1 || bytes > BAREV_POST_STORE_MAX_BYTES) return NULL;
    store = g_try_new0(BarevPostStore, 1); if (!store) return NULL;
    store->refs = 1; store->active = TRUE; memcpy(store->owner, owner, 65);
    store->node_limit = nodes; store->post_limit = posts; store->byte_limit = bytes; return store;
}

void barev_post_store_close(BarevPostStore **pointer)
{
    BarevPostStore *store;
    unsigned i;
    if (!pointer || !(store = *pointer)) return;
    *pointer = NULL; store->active = FALSE;
    for (i = 0; i < store->nodes; ++i) barev_feed_policy_unref(store->destinations[i].policy);
    for (i = 0; i < store->used; ++i) barev_post_unref(store->slots[i].post);
    store->nodes = store->used = store->live = store->bytes = 0; unref(store);
}

BarevPostStore *barev_post_store_copy(const BarevPostStore *source)
{
    BarevPostStore *store;
    unsigned i;
    if (!valid(source)) return NULL;
    store = barev_post_store_new(source->owner, source->node_limit, source->post_limit, source->byte_limit);
    if (!store) return NULL;
    for (i = 0; i < source->nodes; ++i) {
        Node node = source->destinations[i];
        node.policy = barev_feed_policy_ref(node.policy);
        if (!node.policy) goto failed;
        store->destinations[store->nodes++] = node;
    }
    for (i = 0; i < source->used; ++i) {
        Slot slot = source->slots[i];
        if (slot.post && !(slot.post = barev_post_ref(slot.post))) goto failed;
        store->slots[store->used++] = slot;
    }
    store->live = source->live; store->bytes = source->bytes; return store;
failed:
    barev_post_store_close(&store); return NULL;
}

gboolean barev_post_store_owned(const BarevPostStore *store, const char *owner)
{ return valid(store) && barev_post_owner(owner, 65) && !strcmp(store->owner, owner); }

static int node_index(const BarevPostStore *store, const char *name)
{
    unsigned i;
    if (!valid(store) || !barev_post_token(name, 129, 128)) return -1;
    for (i = 0; i < store->nodes; ++i) if (!strcmp(store->destinations[i].name, name)) return i;
    return -1;
}

static int post_index(const BarevPostStore *store, unsigned node, const char *item)
{
    unsigned i;
    if (!barev_post_token(item, 129, 128)) return -1;
    for (i = 0; i < store->used; ++i) if (store->slots[i].node == node && !strcmp(store->slots[i].item, item)) return i;
    return -1;
}

unsigned barev_post_store_add_node(BarevPostStore *store, const char *name, const char *title, BarevFeedPolicy *policy)
{
    unsigned model = barev_feed_policy_model(policy);
    size_t bytes;
    Node *node;
    if (!valid(store) || !barev_post_token(name, 129, 128) || !barev_post_text(title, 257, 256, FALSE) ||
        model < BAREV_FEED_OPEN || model > BAREV_FEED_WHITELIST) return BAREV_POST_INVALID;
    if (node_index(store, name) >= 0) return BAREV_POST_CONFLICT;
    bytes = strlen(name)+strlen(title);
    if (store->nodes == store->node_limit || bytes > store->byte_limit-store->bytes) return BAREV_POST_FULL;
    policy = barev_feed_policy_ref(policy); if (!policy) return BAREV_POST_FULL;
    node = &store->destinations[store->nodes++]; node->policy = policy; node->generation = 1;
    g_strlcpy(node->name, name, sizeof(node->name)); g_strlcpy(node->title, title, sizeof(node->title));
    store->bytes += bytes; return BAREV_POST_OKAY;
}

unsigned barev_post_store_policy(BarevPostStore *store, const char *name, BarevFeedPolicy *policy)
{
    int index;
    Node *node;
    unsigned model = barev_feed_policy_model(policy);
    if (!valid(store)) return BAREV_POST_INVALID;
    index = node_index(store, name); if (index < 0) return BAREV_POST_MISSING;
    node = &store->destinations[index];
    if (!model || model != barev_feed_policy_model(node->policy)) return BAREV_POST_INVALID;
    if (policy == node->policy) return BAREV_POST_OKAY;
    if (node->generation == INT32_MAX || !(policy = barev_feed_policy_ref(policy))) return BAREV_POST_FULL;
    barev_feed_policy_unref(node->policy); node->policy = policy; ++node->generation; return BAREV_POST_OKAY;
}

static gboolean parent_allowed(const BarevPostStore *store, unsigned node, const BarevPostHeader *header)
{
    unsigned i, steps = 0;
    const char *id = header->parent;
    if (!*id) return TRUE;
    for (i = 0; i < store->used; ++i) if (!strcmp(store->slots[i].id, id) && store->slots[i].node != node &&
        barev_feed_policy_model(store->destinations[store->slots[i].node].policy) != BAREV_FEED_OPEN) return FALSE;
    while (*id) {
        int found = -1;
        const BarevPostHeader *previous;
        if (!strcmp(id, header->id) || steps > store->used) return FALSE;
        for (i = 0; i < store->used; ++i) if (!strcmp(store->slots[i].id, id)) found = i;
        if (found < 0 || !(previous = barev_post_header(store->slots[found].post))) return TRUE;
        id = previous->parent; ++steps;
    }
    return TRUE;
}

unsigned barev_post_store_put(BarevPostStore *store, const char *name, BarevPost *post)
{
    const BarevPostHeader *header = barev_post_header(post);
    unsigned i;
    int index;
    Slot *slot;
    Node *node;
    if (!valid(store) || !header) return BAREV_POST_INVALID;
    if (strcmp(store->owner, header->owner)) return BAREV_POST_DENIED;
    index = node_index(store, name); if (index < 0) return BAREV_POST_MISSING;
    for (i = 0; i < store->used; ++i) if (!strcmp(store->slots[i].item, header->item) || !strcmp(store->slots[i].id, header->id)) {
        if (store->slots[i].node == (unsigned)index && barev_post_same(store->slots[i].post, post)) return BAREV_POST_OKAY;
        return BAREV_POST_CONFLICT;
    }
    if (!parent_allowed(store, index, header)) return BAREV_POST_DENIED;
    node = &store->destinations[index];
    if (store->used == store->post_limit || barev_post_size(post) > store->byte_limit-store->bytes ||
        node->generation == INT32_MAX || !(post = barev_post_ref(post))) return BAREV_POST_FULL;
    slot = &store->slots[store->used++]; slot->node = index; slot->post = post;
    g_strlcpy(slot->item, header->item, sizeof(slot->item)); g_strlcpy(slot->id, header->id, sizeof(slot->id));
    ++store->live; store->bytes += barev_post_size(post); ++node->generation; return BAREV_POST_OKAY;
}

unsigned barev_post_store_edit(BarevPostStore *store, const char *name, const BarevPost *expected, BarevPost *replacement)
{
    const BarevPostHeader *header = barev_post_header(replacement);
    int index, slot;
    int64_t delta;
    BarevPost *previous;
    Node *node;
    if (!valid(store) || !expected || !header) return BAREV_POST_INVALID;
    if (strcmp(store->owner, header->owner)) return BAREV_POST_DENIED;
    index = node_index(store, name); if (index < 0) return BAREV_POST_MISSING;
    slot = post_index(store, index, header->item); if (slot < 0) return BAREV_POST_MISSING;
    previous = store->slots[slot].post; if (!previous) return BAREV_POST_CONFLICT;
    if (barev_post_same(previous, replacement)) return BAREV_POST_OKAY;
    if (!barev_post_same(previous, expected) || !barev_post_revision(previous, replacement)) return BAREV_POST_CONFLICT;
    node = &store->destinations[index]; delta = (int64_t)barev_post_size(replacement)-barev_post_size(previous);
    if (delta > store->byte_limit-store->bytes || node->generation == INT32_MAX ||
        !(replacement = barev_post_ref(replacement))) return BAREV_POST_FULL;
    store->slots[slot].post = replacement; store->bytes = (uint32_t)(store->bytes+delta);
    barev_post_unref(previous); ++node->generation; return BAREV_POST_OKAY;
}

unsigned barev_post_store_retract(BarevPostStore *store, const char *name, const char *item)
{
    int index, at;
    Slot *slot;
    if (!valid(store)) return BAREV_POST_INVALID;
    index = node_index(store, name); if (index < 0) return BAREV_POST_MISSING;
    at = post_index(store, index, item); if (at < 0) return BAREV_POST_MISSING;
    slot = &store->slots[at]; if (!slot->post) return BAREV_POST_OKAY;
    if (store->destinations[index].generation == INT32_MAX) return BAREV_POST_FULL;
    store->bytes -= barev_post_size(slot->post)-strlen(slot->item)-strlen(slot->id);
    barev_post_unref(slot->post); slot->post = NULL; --store->live;
    ++store->destinations[index].generation; return BAREV_POST_OKAY;
}

BarevPost *barev_post_store_get(const BarevPostStore *store, const char *name, const char *item)
{
    int index = node_index(store, name), slot;
    if (index < 0) return NULL;
    slot = post_index(store, index, item); return slot < 0 ? NULL : store->slots[slot].post;
}

BarevPost *barev_post_store_read_post(const BarevPostStore *store, const char *name, const char *item,
    const BarevFeedReader *reader, const BarevFeedContact *contact)
{
    int index = node_index(store, name);
    if (index < 0 || !barev_feed_can_read(store->destinations[index].policy, reader, contact)) return NULL;
    return barev_post_store_get(store, name, item);
}

gboolean barev_post_store_node(const BarevPostStore *store, int32_t index, BarevPostNodeInfo *info)
{
    const Node *node;
    if (!valid(store) || !info || index < 0 || (unsigned)index >= store->nodes) return FALSE;
    node = &store->destinations[index]; memcpy(info->name, node->name, sizeof(info->name));
    memcpy(info->title, node->title, sizeof(info->title)); info->model = barev_feed_policy_model(node->policy); return TRUE;
}

gboolean barev_post_store_reference(const BarevPostStore *store, const char *id, BarevPostNodeInfo *info)
{
    unsigned i;
    if (!valid(store) || !barev_post_reference(id, 1025, FALSE)) return FALSE;
    for (i = 0; i < store->used; ++i) if (!strcmp(store->slots[i].id, id))
        return barev_post_store_node(store, store->slots[i].node, info);
    return FALSE;
}

gboolean barev_post_store_describe(const BarevPostStore *store, const char *name,
    const BarevFeedReader *reader, const BarevFeedContact *contact, BarevPostNodeInfo *info)
{
    int index = node_index(store, name);
    return index >= 0 && barev_feed_can_read(store->destinations[index].policy, reader, contact) &&
        barev_post_store_node(store, index, info);
}
uint32_t barev_post_store_count(const BarevPostStore *store) { return valid(store) ? store->live : 0; }
uint32_t barev_post_store_nodes(const BarevPostStore *store) { return valid(store) ? store->nodes : 0; }
uint32_t barev_post_store_reserved(const BarevPostStore *store) { return valid(store) ? store->used : 0; }
uint32_t barev_post_store_bytes(const BarevPostStore *store) { return valid(store) ? store->bytes : 0; }

gboolean barev_post_store_extends(const BarevPostStore *previous, const BarevPostStore *next)
{
    unsigned i;
    if (!valid(previous) || !valid(next) || strcmp(previous->owner, next->owner) ||
        previous->nodes > next->nodes || previous->used > next->used) return FALSE;
    for (i = 0; i < previous->nodes; ++i) if (strcmp(previous->destinations[i].name, next->destinations[i].name) ||
        barev_feed_policy_model(previous->destinations[i].policy) != barev_feed_policy_model(next->destinations[i].policy)) return FALSE;
    for (i = 0; i < previous->used; ++i) {
        const Slot *before = &previous->slots[i], *after = &next->slots[i];
        if (before->node != after->node || strcmp(before->item, after->item) || strcmp(before->id, after->id) ||
            (!before->post && after->post) || (before->post && after->post &&
            !barev_post_same(before->post, after->post) && !barev_post_revision(before->post, after->post))) return FALSE;
    }
    return TRUE;
}

void barev_post_cursor_clear(BarevPostCursor *cursor)
{ if (cursor) { unref(cursor->store); memset(cursor, 0, sizeof(*cursor)); } }

static unsigned begin(BarevPostStore *store, const char *name, const BarevFeedReader *reader,
    const BarevFeedContact *contact, BarevPostCursor *cursor, gboolean owner)
{
    int index;
    if (!cursor) return BAREV_POST_INVALID;
    barev_post_cursor_clear(cursor); index = node_index(store, name);
    if (!owner && (index < 0 || !barev_feed_can_read(store->destinations[index].policy, reader, contact))) return BAREV_POST_DENIED;
    if (index < 0) return BAREV_POST_MISSING;
    if (store->refs == UINT_MAX) return BAREV_POST_FULL;
    ++store->refs; cursor->store = store; cursor->node = index; cursor->owner = owner;
    cursor->generation = store->destinations[index].generation; cursor->next = (int32_t)store->used-1; return BAREV_POST_OKAY;
}
unsigned barev_post_store_begin(BarevPostStore *store, const char *node, BarevPostCursor *cursor)
{ return begin(store, node, NULL, NULL, cursor, TRUE); }
unsigned barev_post_store_begin_read(BarevPostStore *store, const char *node,
    const BarevFeedReader *reader, const BarevFeedContact *contact, BarevPostCursor *cursor)
{ return begin(store, node, reader, contact, cursor, FALSE); }

size_t barev_post_page_size(const BarevPostPage *page) { return page ? page->size : 0; }
BarevPost *barev_post_page_post(const BarevPostPage *page, size_t index)
{ return page && index < page->size ? page->posts[index] : NULL; }
void barev_post_page_free(BarevPostPage *page)
{
    size_t i;
    if (!page) return;
    for (i = 0; i < page->size; ++i) barev_post_unref(page->posts[i]);
    g_free(page);
}

static unsigned take(BarevPostCursor *cursor, int32_t maximum, BarevPostPage **output)
{
    BarevPostPage *page;
    int32_t next;
    if (maximum < 1 || maximum > BAREV_POST_STORE_MAX_PAGE) return BAREV_POST_INVALID;
    if (cursor->generation != cursor->store->destinations[cursor->node].generation) return BAREV_POST_STALE;
    page = g_try_new0(BarevPostPage, 1); if (!page) return BAREV_POST_FULL;
    next = cursor->next;
    while (next >= 0 && page->size < (unsigned)maximum) {
        const Slot *slot = &cursor->store->slots[next];
        if (slot->node == (unsigned)cursor->node && slot->post) {
            BarevPost *post = barev_post_ref(slot->post);
            if (!post) { barev_post_page_free(page); return BAREV_POST_FULL; }
            page->posts[page->size++] = post;
        }
        --next;
    }
    cursor->next = next; *output = page; return BAREV_POST_OKAY;
}
unsigned barev_post_store_page(BarevPostCursor *cursor, int32_t maximum, BarevPostPage **page)
{
    if (!page) return BAREV_POST_INVALID;
    *page = NULL;
    if (!cursor || !valid(cursor->store) || !cursor->owner) return BAREV_POST_INVALID;
    return take(cursor, maximum, page);
}
unsigned barev_post_store_read_page(BarevPostCursor *cursor, const BarevFeedReader *reader,
    const BarevFeedContact *contact, int32_t maximum, BarevPostPage **page)
{
    if (!page) return BAREV_POST_INVALID;
    *page = NULL;
    if (!cursor || !valid(cursor->store) || cursor->owner ||
        !barev_feed_can_read(cursor->store->destinations[cursor->node].policy, reader, contact)) return BAREV_POST_DENIED;
    return take(cursor, maximum, page);
}

typedef struct { unsigned char *data; size_t at, maximum; gboolean good; } Writer;
typedef struct { const unsigned char *data; size_t at, maximum; gboolean good; } Reader;

uint32_t barev_post_snapshot_crc(const unsigned char *bytes, size_t length)
{
    uint32_t crc = UINT32_MAX;
    size_t i;
    unsigned bit;
    if ((!bytes && length) || length > BAREV_POST_STORE_MAX_SNAPSHOT) return 0;
    for (i = 0; i < length; ++i) {
        crc ^= bytes[i];
        for (bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return ~crc;
}
static void word(Writer *writer, uint32_t value)
{
    unsigned i;
    if (!writer->good) return;
    if (writer->maximum-writer->at < 4) { writer->good = FALSE; return; }
    if (writer->data) for (i = 0; i < 4; ++i) writer->data[writer->at+i] = value >> (24-8*i);
    writer->at += 4;
}
static void text(Writer *writer, const char *value)
{
    size_t n;
    if (!writer->good) return;
    n = strlen(value); word(writer, n);
    if (!writer->good || n > writer->maximum-writer->at) { writer->good = FALSE; return; }
    if (writer->data) memcpy(writer->data+writer->at, value, n);
    writer->at += n;
}
static void snapshot(const BarevPostStore *store, Writer *writer)
{
    unsigned i;
    size_t j;
    text(writer, "BAREVPS1"); text(writer, store->owner);
    word(writer, store->node_limit); word(writer, store->post_limit); word(writer, store->byte_limit);
    word(writer, store->nodes); word(writer, store->used);
    for (i = 0; i < store->nodes; ++i) {
        const Node *node = &store->destinations[i];
        text(writer, node->name); text(writer, node->title); word(writer, barev_feed_policy_model(node->policy));
        word(writer, barev_feed_policy_count(node->policy));
        for (j = 0; j < barev_feed_policy_count(node->policy); ++j) text(writer, barev_feed_policy_name(node->policy, j));
    }
    for (i = 0; i < store->used; ++i) {
        const Slot *slot = &store->slots[i];
        const BarevPostHeader *header = barev_post_header(slot->post);
        word(writer, slot->node); word(writer, header ? 1 : 0); text(writer, slot->item); text(writer, slot->id);
        if (header) {
            text(writer, header->author); text(writer, header->title); text(writer, header->published);
            text(writer, header->updated); text(writer, header->parent); text(writer, barev_post_content(slot->post));
        }
    }
    word(writer, writer->data ? barev_post_snapshot_crc(writer->data, writer->at) : 0);
}

gboolean barev_post_store_encode(const BarevPostStore *store, unsigned char **bytes, size_t *length)
{
    Writer writer = {NULL, 0, BAREV_POST_STORE_MAX_SNAPSHOT, TRUE};
    size_t size;
    if (!bytes || !length) return FALSE;
    *bytes = NULL; *length = 0; if (!valid(store)) return FALSE;
    snapshot(store, &writer); if (!writer.good) return FALSE;
    size = writer.at; writer.data = g_try_malloc(size); if (!writer.data) return FALSE;
    writer.at = 0; writer.maximum = size; snapshot(store, &writer);
    if (!writer.good || writer.at != size) { g_free(writer.data); return FALSE; }
    *bytes = writer.data; *length = size; return TRUE;
}
static uint32_t read_word(Reader *reader)
{
    uint32_t value = 0;
    unsigned i;
    if (!reader->good) return 0;
    if (reader->maximum-reader->at < 4) { reader->good = FALSE; return 0; }
    for (i = 0; i < 4; ++i) value = (value << 8) | reader->data[reader->at++];
    return value;
}
static gboolean read_text(Reader *reader, char *output, size_t maximum)
{
    uint32_t n = read_word(reader), i;
    if (!reader->good || n >= maximum || n > reader->maximum-reader->at) { reader->good = FALSE; return FALSE; }
    for (i = 0; i < n; ++i) if (!reader->data[reader->at+i]) { reader->good = FALSE; return FALSE; }
    memcpy(output, reader->data+reader->at, n); output[n] = 0; reader->at += n; return TRUE;
}

BarevPostStore *barev_post_store_decode(const unsigned char *bytes, size_t length, const char *owner)
{
    Reader reader;
    BarevPostStore *store = NULL;
    BarevFeedName *names = NULL;
    BarevPostHeader header = {0};
    char magic[9], found[65], name[129], title[257], body[BAREV_POST_MAX_TEXT_BYTES+1];
    uint32_t node_limit, post_limit, byte_limit, nodes, posts, i, j, model, members, node, state, expected;
    if (!bytes || length < 4 || length > BAREV_POST_STORE_MAX_SNAPSHOT || !barev_post_owner(owner, 65)) return NULL;
    reader = (Reader){bytes, length-4, length, TRUE}; expected = read_word(&reader);
    if (barev_post_snapshot_crc(bytes, length-4) != expected) return NULL;
    reader.at = 0; reader.maximum = length-4;
    if (!read_text(&reader, magic, sizeof(magic)) || strcmp(magic, "BAREVPS1") ||
        !read_text(&reader, found, sizeof(found)) || strcmp(found, owner)) return NULL;
    node_limit = read_word(&reader); post_limit = read_word(&reader); byte_limit = read_word(&reader);
    nodes = read_word(&reader); posts = read_word(&reader);
    if (!reader.good || node_limit < 1 || node_limit > BAREV_POST_STORE_MAX_NODES ||
        post_limit < 1 || post_limit > BAREV_POST_STORE_MAX_POSTS || byte_limit < 1 || byte_limit > BAREV_POST_STORE_MAX_BYTES ||
        nodes > node_limit || posts > post_limit) return NULL;
    store = barev_post_store_new(owner, node_limit, post_limit, byte_limit); if (!store) return NULL;
    names = g_try_new0(BarevFeedName, BAREV_FEED_MAX_MEMBERS); if (!names) goto failed;
    for (i = 0; i < nodes; ++i) {
        BarevFeedPolicy *policy;
        unsigned status;
        if (!read_text(&reader, name, sizeof(name)) || !read_text(&reader, title, sizeof(title))) goto failed;
        model = read_word(&reader); members = read_word(&reader);
        if (!reader.good || model < BAREV_FEED_OPEN || model > BAREV_FEED_WHITELIST || members > BAREV_FEED_MAX_MEMBERS) goto failed;
        for (j = 0; j < members; ++j) if (!read_text(&reader, names[j], sizeof(names[j]))) goto failed;
        policy = barev_feed_policy_new(model, names, BAREV_FEED_MAX_MEMBERS, members);
        status = barev_post_store_add_node(store, name, title, policy); barev_feed_policy_unref(policy);
        if (status != BAREV_POST_OKAY) goto failed;
    }
    memcpy(header.owner, owner, sizeof(header.owner));
    for (i = 0; i < posts; ++i) {
        node = read_word(&reader); state = read_word(&reader);
        if (!reader.good || node >= nodes || state > 1 || !read_text(&reader, header.item, sizeof(header.item)) ||
            !read_text(&reader, header.id, sizeof(header.id))) goto failed;
        if (state) {
            BarevPost *post;
            unsigned status;
            if (!read_text(&reader, header.author, sizeof(header.author)) || !read_text(&reader, header.title, sizeof(header.title)) ||
                !read_text(&reader, header.published, sizeof(header.published)) || !read_text(&reader, header.updated, sizeof(header.updated)) ||
                !read_text(&reader, header.parent, sizeof(header.parent)) || !read_text(&reader, body, sizeof(body))) goto failed;
            post = barev_post_new(&header, body, sizeof(body));
            status = barev_post_store_put(store, store->destinations[node].name, post); barev_post_unref(post);
            if (status != BAREV_POST_OKAY || store->used != i+1) goto failed;
        } else {
            Slot *slot;
            size_t size;
            if (!barev_post_token(header.item, sizeof(header.item), 128) || !barev_post_reference(header.id, sizeof(header.id), FALSE)) goto failed;
            for (j = 0; j < store->used; ++j) if (!strcmp(store->slots[j].item, header.item) || !strcmp(store->slots[j].id, header.id)) goto failed;
            size = strlen(header.item)+strlen(header.id); if (size > store->byte_limit-store->bytes) goto failed;
            slot = &store->slots[store->used++]; slot->node = node;
            g_strlcpy(slot->item, header.item, sizeof(slot->item)); g_strlcpy(slot->id, header.id, sizeof(slot->id)); store->bytes += size;
        }
    }
    if (!reader.good || reader.at != reader.maximum) goto failed;
    g_free(names); return store;
failed:
    g_free(names); barev_post_store_close(&store); return NULL;
}
