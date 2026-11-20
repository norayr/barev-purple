/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feed-access.h"
#include "address.h"
#include <limits.h>
#include <string.h>

struct BarevFeedPolicy {
    unsigned refs, model;
    size_t count;
    BarevFeedName names[BAREV_FEED_MAX_MEMBERS];
};
struct BarevFeedContact {
    BarevFeedName peer;
    unsigned char pin[32];
    size_t count;
    BarevFeedName groups[BAREV_FEED_MAX_GROUPS];
};
enum { PUBLIC_READER = 1, PRIVATE_READER };

static gboolean group_name(const char *name)
{
    size_t length;
    const char *at;
    if (!name) return FALSE;
    for (length = 0; length <= BAREV_FEED_MAX_GROUP_BYTES && name[length]; ++length) {}
    if (!length || length > BAREV_FEED_MAX_GROUP_BYTES || !g_utf8_validate(name, length, NULL)) return FALSE;
    for (at = name; *at; at = g_utf8_next_char(at)) {
        gunichar ch = g_utf8_get_char(at);
        if (ch < 32 || (ch >= 127 && ch <= 159)) return FALSE;
    }
    return TRUE;
}

static gboolean canonical(const char *name, BarevFeedName output)
{
    size_t length;
    const char *at;
    char *value;
    if (!name) return FALSE;
    for (length = 0; length < BAREV_FEED_NAME_BYTES && name[length]; ++length) {}
    if (length == BAREV_FEED_NAME_BYTES) return FALSE;
    at = strchr(name, '@');
    if (!at || strlen(at+1) > 40) return FALSE;
    value = barev_address_identity(name, FALSE);
    if (!value) return FALSE;
    g_strlcpy(output, value, BAREV_FEED_NAME_BYTES); g_free(value); return TRUE;
}

BarevFeedPolicy *barev_feed_policy_new(int32_t model, const BarevFeedName *names,
    size_t available, int32_t count)
{
    BarevFeedPolicy *policy;
    int32_t i, j;
    if (model < BAREV_FEED_OPEN || model > BAREV_FEED_WHITELIST || count < 0 ||
        count > BAREV_FEED_MAX_MEMBERS || (size_t)count > available || (count && !names) ||
        (model == BAREV_FEED_OPEN && count) || (model == BAREV_FEED_ROSTER && count > BAREV_FEED_MAX_GROUPS)) return NULL;
    policy = g_try_new0(BarevFeedPolicy, 1);
    if (!policy) return NULL;
    policy->refs = 1; policy->model = model; policy->count = count;
    for (i = 0; i < count; ++i) {
        if (model == BAREV_FEED_ROSTER) {
            if (!group_name(names[i])) goto invalid;
            g_strlcpy(policy->names[i], names[i], sizeof(policy->names[i]));
        } else if (!canonical(names[i], policy->names[i])) goto invalid;
        for (j = 0; j < i; ++j) if (!strcmp(policy->names[i], policy->names[j])) goto invalid;
    }
    return policy;
invalid:
    g_free(policy); return NULL;
}

BarevFeedPolicy *barev_feed_policy_ref(BarevFeedPolicy *policy)
{
    if (!policy || policy->refs == UINT_MAX) return NULL;
    ++policy->refs; return policy;
}

void barev_feed_policy_unref(BarevFeedPolicy *policy)
{ if (policy && !--policy->refs) g_free(policy); }

unsigned barev_feed_policy_model(const BarevFeedPolicy *policy)
{ return policy ? policy->model : BAREV_FEED_DENIED; }

size_t barev_feed_policy_count(const BarevFeedPolicy *policy)
{ return policy ? policy->count : 0; }

const char *barev_feed_policy_name(const BarevFeedPolicy *policy, size_t index)
{ return policy && index < policy->count ? policy->names[index] : NULL; }

BarevFeedContact *barev_feed_contact_new(const char *peer, const unsigned char *pin,
    size_t pin_length, gboolean authorized, const BarevFeedName *groups,
    size_t available, int32_t count)
{
    BarevFeedContact *contact;
    int32_t i, j;
    if (!authorized || !pin || pin_length != 32 || count < 0 || count > BAREV_FEED_MAX_GROUPS ||
        (size_t)count > available || (count && !groups)) return NULL;
    contact = g_try_new0(BarevFeedContact, 1);
    if (!contact) return NULL;
    if (!canonical(peer, contact->peer)) goto invalid;
    memcpy(contact->pin, pin, 32); contact->count = count;
    for (i = 0; i < count; ++i) {
        if (!group_name(groups[i])) goto invalid;
        g_strlcpy(contact->groups[i], groups[i], sizeof(contact->groups[i]));
        for (j = 0; j < i; ++j) if (!strcmp(contact->groups[i], contact->groups[j])) goto invalid;
    }
    return contact;
invalid:
    g_free(contact); return NULL;
}

void barev_feed_contact_free(BarevFeedContact *contact)
{ g_free(contact); }

void barev_feed_reader_close(BarevFeedReader *reader)
{ if (reader) memset(reader, 0, sizeof(*reader)); }

void barev_feed_reader_anonymous(BarevFeedReader *reader)
{ if (reader) { barev_feed_reader_close(reader); reader->kind = PUBLIC_READER; } }

gboolean barev_feed_reader_authenticate(BarevFeedReader *reader, const char *peer,
    const unsigned char *captured_key, size_t key_length, gboolean mutual_tls, gboolean external)
{
    barev_feed_reader_close(reader);
    if (!reader || !mutual_tls || !external || !captured_key || key_length != 32 ||
        !canonical(peer, reader->peer)) return FALSE;
    memcpy(reader->key, captured_key, 32); reader->kind = PRIVATE_READER; return TRUE;
}

gboolean barev_feed_can_read(const BarevFeedPolicy *policy,
    const BarevFeedReader *reader, const BarevFeedContact *contact)
{
    size_t i, j;
    unsigned different = 0;
    if (!policy || !reader || (reader->kind != PUBLIC_READER && reader->kind != PRIVATE_READER)) return FALSE;
    if (policy->model == BAREV_FEED_OPEN) return TRUE;
    if (reader->kind != PRIVATE_READER || !contact || strcmp(reader->peer, contact->peer)) return FALSE;
    for (i = 0; i < 32; ++i) different |= reader->key[i] ^ contact->pin[i];
    if (different) return FALSE;
    for (i = 0; i < policy->count; ++i) {
        if (policy->model == BAREV_FEED_WHITELIST && !strcmp(reader->peer, policy->names[i])) return TRUE;
        if (policy->model == BAREV_FEED_ROSTER)
            for (j = 0; j < contact->count; ++j)
                if (!strcmp(policy->names[i], contact->groups[j])) return TRUE;
    }
    return FALSE;
}
