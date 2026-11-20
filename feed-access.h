/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BAREV_FEED_ACCESS_H
#define BAREV_FEED_ACCESS_H
#include <glib.h>
#include <stddef.h>
#include <stdint.h>

#define BAREV_FEED_MAX_GROUPS 16
#define BAREV_FEED_MAX_MEMBERS 256
#define BAREV_FEED_MAX_GROUP_BYTES 256
#define BAREV_FEED_NAME_BYTES 384
enum { BAREV_FEED_DENIED, BAREV_FEED_OPEN, BAREV_FEED_ROSTER, BAREV_FEED_WHITELIST };
typedef char BarevFeedName[BAREV_FEED_NAME_BYTES];
typedef struct BarevFeedPolicy BarevFeedPolicy;
typedef struct BarevFeedContact BarevFeedContact;
typedef struct {
    unsigned kind;
    BarevFeedName peer;
    unsigned char key[32];
} BarevFeedReader;

/* Policies and contact snapshots copy their inputs. All calls belong to the
 * owning application thread. Readers capture a live authenticated session;
 * private reads require the current authorized contact and verified pin. */
BarevFeedPolicy *barev_feed_policy_new(int32_t model, const BarevFeedName *names,
    size_t available, int32_t count);
BarevFeedPolicy *barev_feed_policy_ref(BarevFeedPolicy *policy);
void barev_feed_policy_unref(BarevFeedPolicy *policy);
unsigned barev_feed_policy_model(const BarevFeedPolicy *policy);
size_t barev_feed_policy_count(const BarevFeedPolicy *policy);
const char *barev_feed_policy_name(const BarevFeedPolicy *policy, size_t index);
BarevFeedContact *barev_feed_contact_new(const char *peer, const unsigned char *pin,
    size_t pin_length, gboolean authorized, const BarevFeedName *groups,
    size_t available, int32_t count);
void barev_feed_contact_free(BarevFeedContact *contact);
void barev_feed_reader_close(BarevFeedReader *reader);
void barev_feed_reader_anonymous(BarevFeedReader *reader);
gboolean barev_feed_reader_authenticate(BarevFeedReader *reader, const char *peer,
    const unsigned char *captured_key, size_t key_length, gboolean mutual_tls,
    gboolean external);
gboolean barev_feed_can_read(const BarevFeedPolicy *policy,
    const BarevFeedReader *reader, const BarevFeedContact *contact);
#endif
