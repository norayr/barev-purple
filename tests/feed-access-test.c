/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feed-access.h"
#include "address.h"
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(value) do { ++checks; if (!(value)) g_error("Feed access check %u failed: %s", checks, #value); } while (0)
static BarevFeedName names[BAREV_FEED_MAX_MEMBERS+1], groups[BAREV_FEED_MAX_GROUPS+1];
static unsigned char key[32];

static BarevFeedPolicy *policy(int32_t model, const BarevFeedName *input, size_t available, int32_t count)
{ return barev_feed_policy_new(model, input, available, count); }

static BarevFeedContact *contact(const char *peer, const unsigned char *pin, int32_t count)
{ return barev_feed_contact_new(peer, pin, 32, TRUE, groups, G_N_ELEMENTS(groups), count); }

static void policies(void)
{
    BarevFeedPolicy *public, *selected, *group, *empty, *empty_group, *other, *retained;
    BarevFeedContact *current, *stranger, *moved, *replacement;
    BarevFeedReader reader = {0};
    unsigned char changed[32], captured[32];
    unsigned i;
    g_strlcpy(names[0], "reader@200::1", sizeof(names[0]));
    g_strlcpy(groups[0], "friends", sizeof(groups[0]));
    g_strlcpy(groups[1], "family", sizeof(groups[1]));
    public = policy(BAREV_FEED_OPEN, NULL, 0, 0);
    selected = policy(BAREV_FEED_WHITELIST, names, G_N_ELEMENTS(names), 1);
    group = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1);
    empty = policy(BAREV_FEED_WHITELIST, NULL, 0, 0);
    empty_group = policy(BAREV_FEED_ROSTER, NULL, 0, 0);
    CHECK(public && selected && group && empty && empty_group);
    CHECK(barev_feed_policy_model(public) == BAREV_FEED_OPEN);
    CHECK(barev_feed_policy_model(selected) == BAREV_FEED_WHITELIST);
    CHECK(barev_feed_policy_model(group) == BAREV_FEED_ROSTER);
    CHECK(barev_feed_policy_model(NULL) == BAREV_FEED_DENIED);
    CHECK(barev_feed_policy_count(selected) == 1 && barev_feed_policy_count(NULL) == 0);
    CHECK(!barev_feed_policy_name(NULL, 0) && !barev_feed_policy_name(selected, 1));
    retained = barev_feed_policy_ref(selected); CHECK(retained == selected);
    barev_feed_policy_unref(selected); selected = retained;
    CHECK(!strcmp(barev_feed_policy_name(selected, 0), "reader@200::1"));
    current = contact(names[0], key, 1); stranger = contact("other@200::2", key, 1);
    CHECK(current && stranger);
    CHECK(!barev_feed_can_read(public, &reader, current));
    CHECK(!barev_feed_can_read(public, NULL, current));
    barev_feed_reader_anonymous(&reader);
    CHECK(barev_feed_can_read(public, &reader, NULL));
    CHECK(barev_feed_can_read(public, &reader, current));
    CHECK(!barev_feed_can_read(selected, &reader, current) && !barev_feed_can_read(group, &reader, current));
    CHECK(!barev_feed_can_read(NULL, &reader, current));
    memcpy(captured, key, sizeof(captured));
    CHECK(barev_feed_reader_authenticate(&reader, names[0], captured, sizeof(captured), TRUE, TRUE));
    captured[0] ^= 255;
    CHECK(barev_feed_can_read(selected, &reader, current) && barev_feed_can_read(group, &reader, current));
    CHECK(barev_feed_can_read(public, &reader, NULL));
    CHECK(!barev_feed_can_read(selected, &reader, NULL) && !barev_feed_can_read(group, &reader, NULL));
    CHECK(!barev_feed_can_read(selected, &reader, stranger) && !barev_feed_can_read(group, &reader, stranger));
    CHECK(!barev_feed_can_read(empty, &reader, current) && !barev_feed_can_read(empty_group, &reader, current));
    moved = contact(names[0], key, 0); CHECK(moved);
    CHECK(!barev_feed_can_read(group, &reader, moved));
    CHECK(barev_feed_can_read(selected, &reader, moved));
    CHECK(barev_feed_can_read(group, &reader, current));
    g_strlcpy(names[0], "other@200::2", sizeof(names[0]));
    other = policy(BAREV_FEED_WHITELIST, names, G_N_ELEMENTS(names), 1); CHECK(other);
    CHECK(!barev_feed_can_read(other, &reader, current)); barev_feed_policy_unref(other);
    g_strlcpy(groups[0], "family", sizeof(groups[0]));
    other = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1); CHECK(other);
    CHECK(!barev_feed_can_read(other, &reader, current)); barev_feed_policy_unref(other);
    g_strlcpy(groups[1], "friends", sizeof(groups[1]));
    other = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 2); CHECK(other);
    CHECK(barev_feed_can_read(other, &reader, current)); barev_feed_policy_unref(other);
    for (i = 0; i < sizeof(changed); ++i) {
        memcpy(changed, key, sizeof(changed)); changed[i] ^= 255;
        replacement = contact("reader@200::1", changed, 2); CHECK(replacement);
        CHECK(!barev_feed_can_read(selected, &reader, replacement));
        CHECK(!barev_feed_can_read(group, &reader, replacement));
        CHECK(barev_feed_can_read(public, &reader, replacement));
        barev_feed_contact_free(replacement);
    }
    replacement = contact("reader@200::1", changed, 2); CHECK(replacement);
    CHECK(barev_feed_reader_authenticate(&reader, "reader@200::1", changed, 32, TRUE, TRUE));
    CHECK(barev_feed_can_read(selected, &reader, replacement) && barev_feed_can_read(group, &reader, replacement));
    CHECK(!barev_feed_can_read(selected, &reader, current)); barev_feed_contact_free(replacement);
    CHECK(barev_feed_reader_authenticate(&reader, "reader@200::1", key, 32, TRUE, TRUE));
    replacement = contact("Reader@200::1", key, 1); CHECK(replacement);
    CHECK(!barev_feed_can_read(selected, &reader, replacement)); barev_feed_contact_free(replacement);
    replacement = contact("reader@200::2", key, 1); CHECK(replacement);
    CHECK(!barev_feed_can_read(group, &reader, replacement)); barev_feed_contact_free(replacement);
    g_strlcpy(groups[0], "changed", sizeof(groups[0]));
    CHECK(barev_feed_can_read(selected, &reader, current) && barev_feed_can_read(group, &reader, current));
    barev_feed_reader_close(&reader);
    CHECK(!barev_feed_can_read(public, &reader, current) && !barev_feed_can_read(group, &reader, current));
    CHECK(reader.kind == 0 && !reader.peer[0]);
    for (i = 0; i < sizeof(reader.key); ++i) CHECK(!reader.key[i]);
    barev_feed_reader_anonymous(&reader); CHECK(!barev_feed_can_read(group, &reader, current));
    barev_feed_contact_free(current); barev_feed_contact_free(stranger); barev_feed_contact_free(moved);
    barev_feed_policy_unref(public); barev_feed_policy_unref(selected); barev_feed_policy_unref(group);
    barev_feed_policy_unref(empty); barev_feed_policy_unref(empty_group);
    barev_feed_reader_close(NULL); barev_feed_reader_anonymous(NULL);
    barev_feed_policy_unref(NULL); barev_feed_contact_free(NULL); CHECK(!barev_feed_policy_ref(NULL));
}

static void authentication(void)
{
    BarevFeedReader reader = {0};
    BarevFeedPolicy *node;
    BarevFeedContact *current, *copied;
    char *encoded;
    unsigned char pin[33];
    unsigned i;
    const char *invalid[] = {"", "reader@example.org", "reader@200::1/resource", "reader@@200::1", "reader@::1"};
    g_strlcpy(names[0], "reader@200::1", sizeof(names[0]));
    g_strlcpy(groups[0], "friends", sizeof(groups[0]));
    node = policy(BAREV_FEED_WHITELIST, names, G_N_ELEMENTS(names), 1); CHECK(node);
    current = contact(names[0], key, 1); CHECK(current);
    for (i = 0; i < 4; ++i) {
        CHECK(barev_feed_reader_authenticate(&reader, names[0], key, 32, TRUE, TRUE));
        CHECK(barev_feed_reader_authenticate(&reader, names[0], key, 32, i & 1, i & 2) == (i == 3));
        CHECK(barev_feed_can_read(node, &reader, current) == (i == 3));
    }
    memcpy(pin, key, 32); pin[32] = 0;
    CHECK(!barev_feed_reader_authenticate(&reader, names[0], pin, 31, TRUE, TRUE));
    CHECK(!barev_feed_reader_authenticate(&reader, names[0], pin, 33, TRUE, TRUE));
    CHECK(!barev_feed_reader_authenticate(&reader, names[0], NULL, 32, TRUE, TRUE));
    CHECK(!barev_feed_reader_authenticate(NULL, names[0], key, 32, TRUE, TRUE));
    CHECK(!barev_feed_contact_new(names[0], key, 32, FALSE, groups, G_N_ELEMENTS(groups), 1));
    CHECK(!barev_feed_contact_new(names[0], pin, 31, TRUE, groups, G_N_ELEMENTS(groups), 1));
    CHECK(!barev_feed_contact_new(names[0], pin, 33, TRUE, groups, G_N_ELEMENTS(groups), 1));
    CHECK(!barev_feed_contact_new(names[0], NULL, 32, TRUE, groups, G_N_ELEMENTS(groups), 1));
    for (i = 0; i < G_N_ELEMENTS(invalid); ++i) {
        CHECK(!barev_feed_reader_authenticate(&reader, invalid[i], key, 32, TRUE, TRUE));
        CHECK(!contact(invalid[i], key, 1));
    }
    CHECK(!barev_feed_reader_authenticate(&reader, NULL, key, 32, TRUE, TRUE));
    CHECK(barev_feed_reader_authenticate(&reader, "reader@0200:0:0:0:0:0:0:1", key, 32, TRUE, TRUE));
    CHECK(barev_feed_can_read(node, &reader, current));
    encoded = barev_address_identity(names[0], TRUE); CHECK(encoded);
    copied = contact(encoded, key, 1); CHECK(copied);
    CHECK(barev_feed_can_read(node, &reader, copied));
    CHECK(barev_feed_reader_authenticate(&reader, encoded, key, 32, TRUE, TRUE));
    CHECK(barev_feed_can_read(node, &reader, current));
    g_free(encoded); barev_feed_contact_free(copied);
    copied = contact(names[0], pin, 1); CHECK(copied); pin[31] ^= 255;
    CHECK(barev_feed_can_read(node, &reader, copied)); barev_feed_contact_free(copied);
    CHECK(!barev_feed_reader_authenticate(&reader, names[0], pin, 32, TRUE, FALSE));
    CHECK(!barev_feed_can_read(node, &reader, current));
    memset(names[0], 'x', sizeof(names[0]));
    CHECK(!barev_feed_reader_authenticate(&reader, names[0], key, 32, TRUE, TRUE));
    barev_feed_contact_free(current); barev_feed_policy_unref(node);
}

static void configuration(void)
{
    BarevFeedPolicy *node;
    BarevFeedContact *current;
    BarevFeedReader reader = {0};
    const char *invalid[] = {"", "\001", "\302\205", "\300\257", "\355\240\200", "\377"};
    size_t i;
    g_strlcpy(names[0], "reader@200::1", sizeof(names[0]));
    g_strlcpy(names[1], "reader@0200:0:0:0:0:0:0:1", sizeof(names[1]));
    g_strlcpy(groups[0], "friends", sizeof(groups[0])); g_strlcpy(groups[1], "friends", sizeof(groups[1]));
    CHECK(!policy(-1, NULL, 0, 0)); CHECK(!policy(0, NULL, 0, 0)); CHECK(!policy(4, NULL, 0, 0));
    CHECK(!policy(BAREV_FEED_OPEN, names, G_N_ELEMENTS(names), 1));
    CHECK(!policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), -1));
    CHECK(!policy(BAREV_FEED_WHITELIST, names, 1, 2));
    CHECK(!policy(BAREV_FEED_WHITELIST, names, G_N_ELEMENTS(names), BAREV_FEED_MAX_MEMBERS+1));
    CHECK(!policy(BAREV_FEED_WHITELIST, names, G_N_ELEMENTS(names), INT32_MAX));
    CHECK(!policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), BAREV_FEED_MAX_GROUPS+1));
    CHECK(!policy(BAREV_FEED_WHITELIST, NULL, 1, 1));
    CHECK(!policy(BAREV_FEED_WHITELIST, names, G_N_ELEMENTS(names), 2));
    CHECK(!policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 2));
    CHECK(!contact(names[0], key, 2)); CHECK(!contact(names[0], key, -1));
    CHECK(!contact(names[0], key, BAREV_FEED_MAX_GROUPS+1)); CHECK(!contact(names[0], key, INT32_MAX));
    CHECK(!barev_feed_contact_new(names[0], key, 32, TRUE, groups, 0, 1));
    CHECK(!barev_feed_contact_new(names[0], key, 32, TRUE, NULL, 1, 1));
    for (i = 0; i < G_N_ELEMENTS(invalid); ++i) {
        g_strlcpy(groups[0], invalid[i], sizeof(groups[0]));
        CHECK(!policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1));
        CHECK(!contact(names[0], key, 1));
    }
    memset(groups[0], 'x', sizeof(groups[0]));
    CHECK(!policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1));
    groups[0][BAREV_FEED_MAX_GROUP_BYTES+1] = 0;
    CHECK(!policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1));
    groups[0][BAREV_FEED_MAX_GROUP_BYTES] = 0;
    node = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1); current = contact(names[0], key, 1);
    CHECK(node && current && barev_feed_reader_authenticate(&reader, names[0], key, 32, TRUE, TRUE));
    CHECK(barev_feed_can_read(node, &reader, current)); barev_feed_policy_unref(node); barev_feed_contact_free(current);
    g_strlcpy(groups[0], "ընկերներ 😀", sizeof(groups[0])); g_strlcpy(groups[1], "Friends", sizeof(groups[1]));
    node = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1); current = contact(names[0], key, 2);
    CHECK(node && current && barev_feed_can_read(node, &reader, current)); barev_feed_policy_unref(node);
    g_strlcpy(groups[0], "friends", sizeof(groups[0])); node = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1);
    CHECK(node && !barev_feed_can_read(node, &reader, current)); barev_feed_policy_unref(node); barev_feed_contact_free(current);
    for (i = 0; i < BAREV_FEED_MAX_GROUPS; ++i) snprintf(groups[i], sizeof(groups[i]), "group-%zu", i);
    node = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), BAREV_FEED_MAX_GROUPS);
    current = contact(names[0], key, BAREV_FEED_MAX_GROUPS);
    CHECK(node && current && barev_feed_can_read(node, &reader, current)); barev_feed_policy_unref(node);
    memcpy(groups[0], groups[BAREV_FEED_MAX_GROUPS-1], sizeof(groups[0]));
    node = policy(BAREV_FEED_ROSTER, groups, G_N_ELEMENTS(groups), 1);
    CHECK(node && barev_feed_can_read(node, &reader, current)); barev_feed_policy_unref(node); barev_feed_contact_free(current);
    for (i = 0; i < BAREV_FEED_MAX_MEMBERS; ++i) snprintf(names[i], sizeof(names[i]), "reader-%zu@200::1", i);
    node = policy(BAREV_FEED_WHITELIST, names, G_N_ELEMENTS(names), BAREV_FEED_MAX_MEMBERS); CHECK(node);
    CHECK(barev_feed_policy_count(node) == BAREV_FEED_MAX_MEMBERS);
    for (i = 0; i < BAREV_FEED_MAX_MEMBERS; ++i) {
        current = contact(names[i], key, 0); CHECK(current);
        CHECK(barev_feed_reader_authenticate(&reader, names[i], key, 32, TRUE, TRUE));
        CHECK(barev_feed_can_read(node, &reader, current)); barev_feed_contact_free(current);
    }
    barev_feed_policy_unref(node);
}

static void matrix(void)
{
    BarevFeedReader reader = {0};
    BarevFeedPolicy *node;
    BarevFeedContact *current;
    unsigned model, audience, session, person;
    unsigned char changed[32];
    char *encoded;
    BarevFeedName members[1] = {"reader@200::1"};
    BarevFeedName selected_groups[2] = {"ընկերներ 😀", "family"};
    BarevFeedName supplied[2];
    memcpy(changed, key, sizeof(changed)); changed[31] ^= 255;
    encoded = barev_address_identity(members[0], TRUE); CHECK(encoded);
    puts("feed-matrix-v1");
    for (model = BAREV_FEED_OPEN; model <= BAREV_FEED_WHITELIST; ++model)
        for (audience = 0; audience <= 1; ++audience) {
            node = policy(model, model == BAREV_FEED_ROSTER ? selected_groups : members,
                model == BAREV_FEED_ROSTER ? 2 : 1, model == BAREV_FEED_OPEN ? 0 : audience * (model == BAREV_FEED_ROSTER ? 2 : 1));
            CHECK(node);
            for (session = 0; session < 10; ++session) {
                barev_feed_reader_close(&reader);
                if (session == 1) barev_feed_reader_anonymous(&reader);
                else if (session >= 2) {
                    const char *peer = session == 4 ? "other@200::2" : session == 5 ? "reader@example.org" :
                        session == 8 ? encoded : session == 9 ? "reader@0200:0:0:0:0:0:0:1" : members[0];
                    barev_feed_reader_authenticate(&reader, peer, session == 3 ? changed : key, 32, session != 7, session != 6);
                }
                for (person = 0; person < 8; ++person) {
                    memcpy(supplied, selected_groups, sizeof(supplied));
                    if (person == 6) g_strlcpy(supplied[0], "friends", sizeof(supplied[0]));
                    if (person == 7) g_strlcpy(supplied[0], "family", sizeof(supplied[0]));
                    current = person == 0 ? NULL : barev_feed_contact_new(person == 4 ? "other@200::2" : members[0],
                        person == 3 ? changed : key, 32, person != 5, supplied, 2,
                        person == 2 ? 0 : person >= 6 ? 1 : 2);
                    printf("%u %u %u %u %u\n", model, audience, session, person, barev_feed_can_read(node, &reader, current) ? 1u : 0u);
                    barev_feed_contact_free(current);
                }
            }
            barev_feed_policy_unref(node);
        }
    g_free(encoded);
}

int main(int argc, char **argv)
{
    unsigned i;
    for (i = 0; i < sizeof(key); ++i) key[i] = (unsigned char)i;
    if (argc == 2 && !strcmp(argv[1], "--matrix")) { matrix(); return 0; }
    if (argc != 1) return 2;
    policies(); authentication(); configuration();
    printf("C feed access: %u checks passed\n", checks); return 0;
}
