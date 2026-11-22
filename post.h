/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BAREV_POST_H
#define BAREV_POST_H
#include <glib.h>
#include <stddef.h>
#include <stdint.h>

#define BAREV_POST_MAX_ITEM_BYTES 128
#define BAREV_POST_MAX_ID_BYTES 1024
#define BAREV_POST_MAX_TITLE_BYTES 256
#define BAREV_POST_MAX_TEXT_BYTES 16384
typedef struct {
    char item[129], id[1025], parent[1025], owner[65], author[384];
    char title[257], published[21], updated[21];
} BarevPostHeader;
typedef struct BarevPost BarevPost;

/* Validators require a terminator within the supplied buffer. Posts copy their
 * inputs and expose immutable borrowed views for their reference lifetime. */
gboolean barev_post_owner(const char *text, size_t available);
gboolean barev_post_token(const char *text, size_t available, int32_t maximum);
gboolean barev_post_text(const char *text, size_t available, int32_t maximum, gboolean empty);
gboolean barev_post_reference(const char *text, size_t available, gboolean empty);
gboolean barev_post_timestamp(const char *stamp, size_t available);
gboolean barev_post_utc(int64_t seconds, char *stamp, size_t available);
gboolean barev_post_identifiers(const unsigned char *entropy, size_t length,
    char *item, size_t item_size, char *id, size_t id_size);
BarevPost *barev_post_new(const BarevPostHeader *header, const char *text, size_t available);
BarevPost *barev_post_ref(BarevPost *post);
void barev_post_unref(BarevPost *post);
const BarevPostHeader *barev_post_header(const BarevPost *post);
const char *barev_post_content(const BarevPost *post);
uint32_t barev_post_size(const BarevPost *post);
gboolean barev_post_same(const BarevPost *left, const BarevPost *right);
gboolean barev_post_revision(const BarevPost *previous, const BarevPost *next);
#endif
