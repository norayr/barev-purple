/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "post.h"
#include "address.h"
#include <limits.h>
#include <string.h>

struct BarevPost {
    unsigned refs;
    uint32_t size;
    BarevPostHeader header;
    char text[];
};

static gboolean length(const char *text, size_t available, size_t maximum, size_t *result)
{
    size_t n = 0;
    if (!text) return FALSE;
    while (n < available && n <= maximum && text[n]) ++n;
    if (n == available || n > maximum) return FALSE;
    *result = n; return TRUE;
}

static gboolean alpha(unsigned char ch)
{ return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'); }
static gboolean digit(unsigned char ch) { return ch >= '0' && ch <= '9'; }
static gboolean hex(unsigned char ch)
{ return digit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'); }
static gboolean member(unsigned char ch, const char *set)
{
    size_t i;
    for (i = 0; set[i]; ++i) if (ch == (unsigned char)set[i]) return TRUE;
    return FALSE;
}

gboolean barev_post_owner(const char *text, size_t available)
{
    size_t i, n;
    if (!length(text, available, 64, &n) || n != 64) return FALSE;
    for (i = 0; i < n; ++i) if (!digit(text[i]) && !(text[i] >= 'a' && text[i] <= 'f')) return FALSE;
    return TRUE;
}

gboolean barev_post_token(const char *text, size_t available, int32_t maximum)
{
    size_t i, n;
    if (maximum < 1 || maximum > BAREV_POST_MAX_ITEM_BYTES ||
        !length(text, available, maximum, &n) || !n) return FALSE;
    for (i = 0; i < n; ++i) if (!alpha(text[i]) && !digit(text[i]) && !member(text[i], "-_.")) return FALSE;
    return TRUE;
}

gboolean barev_post_text(const char *text, size_t available, int32_t maximum, gboolean empty)
{
    size_t n;
    const char *at;
    if (maximum < 0 || maximum > BAREV_POST_MAX_TEXT_BYTES ||
        !length(text, available, maximum, &n) || (!n && !empty) || !g_utf8_validate(text, n, NULL)) return FALSE;
    for (at = text; *at; at = g_utf8_next_char(at)) {
        gunichar ch = g_utf8_get_char(at);
        if ((ch < 32 && ch != 9 && ch != 10 && ch != 13) || ch == 0xfffe || ch == 0xffff) return FALSE;
    }
    return TRUE;
}

static gboolean component(const char *text, size_t *at, size_t end, const char *reserved)
{
    while (*at < end) {
        unsigned char ch = text[*at];
        if (alpha(ch) || digit(ch) || member(ch, "-_.!~*'()") || member(ch, reserved)) ++*at;
        else if (ch == '%' && end-*at >= 3 && hex(text[*at+1]) && hex(text[*at+2]) &&
            (text[*at+1] != '0' || text[*at+2] != '0')) *at += 3;
        else return FALSE;
    }
    return TRUE;
}

gboolean barev_post_reference(const char *text, size_t available, gboolean empty)
{
    size_t n, at, end, fragment, limit;
    if (!length(text, available, BAREV_POST_MAX_ID_BYTES, &n)) return FALSE;
    if (!n) return empty;
    for (at = 0; at < n; ++at) if ((unsigned char)text[at] <= 32 || (unsigned char)text[at] >= 127) return FALSE;
    if (!alpha(text[0])) return FALSE;
    at = 1;
    while (at < n && (alpha(text[at]) || digit(text[at]) || member(text[at], "+-."))) ++at;
    if (at == n || text[at++] != ':') return FALSE;
    for (fragment = at; fragment < n && text[fragment] != '#'; ++fragment) {}
    end = fragment;
    if (at == end) return FALSE;
    if (text[at] == '/') {
        if (end-at >= 2 && text[at+1] == '/') {
            at += 2;
            for (limit = at; limit < end && text[limit] != '/' && text[limit] != '?'; ++limit) {}
            if (!component(text, &at, limit, "$,;:@&=+")) return FALSE;
        }
        for (limit = at; limit < end && text[limit] != '?'; ++limit) {}
        if (!component(text, &at, limit, ":@&=+$,;/")) return FALSE;
        if (at < end) { ++at; if (!component(text, &at, end, ";/?:@&=+$,[]")) return FALSE; }
    } else if (!component(text, &at, end, ";/?:@&=+$,[]")) return FALSE;
    if (fragment < n) { at = fragment+1; if (!component(text, &at, n, ";/?:@&=+$,[]")) return FALSE; }
    return TRUE;
}

gboolean barev_post_timestamp(const char *stamp, size_t available)
{
    static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    size_t i, n;
    unsigned year = 0, month, day, hour, minute, second, maximum;
    if (!length(stamp, available, 20, &n) || n != 20 || stamp[4] != '-' || stamp[7] != '-' ||
        stamp[10] != 'T' || stamp[13] != ':' || stamp[16] != ':' || stamp[19] != 'Z') return FALSE;
    for (i = 0; i < 19; ++i)
        if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 && !digit(stamp[i])) return FALSE;
    for (i = 0; i < 4; ++i) year = year*10+stamp[i]-'0';
    month = (stamp[5]-'0')*10+stamp[6]-'0'; day = (stamp[8]-'0')*10+stamp[9]-'0';
    hour = (stamp[11]-'0')*10+stamp[12]-'0'; minute = (stamp[14]-'0')*10+stamp[15]-'0';
    second = (stamp[17]-'0')*10+stamp[18]-'0';
    if (!year || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return FALSE;
    maximum = days[month-1];
    if (month == 2 && year%4 == 0 && (year%100 != 0 || year%400 == 0)) ++maximum;
    return day >= 1 && day <= maximum;
}

static void digits(unsigned value, unsigned width, char *output)
{ while (width) { output[--width] = '0'+value%10; value /= 10; } }

gboolean barev_post_utc(int64_t seconds, char *stamp, size_t available)
{
    unsigned z, era, doe, yoe, doy, mp, year, month, day, sod;
    char next[21] = "0000-00-00T00:00:00Z";
    if (!stamp || available < sizeof(next) || seconds < 0 || seconds > INT64_C(253402300799)) return FALSE;
    z = (unsigned)(seconds/86400)+719468; sod = seconds%86400;
    era = z/146097; doe = z-era*146097;
    yoe = (doe-doe/1460+doe/36524-doe/146096)/365;
    doy = doe-(365*yoe+yoe/4-yoe/100); mp = (5*doy+2)/153;
    day = doy-(153*mp+2)/5+1; month = mp < 10 ? mp+3 : mp-9;
    year = yoe+era*400+(month <= 2);
    digits(year, 4, next); digits(month, 2, next+5); digits(day, 2, next+8);
    digits(sod/3600, 2, next+11); digits(sod%3600/60, 2, next+14); digits(sod%60, 2, next+17);
    memcpy(stamp, next, sizeof(next)); return TRUE;
}

gboolean barev_post_identifiers(const unsigned char *entropy, size_t length,
    char *item, size_t item_size, char *id, size_t id_size)
{
    static const char hex_digits[] = "0123456789abcdef";
    unsigned i, j, value;
    char token[33], atom[46] = "urn:uuid:";
    if (!entropy || length != 16 || !item || item_size < sizeof(token) || !id || id_size < sizeof(atom)) return FALSE;
    for (i = 0; i < 16; ++i) {
        value = entropy[i]; if (i == 6) value = 64+value%16; else if (i == 8) value = 128+value%64;
        token[2*i] = hex_digits[value/16]; token[2*i+1] = hex_digits[value%16];
    }
    token[32] = 0; j = 9;
    for (i = 0; i < 32; ++i) {
        if (i == 8 || i == 12 || i == 16 || i == 20) atom[j++] = '-';
        atom[j++] = token[i];
    }
    atom[j] = 0; memcpy(item, token, sizeof(token)); memcpy(id, atom, sizeof(atom)); return TRUE;
}

BarevPost *barev_post_new(const BarevPostHeader *header, const char *text, size_t available)
{
    BarevPost *post;
    size_t n, author_length;
    const char *at;
    char *author;
    if (!header || !barev_post_owner(header->owner, sizeof(header->owner)) ||
        !barev_post_token(header->item, sizeof(header->item), BAREV_POST_MAX_ITEM_BYTES) ||
        !barev_post_reference(header->id, sizeof(header->id), FALSE) ||
        !barev_post_reference(header->parent, sizeof(header->parent), TRUE) || !strcmp(header->id, header->parent) ||
        !barev_post_timestamp(header->published, sizeof(header->published)) ||
        !barev_post_timestamp(header->updated, sizeof(header->updated)) || strcmp(header->updated, header->published) < 0 ||
        !barev_post_text(header->title, sizeof(header->title), BAREV_POST_MAX_TITLE_BYTES, TRUE) ||
        !barev_post_text(text, available, BAREV_POST_MAX_TEXT_BYTES, FALSE) ||
        !length(header->author, sizeof(header->author), sizeof(header->author)-1, &author_length)) return NULL;
    at = strchr(header->author, '@'); if (!at || strlen(at+1) > 40) return NULL;
    author = barev_address_identity(header->author, FALSE); if (!author) return NULL;
    n = strlen(text); post = g_try_malloc(sizeof(*post)+n+1);
    if (!post) { g_free(author); return NULL; }
    post->refs = 1; post->header = *header; g_strlcpy(post->header.author, author, sizeof(post->header.author));
    post->size = strlen(header->item)+strlen(header->id)+strlen(header->parent)+64+strlen(author)+strlen(header->title)+40+n;
    memcpy(post->text, text, n+1); g_free(author); return post;
}

BarevPost *barev_post_ref(BarevPost *post)
{ if (!post || post->refs == UINT_MAX) return NULL; ++post->refs; return post; }
void barev_post_unref(BarevPost *post) { if (post && !--post->refs) g_free(post); }
const BarevPostHeader *barev_post_header(const BarevPost *post) { return post ? &post->header : NULL; }
const char *barev_post_content(const BarevPost *post) { return post ? post->text : NULL; }
uint32_t barev_post_size(const BarevPost *post) { return post ? post->size : 0; }

gboolean barev_post_revision(const BarevPost *previous, const BarevPost *next)
{
    return previous && next && !strcmp(previous->header.item, next->header.item) &&
        !strcmp(previous->header.id, next->header.id) && !strcmp(previous->header.parent, next->header.parent) &&
        !strcmp(previous->header.owner, next->header.owner) && !strcmp(previous->header.author, next->header.author) &&
        !strcmp(previous->header.published, next->header.published) && strcmp(next->header.updated, previous->header.updated) > 0;
}

gboolean barev_post_same(const BarevPost *left, const BarevPost *right)
{
    return left && right && !strcmp(left->header.item, right->header.item) && !strcmp(left->header.id, right->header.id) &&
        !strcmp(left->header.parent, right->header.parent) && !strcmp(left->header.owner, right->header.owner) &&
        !strcmp(left->header.author, right->header.author) && !strcmp(left->header.title, right->header.title) &&
        !strcmp(left->header.published, right->header.published) && !strcmp(left->header.updated, right->header.updated) &&
        !strcmp(left->text, right->text);
}
