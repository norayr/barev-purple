/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "internal.h"
#include "address.h"
#include <string.h>

static const char suffix[] = ".barev.v6.alt";
static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

gboolean
barev_address_encode(const unsigned char ip[16], char *host, size_t size)
{
    char label[26];
    size_t i, bit, run, best = 0, longest = 1, out = 0;
    if (!ip || !host || size < 40) return FALSE;
    for (i = 0; i < 26; ++i) {
        unsigned value = 0;
        for (bit = 0; bit < 5; ++bit) {
            size_t at = i*5+bit;
            value = value*2 + (at < 128 ? (ip[at/8] >> (7-at%8)) & 1 : 0);
        }
        label[i] = alphabet[value];
    }
    for (i = 1; i < 25;) {
        for (run = 0; i+run < 25 && label[i+run] == 'a'; ++run) {}
        if (run > longest) { best = i; longest = run; }
        i += run ? run : 1;
    }
    for (i = 0; i < 26;) {
        if (i == best && longest > 1) { host[out++] = '-'; i += longest; }
        else host[out++] = label[i++];
    }
    memcpy(host+out, suffix, sizeof(suffix));
    return TRUE;
}

gboolean
barev_address_decode(const char *host, unsigned char ip[16])
{
    char label[26];
    size_t n, size, i, j, out = 0, hyphen = 26;
    unsigned value = 0, bits = 0;
    if (!host || !ip) return FALSE;
    for (n = 0; n <= 40 && host[n]; ++n) {}
    if (n < 16 || n > 40) return FALSE;
    if (host[n-1] == '.') --n;
    size = n-(sizeof(suffix)-1);
    if (size < 3 || size > 26 || g_ascii_strncasecmp(host+size, suffix, sizeof(suffix)-1)) return FALSE;
    for (i = 0; i < size; ++i) {
        if (host[i] == '-') {
            if (hyphen != 26 || i == 0 || i == size-1 || size > 25) return FALSE;
            hyphen = i;
        }
    }
    if (hyphen == 26 && size != 26) return FALSE;
    for (i = 0; i < size; ++i) {
        if (i == hyphen) for (j = 0; j <= 26-size; ++j) label[out++] = 'a';
        else label[out++] = g_ascii_tolower(host[i]);
    }
    out = 0;
    for (i = 0; i < 26; ++i) {
        unsigned digit;
        if (label[i] >= 'a' && label[i] <= 'z') digit = label[i]-'a';
        else if (label[i] >= '2' && label[i] <= '7') digit = label[i]-'2'+26;
        else return FALSE;
        value = value*32+digit;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            ip[out++] = value >> bits;
            value &= (1u << bits)-1;
        }
    }
    /* RFC 4648's two unused low bits must be zero. */
    return value == 0;
}

char *
barev_address_identity(const char *name, gboolean encoded)
{
    const char *at;
    unsigned char ip[16];
    char host[INET6_ADDRSTRLEN];
    char *nick, *result;
    if (!name || strlen(name) >= 384 || !g_utf8_validate(name, -1, NULL)) return NULL;
    at = strchr(name, '@');
    if (!at || at == name || at-name > 256 || strchr(at+1, '@')) return NULL;
    for (const char *p = name; p < at; p = g_utf8_next_char(p)) {
        gunichar ch = g_utf8_get_char(p);
        if (ch <= 32 || (ch >= 127 && ch <= 160) || ch == '/' || ch == 0x1680 ||
            (ch >= 0x2000 && ch <= 0x200f) || (ch >= 0x2028 && ch <= 0x202f) ||
            (ch >= 0x205f && ch <= 0x206f) || ch == 0x3000 || ch == 0xfeff ||
            ch == 0xfffe || ch == 0xffff) return NULL;
    }
    if (inet_pton(AF_INET6, at+1, ip) != 1 && !barev_address_decode(at+1, ip)) return NULL;
    if (ip[0] != 2 && ip[0] != 3) return NULL;
    if (encoded) {
        if (!barev_address_encode(ip, host, sizeof(host))) return NULL;
    } else if (!inet_ntop(AF_INET6, ip, host, sizeof(host))) return NULL;
    nick = g_strndup(name, at-name);
    result = g_strdup_printf("%s@%s", nick, host);
    g_free(nick);
    return result;
}
