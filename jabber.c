/*
 * purple - Bonjour Protocol Plugin
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"

#ifndef _WIN32
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iptypes.h>
#else
#include <sys/socket.h>
#endif
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include "libc_interface.h"
#endif
#include <sys/types.h>

/* Solaris */
#if defined (__SVR4) && defined (__sun)
#include <sys/sockio.h>
#endif

#include <glib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif


#include "network.h"
#include "eventloop.h"
#include "connection.h"
#include "blist.h"
#include "xmlnode.h"
#include "debug.h"
#include "notify.h"
#include "util.h"

#include "jabber.h"
#include "address.h"
#include "jingle/jingle.h"
#include "parser.h"
#include "barev.h"
#include "buddy.h"
#include "bonjour_ft.h"
#include "libpurple/server.h"

#include "buddyicon.h"
#include "notify.h"
#include "imgstore.h"
#include "image-ui.h"

#ifdef _SIZEOF_ADDR_IFREQ
#  define HX_SIZE_OF_IFREQ(a) _SIZEOF_ADDR_IFREQ(a)
#else
#  define HX_SIZE_OF_IFREQ(a) sizeof(a)
#endif

#ifndef HAVE_GETIFADDRS
#define HAVE_GETIFADDRS 1
#endif

#if defined(_WIN32)

struct ifaddrs {
	struct ifaddrs  *ifa_next;
	char            *ifa_name; /* UTF-8 friendly name */
	unsigned int     ifa_flags;
	struct sockaddr *ifa_addr;
	struct sockaddr *ifa_netmask;
};

static inline void
freeifaddrs(struct ifaddrs *ifa)
{
    while (ifa) {
        struct ifaddrs *next = ifa->ifa_next;
        free(ifa);
        ifa = next;
    }
}

static inline struct ifaddrs *
_win_ifaddrs_add(struct ifaddrs ***tail, const struct sockaddr *sa, int salen,
                 const struct sockaddr *mask, int masklen,
                 unsigned int flags, const char *name)
{
    size_t slot = sizeof(struct sockaddr_storage);
    struct ifaddrs *n = (struct ifaddrs *)calloc(1, sizeof(struct ifaddrs) + 2 * slot + strlen(name) + 1);
    if (!n)
        return NULL;

    n->ifa_addr = (struct sockaddr *)(n + 1);
    n->ifa_netmask = (struct sockaddr *)((char *)n->ifa_addr + slot);
    n->ifa_name = (char *)n->ifa_netmask + slot;
    memcpy(n->ifa_addr, sa, salen);
    if (mask)
        memcpy(n->ifa_netmask, mask, masklen);
    strcpy(n->ifa_name, name);
    n->ifa_flags = flags;
    **tail = n;
    *tail = &n->ifa_next;

    return n;
}

static inline int
getifaddrs(struct ifaddrs **ifap)
{
    struct ifaddrs *head = NULL, **tail = &head;
    SOCKET s;
    DWORD bytes = 0;
    int got_any = 0;

    *ifap = NULL;

    /* IPv4 */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s != INVALID_SOCKET) {
        INTERFACE_INFO info[64];
        if (WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, info, sizeof(info), &bytes, NULL, NULL) == 0) {
            unsigned int i, n = bytes / sizeof(INTERFACE_INFO);
            for (i = 0; i < n; i++) {
                char name[32];
                if (info[i].iiAddress.Address.sa_family != AF_INET)
                    continue;
                snprintf(name, sizeof(name), "if%u", i + 1);
                if (!_win_ifaddrs_add(&tail,
                        (struct sockaddr *)&info[i].iiAddress.AddressIn,
                        sizeof(struct sockaddr_in),
                        (struct sockaddr *)&info[i].iiNetmask.AddressIn,
                        sizeof(struct sockaddr_in),
                        (unsigned int)info[i].iiFlags, name)) {
                    closesocket(s);
                    freeifaddrs(head);
                    return -1;
                }
                got_any = 1;
            }
        }
        closesocket(s);
    }

    /* IPv6 */
    s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s != INVALID_SOCKET) {
        char buf[4096];
        SOCKET_ADDRESS_LIST *list = (SOCKET_ADDRESS_LIST *)buf;
        if (WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, sizeof(buf), &bytes, NULL, NULL) == 0) {
            INT i;
            for (i = 0; i < list->iAddressCount; i++) {
                struct sockaddr *sa = list->Address[i].lpSockaddr;
                struct sockaddr_in6 mask;
                char name[32];
                unsigned int flags = IFF_UP | IFF_MULTICAST;
                int k;

                if (!sa || sa->sa_family != AF_INET6 ||
                    list->Address[i].iSockaddrLength < (int)sizeof(struct sockaddr_in6))
                    continue;
                if (IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)sa)->sin6_addr))
                    flags |= IFF_LOOPBACK;

                memset(&mask, 0, sizeof(mask));
                mask.sin6_family = AF_INET6;
                for (k = 0; k < 8; k++)
                    mask.sin6_addr.s6_addr[k] = 0xFF;

                snprintf(name, sizeof(name), "if%lu", (unsigned long)((struct sockaddr_in6 *)sa)->sin6_scope_id);
                if (!_win_ifaddrs_add(&tail, sa, sizeof(struct sockaddr_in6),
                                      (struct sockaddr *)&mask, sizeof(mask),
                                      flags, name)) {
                    closesocket(s);
                    freeifaddrs(head);
                    return -1;
                }
                got_any = 1;
            }
        }
        closesocket(s);
    }

    *ifap = head;
    return got_any ? 0 : -1;
}

/* Win32-specific helper functionality: some functions are not existing in Windows Sockets API, so we should implement remaining ones by ourselves */

static inline unsigned int
if_nametoindex(const char *name)
{
    char *end = NULL;
    unsigned long idx;

    if (!name || !*name)
        return 0;

    idx = strtoul(name, &end, 10);
    return (end && *end == '\0') ? (unsigned int)idx : 0;
}

#endif

/* TODO: specify version='1.0' and send stream features */
#define DOCTYPE "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
    "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" from=\"%s\" to=\"%s\">"


#define PING_INTERVAL 30      /* Send ping every 30 seconds */
#define PING_TIMEOUT 10       /* Wait 10 seconds for response */
#define MAX_PING_FAILURES 2   /* Mark offline after 2 consecutive failures */

#define BAREV_VCARD_NS         "vcard-temp"
#define BAREV_VCARD_UPDATE_NS  "vcard-temp:x:update"

static guint barev_avatar_id_counter = 0;
static GSList *barev_conversations;
static gboolean bonjour_peer_allowed(PurpleAccount *account, const char *ip);
static gint _send_data(PurpleBuddy *pb, char *message);
static char *bonjour_jabber_packet_xml(PurpleBuddy *pb, xmlnode *packet);
static gchar * barev_make_iq_id(const char *prefix);
static void _jabber_parse_and_write_message_to_ui(xmlnode *message_node, PurpleBuddy *pb);
static void _bonjour_handle_presence(PurpleBuddy *pb, xmlnode *presence_node);
typedef struct {
    PurpleNotifyUserInfo *info;
    int avatar_img_id; /* 0 if none */
} BarevUserInfoCloseData;

#define NOT_SENT       STREAM_NOT_SENT
#define PARTIALLY_SENT STREAM_PARTIALLY_SENT
#define FULLY_SENT     STREAM_FULLY_SENT

typedef struct {
    PurpleAccount *account;
    char *who;
} BarevVcardReq;

static void
barev_userinfo_close_cb(gpointer user_data)
{
    BarevUserInfoCloseData *d = (BarevUserInfoCloseData *)user_data;
    if (!d) return;

    if (d->avatar_img_id > 0)
        purple_imgstore_unref_by_id(d->avatar_img_id);

    if (d->info)
        purple_notify_user_info_destroy(d->info);

    g_free(d);
}

/*
 * Add avatar from a parsed <vCard/> into a PurpleNotifyUserInfo popup.
 * Returns imgstore id (caller must unref later), or 0 if no avatar.
 */
static int
barev_userinfo_add_avatar(PurpleNotifyUserInfo *info, xmlnode *vcard)
{
    xmlnode *photo, *binval, *type_node;
    gchar *b64 = NULL;
    guchar *raw = NULL;
    gsize raw_len = 0;
    gchar *type_s = NULL;
    gchar *filename = NULL;
    gchar *html = NULL;
    int img_id = 0;

    if (!info || !vcard)
        return 0;

    photo = xmlnode_get_child(vcard, "PHOTO");
    if (!photo)
        return 0;

    binval = xmlnode_get_child(photo, "BINVAL");
    if (!binval)
        return 0;

    b64 = xmlnode_get_data(binval);
    if (!b64 || !*b64) {
        g_free(b64);
        return 0;
    }

    raw = g_base64_decode(b64, &raw_len);
    g_free(b64);

    if (!raw || raw_len == 0) {
        g_free(raw);
        return 0;
    }

    /* Optional MIME type, e.g. image/jpeg */
    type_node = xmlnode_get_child(photo, "TYPE");
    if (type_node)
        type_s = xmlnode_get_data(type_node);

    /* Filename is just "for convenience" in imgstore */
    if (type_s && g_str_has_prefix(type_s, "image/")) {
        filename = g_strdup_printf("barev-avatar.%s", type_s + 6);
    } else {
        filename = g_strdup("barev-avatar");
    }

    /* Takes ownership of raw on success; caller owns a ref by id and must unref */
    img_id = purple_imgstore_add_with_id(raw, raw_len, filename);
    g_free(filename);
    g_free(type_s);

    if (img_id <= 0) {
        /* If add_with_id failed, it did NOT take ownership */
        g_free(raw);
        return 0;
    }

    /*
     * Pidgin turns <img ...> without id into a link.
     * So we embed <img id="..."> referencing imgstore.
     */
    html = g_strdup_printf("<img id=\"%d\" alt=\"avatar\"/>", img_id);

    purple_notify_user_info_add_pair(info, "Avatar", html);
    g_free(html);

    return img_id;
}

static void barev_vcard_req_free(BarevVcardReq *r)
{
    if (!r) return;
    g_free(r->who);
    g_free(r);
}

static GHashTable *barev_vcard_userinfo = NULL;

gboolean
bonjour_jabber_request_vcard(PurpleBuddy *pb, gboolean for_userinfo)
{
    BonjourBuddy *bb;
    BonjourJabberConversation *bconv;
    PurpleAccount *account;
    const char *from, *to;
    xmlnode *iq, *vcard;
    gchar *id, *xml;

    if (!pb)
        return FALSE;

    bb = purple_buddy_get_protocol_data(pb);
    if (!bb || !bb->conversation)
        return FALSE;

    bconv = bb->conversation;

    /* Must be a real, fully-started stream (not a pending connect) */
    if (bconv->socket < 0)
        return FALSE;

    if (bconv->connect_data != NULL)
        return FALSE;

    if (bconv->sent_stream_start != FULLY_SENT || !bconv->recv_stream_start)
        return FALSE;

    if (!for_userinfo && (!barev_avatar_hash_valid(bb->phsh) ||
        barev_avatar_request_pending(&bb->avatar_request, g_get_monotonic_time())))
        return FALSE;

    account = purple_buddy_get_account(pb);
    from = bonjour_jabber_get_local_jid(bconv);
    to   = purple_buddy_get_name(pb);

    id = barev_make_iq_id("vcard");

    if (for_userinfo) {
        if (!barev_vcard_userinfo) {
            barev_vcard_userinfo = g_hash_table_new_full(
                g_str_hash, g_str_equal,
                g_free, (GDestroyNotify)barev_vcard_req_free
            );
        }
        BarevVcardReq *r = g_new0(BarevVcardReq, 1);
        r->account = account;
        r->who = g_strdup(to);
        g_hash_table_replace(barev_vcard_userinfo, g_strdup(id), r);
    }

    iq = xmlnode_new("iq");
    xmlnode_set_attrib(iq, "type", "get");
    xmlnode_set_attrib(iq, "id", id);
    if (from && *from) xmlnode_set_attrib(iq, "from", from);
    if (to   && *to)   xmlnode_set_attrib(iq, "to", to);

    vcard = xmlnode_new_child(iq, "vCard");
    xmlnode_set_namespace(vcard, BAREV_VCARD_NS);

    xml = bonjour_jabber_packet_xml(pb, iq);
    xmlnode_free(iq);

    if (!for_userinfo)
        barev_avatar_request_begin(&bb->avatar_request, id, bb->phsh, g_get_monotonic_time());
    purple_debug_info("barev", "Barev: sending vCard GET to %s id=%s\n", to, id);
    _send_data(pb, xml);

    g_free(xml);
    g_free(id);

    return TRUE;
}

static gchar *
barev_guess_mime_type(const guchar *data, gsize len)
{
    if (!data || len < 4) return NULL;

    /* PNG */
    if (len >= 8 &&
        data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 &&
        data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A)
        return g_strdup("image/png");

    /* JPEG */
    if (len >= 2 && data[0] == 0xFF && data[1] == 0xD8)
        return g_strdup("image/jpeg");

    /* GIF */
    if (len >= 6 &&
        data[0] == 'G' && data[1] == 'I' && data[2] == 'F' &&
        (data[3] == '8') && (data[4] == '7' || data[4] == '9') && data[5] == 'a')
        return g_strdup("image/gif");

    return NULL;
}

static gchar *
barev_sha1_hex(const guchar *data, gsize len)
{
    if (!data || len == 0) return NULL;
    /* Returns newly allocated lowercase hex string */
    return g_compute_checksum_for_data(G_CHECKSUM_SHA1, data, len);
}

static gchar *
barev_make_iq_id(const char *prefix)
{
    return g_strdup_printf("%s-%lu-%u",
                           prefix ? prefix : "id",
                           (unsigned long)time(NULL),
                           ++barev_avatar_id_counter);
}

/* Returns sha1 hex of current account icon bytes (or NULL if none). */
static gchar *
barev_get_account_avatar_sha1(PurpleAccount *account)
{
    PurpleStoredImage *img;
    const guchar *data;
    gsize len;
    gchar *sha1 = NULL;

    if (!account) return NULL;

    img = purple_buddy_icons_find_account_icon(account);
    if (!img) return NULL;

    data = (const guchar *)purple_imgstore_get_data(img);
    len  = (gsize)purple_imgstore_get_size(img);

    if (data && len > 0)
        sha1 = barev_sha1_hex(data, len);

    purple_imgstore_unref(img);
    return sha1;
}

static void
barev_presence_add_avatar_update(xmlnode *presence_node, PurpleAccount *account)
{
    xmlnode *x, *photo;
    gchar *sha1 = barev_get_account_avatar_sha1(account);

    x = xmlnode_new_child(presence_node, "x");
    xmlnode_set_namespace(x, BAREV_VCARD_UPDATE_NS);

    photo = xmlnode_new_child(x, "photo");
    if (sha1 && *sha1)
        xmlnode_insert_data(photo, sha1, strlen(sha1));

    g_free(sha1);
}

static void
barev_clear_buddy_icon(PurpleBuddy *pb, BonjourBuddy *bb)
{
    PurpleAccount *account;
    const char *name;

    if (!pb || !bb) return;

    account = purple_buddy_get_account(pb);
    name = purple_buddy_get_name(pb);

    g_free(bb->phsh);
    bb->phsh = NULL;
    barev_avatar_request_clear(&bb->avatar_request);

    if (account && name)
        purple_buddy_icons_set_for_user(account, name, NULL, 0, NULL);
}

static void
barev_handle_vcard_result(PurpleBuddy *pb, xmlnode *vcard, const char *expected)
{
    BonjourBuddy *bb;
    xmlnode *photo, *binval;
    gchar *b64 = NULL;
    guchar *raw = NULL;
    gsize raw_len = 0;
    gchar *sha1 = NULL;

    if (!pb || !vcard) return;

    bb = purple_buddy_get_protocol_data(pb);
    if (!bb) return;

    photo = xmlnode_get_child(vcard, "PHOTO");
    if (!photo) return;

    binval = xmlnode_get_child(photo, "BINVAL");
    if (!binval) return;

    b64 = xmlnode_get_data(binval);
    if (!b64 || !*b64) {
        g_free(b64);
        return;
    }

    raw = g_base64_decode(b64, &raw_len);
    g_free(b64);

    if (!raw || raw_len == 0 || raw_len > BAREV_AVATAR_MAX_BYTES) {
        g_free(raw);
        return;
    }

    sha1 = barev_sha1_hex(raw, raw_len);
    if (!sha1 || (expected && g_ascii_strcasecmp(sha1, expected))) {
        purple_debug_warning("barev", "Avatar reply rejected: advertised SHA-1 mismatch.\n");
        g_free(sha1); g_free(raw); return;
    }
    if (sha1) {
        g_free(bb->phsh);
        bb->phsh = g_strdup(sha1);
    }

    bonjour_buddy_got_buddy_icon(bb, raw, raw_len);

    g_free(sha1);
    g_free(raw);
}

/* Handle incoming <iq> vCard get/result. Return TRUE if handled. */
static gboolean
barev_handle_vcard_iq(xmlnode *packet, PurpleBuddy *pb)
{
    const char *type, *id;
    xmlnode *vcard;
    BonjourBuddy *avatar_buddy;

    if (!packet || !pb) return FALSE;
    if (!purple_strequal(packet->name, "iq")) return FALSE;

    type = xmlnode_get_attrib(packet, "type");
    id   = xmlnode_get_attrib(packet, "id");
    avatar_buddy = purple_buddy_get_protocol_data(pb);
    if (type && !g_ascii_strcasecmp(type, "error") && avatar_buddy && id &&
        !g_strcmp0(id, avatar_buddy->avatar_request.id)) {
        barev_avatar_request_clear(&avatar_buddy->avatar_request);
        return TRUE;
    }
    vcard = xmlnode_get_child_with_namespace(packet, "vCard", BAREV_VCARD_NS);
    if (!vcard) return FALSE;

    if (type && !g_ascii_strcasecmp(type, "get")) {
        /* Peer requests our vCard: reply with PHOTO if we have an account icon */
        PurpleAccount *account = purple_buddy_get_account(pb);
        BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
        const char *from = bb && bb->conversation
                           ? bonjour_jabber_get_local_jid(bb->conversation)
                           : account ? bonjour_get_jid(account) : "";
        const char *to   = purple_buddy_get_name(pb);

        PurpleStoredImage *img = NULL;
        const guchar *data = NULL;
        gsize len = 0;

        xmlnode *iq = xmlnode_new("iq");
        xmlnode *out_vcard;
        gchar *xml;

        xmlnode_set_attrib(iq, "type", "result");
        if (id && *id) xmlnode_set_attrib(iq, "id", id);
        if (from && *from) xmlnode_set_attrib(iq, "from", from);
        if (to   && *to)   xmlnode_set_attrib(iq, "to", to);

        out_vcard = xmlnode_new_child(iq, "vCard");
        xmlnode_set_namespace(out_vcard, BAREV_VCARD_NS);

        img = (account ? purple_buddy_icons_find_account_icon(account) : NULL);
        if (img) {
            data = (const guchar *)purple_imgstore_get_data(img);
            len  = (gsize)purple_imgstore_get_size(img);
        }

        if (img && data && len > 0) {
            gchar *mime = barev_guess_mime_type(data, len);
            gchar *b64  = g_base64_encode(data, len);

            xmlnode *photo = xmlnode_new_child(out_vcard, "PHOTO");

            if (mime && *mime) {
                xmlnode *t = xmlnode_new_child(photo, "TYPE");
                xmlnode_insert_data(t, mime, strlen(mime));
            }

            if (b64 && *b64) {
                xmlnode *bv = xmlnode_new_child(photo, "BINVAL");
                xmlnode_insert_data(bv, b64, strlen(b64));
            }

            g_free(mime);
            g_free(b64);
        }

        if (img)
            purple_imgstore_unref(img);

        xml = bonjour_jabber_packet_xml(pb, iq);
        xmlnode_free(iq);

        _send_data(pb, xml);
        g_free(xml);

        return TRUE;
    }

    if (type && !g_ascii_strcasecmp(type, "result")) {
        BarevVcardReq *userinfo = id && barev_vcard_userinfo ? g_hash_table_lookup(barev_vcard_userinfo, id) : NULL;
        gboolean avatar_reply = avatar_buddy &&
            barev_avatar_request_pending(&avatar_buddy->avatar_request, g_get_monotonic_time()) &&
            id && !g_strcmp0(id, avatar_buddy->avatar_request.id);
        if (avatar_reply) {
            gchar *expected = g_strdup(avatar_buddy->avatar_request.hash);
            barev_avatar_request_clear(&avatar_buddy->avatar_request);
            if (!g_strcmp0(expected, avatar_buddy->phsh)) barev_handle_vcard_result(pb, vcard, expected);
            else if (barev_avatar_hash_valid(avatar_buddy->phsh)) bonjour_jabber_request_vcard(pb, FALSE);
            g_free(expected);
        } else if (userinfo && userinfo->account == purple_buddy_get_account(pb) &&
                   purple_strequal(userinfo->who, purple_buddy_get_name(pb))) {
            barev_handle_vcard_result(pb, vcard, avatar_buddy ? avatar_buddy->phsh : NULL);
        }

        /* if this id was requested by "Get Info", show a userinfo popup */
        if (userinfo && userinfo->account == purple_buddy_get_account(pb) &&
            purple_strequal(userinfo->who, purple_buddy_get_name(pb))) {
            BarevVcardReq *r = userinfo;
            if (r) {
                PurpleConnection *gc = purple_account_get_connection(r->account);
                PurpleNotifyUserInfo *info;

                if (gc == NULL) {
                    /* Account went away while the vCard request was in flight. */
                    g_hash_table_remove(barev_vcard_userinfo, id);
                    return TRUE;
                }

                info = purple_notify_user_info_new();

                gchar *fn = NULL;
                xmlnode *fn_node = xmlnode_get_child(vcard, "FN");
                if (fn_node) fn = xmlnode_get_data(fn_node);

                purple_notify_user_info_add_pair_plaintext(info, "JID", r->who);
                barev_address_info(info, r->who, purple_buddy_get_protocol_data(pb));
                if (fn && *fn) purple_notify_user_info_add_pair_plaintext(info, "Full Name", fn);

                {
                    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
                    if (bb && bb->msg && *bb->msg)
                        purple_notify_user_info_add_pair_plaintext(info, "Status", bb->msg);
                }

                /* show avatar hash we currently track (if any) */
                {
                    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
                    if (bb && bb->phsh)
                        purple_notify_user_info_add_pair_plaintext(info, "Avatar SHA1", bb->phsh);
                }

                int avatar_id = 0;
                BarevUserInfoCloseData *cd = NULL;
                avatar_id = barev_userinfo_add_avatar(info, vcard);

                cd = g_new0(BarevUserInfoCloseData, 1);
                cd->info = info;
                cd->avatar_img_id = avatar_id;

                purple_notify_userinfo(gc, r->who, info, barev_userinfo_close_cb, cd);

                g_free(fn);

                g_hash_table_remove(barev_vcard_userinfo, id);
            }
        }

        return TRUE;
    }


    /* error / set etc: ignore but mark as handled so xfer code doesn't touch it */
    if (type && (!g_ascii_strcasecmp(type, "error") || !g_ascii_strcasecmp(type, "set")))
        return TRUE;

    return FALSE;
}

static void
xep_iq_parse(xmlnode *packet, PurpleBuddy *pb)
{
  PurpleAccount *account;
  PurpleConnection *gc;

    if (!packet || !pb) {
    purple_debug_error("barev", "xep_iq_parse: NULL input\n");
    return;
    }
    if (!packet) {
        purple_debug_error("barev", "xep_iq_parse: NULL packet!\n");
        return;
    }
    if (!pb) {
        purple_debug_error("barev", "xep_iq_parse: NULL buddy!\n");
        return;
    }

    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
    if (!bb) {
        purple_debug_error("barev", "xep_iq_parse: No buddy data!\n");
        return;
    }
    if (!bb->conversation) {
        purple_debug_error("barev", "xep_iq_parse: No conversation!\n");
        return;
    }

  account = purple_buddy_get_account(pb);
  gc = purple_account_get_connection(account);

  if (xmlnode_get_child(packet, "si") != NULL || xmlnode_get_child(packet, "error") != NULL)
    xep_si_parse(gc, packet, pb);
  else
    xep_bytestreams_parse(gc, packet, pb);
}


static void
safe_set_buddy_status(PurpleAccount *account, const char *who, const char *status_id,
                      const char *attr_name, const char *attr_value)
{
    if (!account || !who || !status_id) {
        purple_debug_error("barev", "NULL parameter in safe_set_buddy_status\n");
        return;
    }

    PurpleStatusType *stype = purple_account_get_status_type(account, status_id);
    if (!stype) {
        purple_debug_error("barev", "No status type '%s' for account\n", status_id);
        return;
    }

    if (attr_name && attr_value) {
        purple_prpl_got_user_status(account, who, status_id, attr_name, attr_value, NULL);
    } else {
        purple_prpl_got_user_status(account, who, status_id, NULL);
    }
}

/* Get the JID for a specific conversation based on its actual source IP. */
const char *
bonjour_jabber_get_local_jid(BonjourJabberConversation *bconv)
{
    static char jid_buf[512];
    const char *username = purple_account_get_username(bconv->account);

    if (bconv->local_ip && *bconv->local_ip) {
        g_snprintf(jid_buf, sizeof(jid_buf), "%s@%s", username, bconv->local_ip);
    } else {
        /* Fallback to account-wide JID */
        const char *global_jid = bonjour_get_jid(bconv->account);
        if (global_jid && *global_jid)
            g_strlcpy(jid_buf, global_jid, sizeof(jid_buf));
        else
            jid_buf[0] = '\0';
    }

    return jid_buf;
}

static void
barev_refresh_account_jid(BonjourJabberConversation *bconv)
{
    PurpleConnection *gc;
    BonjourData *bd;
    const char *local_jid;

    if (!bconv || !bconv->local_ip || !*bconv->local_ip || !bconv->account)
        return;

    gc = purple_account_get_connection(bconv->account);
    bd = gc ? gc->proto_data : NULL;
    if (!bd)
        return;

    local_jid = bonjour_jabber_get_local_jid(bconv);
    if (!local_jid || !*local_jid || purple_strequal(bd->jid, local_jid))
        return;

    purple_debug_info("barev", "Updating account JID from %s to %s\n",
                      bd->jid ? bd->jid : "(null)", local_jid);
    g_free(bd->jid);
    bd->jid = g_strdup(local_jid);
}

/* Haze may store a nickname separately from its explicitly saved address. */
static char *
bonjour_buddy_identity(PurpleBuddy *pb)
{
    const char *name = purple_buddy_get_name(pb);
    char *identity = barev_address_identity(name, FALSE);
    if (!identity && name && !strchr(name, '@')) {
        const char *ip = purple_blist_node_get_string(PURPLE_BLIST_NODE(pb), "barev_ip");
        if (ip) {
            char *full = g_strdup_printf("%s@%s", name, ip);
            identity = barev_address_identity(full, FALSE);
            g_free(full);
        }
    }
    return identity;
}

/* Keep UI nicknames and aliases separate from complete wire identities. */
static char *
bonjour_jabber_packet_xml(PurpleBuddy *pb, xmlnode *packet)
{
    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
    char *peer = bb && bb->conversation && bb->conversation->buddy_name ?
        barev_address_identity(bb->conversation->buddy_name, FALSE) : bonjour_buddy_identity(pb);
    char *local = NULL, *xml = NULL;
    if (bb && bb->conversation)
        local = barev_address_identity(bonjour_jabber_get_local_jid(bb->conversation), FALSE);
    if (peer && local) {
        xmlnode_set_attrib(packet, "from", local);
        xmlnode_set_attrib(packet, "to", peer);
        xml = xmlnode_to_str(packet, NULL);
    }
    g_free(peer); g_free(local);
    return xml;
}

/* Read both endpoints from the socket; interface enumeration cannot establish
 * which local address actually owns this connection. */
static gboolean
bonjour_validate_endpoints(BonjourJabberConversation *bconv, const char *identity)
{
    struct sockaddr_storage peer, local;
    socklen_t peer_len = sizeof(peer), local_len = sizeof(local);
    struct in6_addr expected_peer, expected_local;
    char *own = barev_address_identity(bonjour_get_jid(bconv->account), FALSE);
    const char *at = identity ? strchr(identity, '@') : NULL;
    gboolean valid = own && bconv->socket >= 0 &&
        (!identity || (at && strcmp(own, identity) && inet_pton(AF_INET6, at+1, &expected_peer) == 1)) &&
        inet_pton(AF_INET6, strchr(own, '@')+1, &expected_local) == 1 &&
        getpeername(bconv->socket, (struct sockaddr *)&peer, &peer_len) == 0 &&
        getsockname(bconv->socket, (struct sockaddr *)&local, &local_len) == 0 &&
        peer.ss_family == AF_INET6 && local.ss_family == AF_INET6 &&
        (((unsigned char *)&((struct sockaddr_in6 *)&peer)->sin6_addr)[0] == 2 ||
         ((unsigned char *)&((struct sockaddr_in6 *)&peer)->sin6_addr)[0] == 3) &&
        (!identity || !memcmp(&expected_peer, &((struct sockaddr_in6 *)&peer)->sin6_addr, 16)) &&
        !memcmp(&expected_local, &((struct sockaddr_in6 *)&local)->sin6_addr, 16);
    if (valid) {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, ip, sizeof(ip));
        g_free(bconv->ip); bconv->ip = g_strdup(ip);
        inet_ntop(AF_INET6, &expected_local, ip, sizeof(ip));
        g_free(bconv->local_ip); bconv->local_ip = g_strdup(ip);
    }
    g_free(own);
    return valid;
}

/* Resolve the normal TCP collision where both peers auto-connect at the same
 * time.  Both ends must choose the same physical connection.  The peer with
 * the lexicographically smaller JID keeps its outgoing connection; the larger
 * peer keeps the corresponding incoming connection. */
static gboolean
bonjour_candidate_wins_collision(PurpleBuddy *pb,
                                  BonjourJabberConversation *existing,
                                  BonjourJabberConversation *candidate)
{
    const char *local_jid;
    const char *remote_jid;
    gboolean prefer_outgoing;

    if (!existing || existing == candidate)
        return TRUE;

    if (existing->closing || existing->close_timeout != 0)
        return TRUE;

    /* An established stream always wins over a newly arriving duplicate. */
    if (existing->recv_stream_start && existing->sent_stream_start == FULLY_SENT)
        return FALSE;

    /* Two connections in the same direction are duplicates.  Keep the first
     * one instead of allowing a late callback to replace a working stream. */
    if (existing->incoming == candidate->incoming)
        return FALSE;

    local_jid = bonjour_jabber_get_local_jid(candidate);
    remote_jid = candidate->buddy_name;

    if (!local_jid || !remote_jid)
        return FALSE;

    {
        int order = g_ascii_strcasecmp(local_jid, remote_jid);
        prefer_outgoing = order < 0 || (order == 0 && strcmp(local_jid, remote_jid) < 0);
    }
    return candidate->incoming ? !prefer_outgoing : prefer_outgoing;
}

/* Helper to format the IPv6 */
/* Update format_host_for_proxy in jabber.c */

static gchar *
format_host_for_proxy(const gchar *ip)
{
    if (!ip) return g_strdup("");

    /* Remove any existing brackets first */
    gchar *clean_ip = g_strdup(ip);
    if (clean_ip[0] == '[') {
        /* Remove opening bracket */
        memmove(clean_ip, clean_ip + 1, strlen(clean_ip));

        /* Remove closing bracket if present */
        char *closing = strchr(clean_ip, ']');
        if (closing) *closing = '\0';
    }

    /* For IPv6 addresses, we need to handle scope IDs */
    if (strchr(clean_ip, ':')) {
        /* IPv6 address */
        if (strchr(clean_ip, '%')) {
            /* Link-local with scope - keep as is */
            gchar *result = g_strdup(clean_ip);
            g_free(clean_ip);
            return result;
        } else {
            /* Regular IPv6 - no brackets needed for proxy_connect */
            gchar *result = g_strdup(clean_ip);
            g_free(clean_ip);
            return result;
        }
    }

    /* IPv4 address - return as is */
    gchar *result = g_strdup(clean_ip);
    g_free(clean_ip);
    return result;
}

/* Ping functions */
/* Helper function to generate ping ID */
static gchar* generate_ping_id(void) {
  static guint counter = 0;
  return g_strdup_printf("ping-%lu-%u", (unsigned long)time(NULL), counter++);
}


/* Ping timeout callback */
static gboolean bonjour_jabber_ping_timeout_cb(gpointer data) {
  BonjourJabberConversation *bconv = data;

  if (!bconv || bconv->closing || bconv->close_timeout != 0) {
    return FALSE;
  }

  bconv->ping_response_timer = 0;

  if (!bconv->pb) {
    return FALSE;
  }

  bconv->ping_failures++;

  purple_debug_warning("barev", "Ping timeout for %s (failures: %d)\n",
                      purple_buddy_get_name(bconv->pb), bconv->ping_failures);

  if (bconv->ping_failures >= MAX_PING_FAILURES) {
    /* This function also clears the buddy back-pointer and marks the current
     * stream offline.  Do not touch bconv after it returns. */
    bonjour_jabber_close_conversation(bconv);
    return FALSE;
  }

  /* Try another ping immediately */
  bonjour_jabber_send_ping_request(bconv);
  return FALSE;
}

/* Periodic ping timer callback */
static gboolean bonjour_jabber_ping_timer_cb(gpointer data) {
  BonjourJabberConversation *bconv = data;

  if (!bconv || bconv->closing || bconv->close_timeout != 0 ||
      bconv->socket < 0 || !bconv->pb) {
    return FALSE;
  }

  time_t now = time(NULL);
  if (now - bconv->last_activity >= PING_INTERVAL) {
    PurpleBuddy *pb = bconv->pb;
    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
    bonjour_jabber_send_ping_request(bconv);
    /* bonjour_jabber_send_ping_request may have freed bconv on a send error.
     * Detect this via bb->conversation and do not reschedule a dead timer. */
    if (!bb || bb->conversation != bconv)
      return FALSE;
  } else {
    purple_debug_info("barev", "Skipping ping for %s - recent activity\n",
                     purple_buddy_get_name(bconv->pb));
  }

  return TRUE;
}

/* Start ping mechanism */
void bonjour_jabber_start_ping(BonjourJabberConversation *bconv) {
  if (!bconv || bconv->closing || bconv->close_timeout != 0) return;

  /* Stop any existing ping timers */
  bonjour_jabber_stop_ping(bconv);

  /* Initialize ping state */
  bconv->last_activity = time(NULL);
  bconv->ping_failures = 0;
  g_free(bconv->last_ping_id);
  bconv->last_ping_id = NULL;

  /* Start periodic ping timer */
  bconv->ping_timer = purple_timeout_add_seconds(PING_INTERVAL,
                                                bonjour_jabber_ping_timer_cb,
                                                bconv);

  purple_debug_info("barev", "Started ping mechanism for %s\n",
                   bconv->pb ? purple_buddy_get_name(bconv->pb) : "unknown");
}

/* Stop ping mechanism */
void bonjour_jabber_stop_ping(BonjourJabberConversation *bconv) {
  if (!bconv) return;

  if (bconv->ping_timer) {
    purple_timeout_remove(bconv->ping_timer);
    bconv->ping_timer = 0;
  }

  if (bconv->ping_response_timer) {
    purple_timeout_remove(bconv->ping_response_timer);
    bconv->ping_response_timer = 0;
  }

  g_free(bconv->last_ping_id);
  bconv->last_ping_id = NULL;
  bconv->ping_failures = 0;
}


/* Handle ping response */
static void bonjour_jabber_handle_ping_response(xmlnode *packet, BonjourJabberConversation *bconv) {
  if (!packet || !bconv || bconv->closing || bconv->close_timeout != 0 ||
      !bconv->last_ping_id) return;

  const char *type = xmlnode_get_attrib(packet, "type");
  const char *id = xmlnode_get_attrib(packet, "id");

  if (type && g_ascii_strcasecmp(type, "result") == 0 &&
      id && g_strcmp0(id, bconv->last_ping_id) == 0) {

    /* Cancel response timeout */
    if (bconv->ping_response_timer) {
      purple_timeout_remove(bconv->ping_response_timer);
      bconv->ping_response_timer = 0;
    }

    /* Reset failure counter */
    bconv->ping_failures = 0;

    purple_debug_info("barev", "Received ping response from %s\n",
                     purple_buddy_get_name(bconv->pb));
  }
}

static gboolean
is_ipv6_address(const gchar *str)
{
    /* Check if string looks like an IPv6 address */
    if (!str) return FALSE;

    /* Must contain colon */
    if (!strchr(str, ':')) return FALSE;

    /* Check format - should be hex digits and colons */
    const gchar *p = str;
    int colons = 0;
    int digits = 0;

    while (*p) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'f') ||
            (*p >= 'A' && *p <= 'F')) {
            digits++;
        } else if (*p == ':') {
            colons++;
        } else if (*p == '%') {
            /* Link-local with scope ID - OK */
            break;
        } else {
            /* Invalid character for IPv6 */
            return FALSE;
        }
        p++;
    }

    /* IPv6 must have at least 2 colons */
    return (colons >= 2);
}

/*
 * Return TRUE if the string `host` looks like a Yggdrasil IPv6 address.
 *
 * Yggdrasil uses 0200::/7, so the first hextet is in the range
 * 0x0200 .. 0x03FF (i.e. "200"–"3ff" in hex).
 */
static gboolean
is_yggdrasil_addr(const char *host)
{
    const char *colon;
    char hextet[5];
    long val;
    size_t len;

    if (!host || !*host)
        return FALSE;

    colon = strchr(host, ':');
    if (!colon)
        return FALSE;

    len = (size_t)(colon - host);
    if (len == 0 || len > 4)
        return FALSE;

    memcpy(hextet, host, len);
    hextet[len] = '\0';

    errno = 0;
    val = strtol(hextet, NULL, 16);
    if (errno != 0)
        return FALSE;

    /* Yggdrasil prefix: 0200::/7 -> first hextet 0x0200–0x03FF */
    return (val >= 0x0200 && val <= 0x03FF);
}

/*
 * Return the local Yggdrasil IPv6 address for the given connected fd.
 * Uses the actual socket endpoint and requires a Yggdrasil address.
 * Returns a g_malloc'd string the caller must g_free(), or NULL.
 */
static gchar *
get_local_yggdrasil_ip(int fd)
{
    struct sockaddr_storage local_addr;
    socklen_t addr_len = sizeof(local_addr);

    if (fd >= 0 &&
        getsockname(fd, (struct sockaddr *)&local_addr, &addr_len) == 0 &&
        local_addr.ss_family == AF_INET6) {
        char buf[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&local_addr;
        inet_ntop(AF_INET6, &addr6->sin6_addr, buf, sizeof(buf));
        char *pct = strchr(buf, '%');
        if (pct) *pct = '\0';
        if (is_yggdrasil_addr(buf))
            return g_strdup(buf);
    }

    return NULL;
}

void
bonjour_jabber_process_packet(PurpleBuddy *pb, xmlnode *packet)
{
    BonjourBuddy *bb;

    if (!packet || !pb)
        return;

    bb = purple_buddy_get_protocol_data(pb);
    if (bb && bb->conversation)
        bb->conversation->last_activity = time(NULL);

    if (barev_images_receive(pb, packet))
        return;

    if (purple_strequal(packet->name, "message")) {
        _jabber_parse_and_write_message_to_ui(packet, pb);
        return;
    }

    if (purple_strequal(packet->name, "presence")) {
        _bonjour_handle_presence(pb, packet);
        return;
    }

    if (purple_strequal(packet->name, "iq")) {
        const char *type = xmlnode_get_attrib(packet, "type");
        const char *id   = xmlnode_get_attrib(packet, "id");

        /* Ping request? (has <ping xmlns='urn:yggb:ping'/>) */
        if (bb && bb->conversation) {
            if (bonjour_jabber_handle_ping(packet, bb->conversation))
                return;
        }

        /* Ping response? (empty <iq type='result' id='ping-...'/>) */
        if (type && !g_ascii_strcasecmp(type, "result") &&
            id && g_str_has_prefix(id, "ping-")) {
            if (bb && bb->conversation)
                bonjour_jabber_handle_ping_response(packet, bb->conversation);
            return; /* don't fall into xep_iq_parse */
        }

        /* vCard avatars? */
        if (barev_handle_vcard_iq(packet, pb))
            return;

        /* Jingle voice/video? */
        {
            xmlnode *jingle_node = xmlnode_get_child_with_namespace(
                    packet, "jingle", "urn:xmpp:jingle:1");
            if (jingle_node && bb && bb->conversation) {
                barev_jingle_parse(bb->conversation,
                        purple_buddy_get_name(pb),
                        type, id, jingle_node);
                return;
            }
        }

        /* Only hand to file-transfer parser if IQ actually has children */
        if (packet->child != NULL) {
            xep_iq_parse(packet, pb);
        }

        return;
    }

    purple_debug_warning("barev", "Unknown packet: %s\n",
                         packet->name ? packet->name : "(null)");
}

static void
_bonjour_handle_presence(PurpleBuddy *pb, xmlnode *presence_node)
{
    PurpleAccount *account;
    BonjourBuddy *bb;
    const char *name;
    const char *type;
    xmlnode *child;
    char *show_text = NULL;
    char *status_text = NULL;
    const char *status_id;

    g_return_if_fail(pb != NULL);
    g_return_if_fail(presence_node != NULL);

    account = purple_buddy_get_account(pb);
    bb = purple_buddy_get_protocol_data(pb);
    name = purple_buddy_get_name(pb);

    if (!account || !name)
        return;

    /* unavailable => offline */
    type = xmlnode_get_attrib(presence_node, "type");
    if (type && !g_ascii_strcasecmp(type, "unavailable")) {
        bonjour_buddy_cancel_deferred_offline(bb);
        safe_set_buddy_status(account, name, BONJOUR_STATUS_ID_OFFLINE, NULL, NULL);
        purple_prpl_got_user_idle(account, name, FALSE, 0);
        return;
    }

    child = xmlnode_get_child(presence_node, "show");
    if (child)
        show_text = xmlnode_get_data(child);

    child = xmlnode_get_child(presence_node, "status");
    if (child)
        status_text = xmlnode_get_data(child);

    if (show_text &&
        !g_ascii_strcasecmp(show_text, "away")) {
        status_id = BONJOUR_STATUS_ID_AWAY;
    } else if (show_text &&
               !g_ascii_strcasecmp(show_text, "dnd")) {
        status_id = BONJOUR_STATUS_ID_BUSY;
    } else {
        status_id = BONJOUR_STATUS_ID_AVAILABLE;
    }

    if (bb) {
        bonjour_buddy_cancel_deferred_offline(bb);
        g_free(bb->status);
        bb->status = show_text ? g_strdup(show_text) : NULL;
        g_free(bb->msg);
        bb->msg = status_text ? g_strdup(status_text) : NULL;
    }

    {
        PurpleStatusType *stype = purple_account_get_status_type(account, status_id);
        if (!stype) {
            purple_debug_warning("barev",
                "Presence: %s: unknown status id '%s', falling back to 'available'\n",
                name, status_id);
            status_id = BONJOUR_STATUS_ID_AVAILABLE;
        }
    }

    if (status_text) {
        safe_set_buddy_status(account, name, status_id, "message", status_text);
    } else {
        safe_set_buddy_status(account, name, status_id, NULL, NULL);
    }

    purple_prpl_got_user_idle(account, name, FALSE, 0);

    /* --- Barev: XEP-0153 avatar update in presence --- */
    if (bb) {
        xmlnode *x = xmlnode_get_child_with_namespace(presence_node, "x", BAREV_VCARD_UPDATE_NS);
        if (x && xmlnode_get_child(x, "photo")) {
            xmlnode *p = xmlnode_get_child(x, "photo");
            gchar *new_hash = p ? xmlnode_get_data(p) : NULL;

            /* Does libpurple think we already have an icon for this buddy? */
            gboolean have_icon = (purple_buddy_get_icon(pb) != NULL);

            purple_debug_info("barev",
                "Barev: presence avatar update for %s: hash='%s' old='%s' have_icon=%d\n",
                name,
                new_hash ? new_hash : "(none)",
                bb->phsh ? bb->phsh : "(none)",
                have_icon ? 1 : 0);

            if (!new_hash || !*new_hash) {
                if (new_hash) g_free(new_hash);
                barev_clear_buddy_icon(pb, bb);
            } else {
                if (barev_avatar_hash_valid(new_hash)) {
                    gboolean cached;
                    g_free(bb->phsh); bb->phsh = g_ascii_strdown(new_hash, -1);
                    cached = barev_avatar_cache_matches(pb, new_hash);
                    /* Loading an icon can invoke UI callbacks that disconnect. */
                    bb = purple_buddy_get_protocol_data(pb);
                    if (bb && bb->phsh && !g_ascii_strcasecmp(bb->phsh, new_hash)) {
                        if (cached) {
                            barev_avatar_request_clear(&bb->avatar_request);
                            purple_debug_info("barev", "Avatar cache: advertised SHA-1 matches cached bytes.\n");
                        } else bonjour_jabber_request_vcard(pb, FALSE);
                    }
                } else purple_debug_warning("barev", "Avatar announcement ignored: invalid SHA-1.\n");

                g_free(new_hash);
            }
        }
    }

    purple_debug_info("barev",
                      "Presence: %s show='%s' status='%s'\n",
                      name,
                      show_text ? show_text : "(none)",
                      status_text ? status_text : "(none)");

    g_free(show_text);
    g_free(status_text);
}

static gboolean
bonjour_jabber_frame_timeout(gpointer data)
{
  BonjourJabberConversation *bconv = data;
  time_t deadline = bconv->recv_stream_start && bconv->sent_stream_start == FULLY_SENT ?
      120 : PENDING_STREAM_TIMEOUT;
  if (bconv->closing || bconv->close_timeout) {
    bconv->frame_timer = 0;
    return FALSE;
  }
  if (g_get_monotonic_time()-bconv->frame_started < deadline*G_USEC_PER_SEC) return TRUE;
  bconv->frame_timer = 0;
  bonjour_jabber_close_conversation(bconv);
  return FALSE;
}

static BonjourJabberConversation *
bonjour_jabber_conv_new(PurpleBuddy *pb, PurpleAccount *account, const char *ip) {

  if (!bonjour_peer_allowed(account, ip)) return NULL;
  BonjourJabberConversation *bconv = g_new0(BonjourJabberConversation, 1);
  barev_conversations = g_slist_prepend(barev_conversations, bconv);
  bconv->socket = -1;
  bconv->tx_buf = purple_circ_buffer_new(512);
  bconv->tx_handler = 0;
  bconv->rx_handler = 0;
  bconv->pb = pb;
  bconv->buddy_name = pb ? bonjour_buddy_identity(pb) : NULL;
  bconv->account = account;
  bconv->ip = g_strdup(ip);

  bconv->remote_port = -1;

  /* Initialize ping fields */
  bconv->ping_timer = 0;
  bconv->ping_response_timer = 0;
  bconv->last_ping_id = NULL;
  bconv->last_activity = time(NULL);
  bconv->frame_started = g_get_monotonic_time();
  bconv->frame_timer = purple_timeout_add_seconds(1, bonjour_jabber_frame_timeout, bconv);
  bconv->ping_failures = 0;

  bonjour_parser_setup(bconv);

  return bconv;
}

static const char *
_font_size_ichat_to_purple(int size)
{
  if (size > 24) {
    return "7";
  } else if (size >= 21) {
    return "6";
  } else if (size >= 17) {
    return "5";
  } else if (size >= 14) {
    return "4";
  } else if (size >= 12) {
    return "3";
  } else if (size >= 10) {
    return "2";
  }

  return "1";
}

static gchar *
get_xmlnode_contents(xmlnode *node)
{
  gchar *contents;

  contents = xmlnode_to_str(node, NULL);

  /* we just want the stuff inside <font></font>
   * There isn't stuff exposed in xmlnode.c to do this more cleanly. */

  if (contents) {
    char *bodystart = strchr(contents, '>');
    char *bodyend = bodystart ? strrchr(bodystart, '<') : NULL;
    if (bodystart && bodyend && (bodystart + 1) != bodyend) {
      *bodyend = '\0';
      memmove(contents, bodystart + 1, (bodyend - bodystart));
    }
  }

  return contents;
}


static void
_jabber_parse_and_write_message_to_ui(xmlnode *message_node, PurpleBuddy *pb)
{
     if (!pb) {
        purple_debug_error("barev", "message_to_ui: pb is NULL\n");
        return;
    }

    PurpleAccount *acc = purple_buddy_get_account(pb);
    if (!acc) return;

    PurpleConnection *gc = purple_account_get_connection(acc);
    if (!gc) return;

  xmlnode *body_node, *html_node, *events_node;
  //PurpleConnection *gc = purple_account_get_connection(purple_buddy_get_account(pb));
  gchar *body = NULL;

  body_node = xmlnode_get_child(message_node, "body");
  html_node = xmlnode_get_child(message_node, "html");

    /* XEP-0085 chat states */
  xmlnode *cs = xmlnode_get_child_with_namespace(message_node, "composing",
                     "http://jabber.org/protocol/chatstates");
  if (cs) {
      PurpleConnection *gc = purple_account_get_connection(purple_buddy_get_account(pb));
      serv_got_typing(gc, purple_buddy_get_name(pb), BAREV_CHATSTATE_TIMEOUT_SECONDS, PURPLE_TYPING);
      return;
  }

  cs = xmlnode_get_child_with_namespace(message_node, "active",
                     "http://jabber.org/protocol/chatstates");
  if (cs) {
      PurpleConnection *gc = purple_account_get_connection(purple_buddy_get_account(pb));
      serv_got_typing_stopped(gc, purple_buddy_get_name(pb));
      return;
  }


  if (body_node == NULL && html_node == NULL) {
    purple_debug_error("barev", "No body or html node found, discarding message.\n");
    return;
  }

  events_node = xmlnode_get_child_with_namespace(message_node, "x", "jabber:x:event");
  if (events_node != NULL) {
#if 0
    if (xmlnode_get_child(events_node, "composing") != NULL)
      composing_event = TRUE;
#endif
    if (xmlnode_get_child(events_node, "id") != NULL) {
      /* The user is just typing */
      /* TODO: Deal with typing notification */
      return;
    }
  }

  if (html_node != NULL) {
    xmlnode *html_body_node;

    html_body_node = xmlnode_get_child(html_node, "body");
    if (html_body_node != NULL) {
      xmlnode *html_body_font_node;

      html_body_font_node = xmlnode_get_child(html_body_node, "font");
      /* Types of messages sent by iChat */
      if (html_body_font_node != NULL) {
        gchar *html_body;
        const char *font_face, *font_size,
          *ichat_balloon_color, *ichat_text_color;

        font_face = xmlnode_get_attrib(html_body_font_node, "face");
        /* The absolute iChat font sizes should be converted to 1..7 range */
        font_size = xmlnode_get_attrib(html_body_font_node, "ABSZ");
        if (font_size != NULL)
          font_size = _font_size_ichat_to_purple(atoi(font_size));
        /*font_color = xmlnode_get_attrib(html_body_font_node, "color");*/
        ichat_balloon_color = xmlnode_get_attrib(html_body_node, "ichatballooncolor");
        ichat_text_color = xmlnode_get_attrib(html_body_node, "ichattextcolor");

        html_body = get_xmlnode_contents(html_body_font_node);

        if (html_body == NULL)
          /* This is the kind of formatted messages that Purple creates */
          html_body = xmlnode_to_str(html_body_font_node, NULL);

        if (html_body != NULL) {
          GString *str = g_string_new("<font");

          if (font_face)
            g_string_append_printf(str, " face='%s'", font_face);
          if (font_size)
            g_string_append_printf(str, " size='%s'", font_size);
          if (ichat_text_color)
            g_string_append_printf(str, " color='%s'", ichat_text_color);
          if (ichat_balloon_color)
            g_string_append_printf(str, " back='%s'", ichat_balloon_color);
          g_string_append_printf(str, ">%s</font>", html_body);

          body = g_string_free(str, FALSE);

          g_free(html_body);
        }
      }
    }
  }

  /* Compose the message */
  if (body == NULL && body_node != NULL)
    body = xmlnode_get_data(body_node);

  if (body == NULL) {
    purple_debug_error("barev", "No html body or regular body found.\n");
    return;
  }

  /* Send the message to the UI */
  {
    char *safe = BarevImageUI_Strip(body);
    g_free(body); body = safe;
  }
  serv_got_im(gc, purple_buddy_get_name(pb), body, 0, time(NULL));

  g_free(body);
}

static gboolean
bonjour_peer_allowed(PurpleAccount *account, const char *ip)
{
  struct in6_addr actual, expected;
  GSList *buddies, *it;
  gboolean known = FALSE;
  unsigned connections = 0;
  if (!ip || inet_pton(AF_INET6, ip, &actual) != 1 ||
      g_slist_length(barev_conversations) >= 64) return FALSE;
  buddies = purple_find_buddies(account, NULL);
  for (it = buddies; it; it = it->next) {
    char *identity = bonjour_buddy_identity(it->data);
    if (identity && purple_buddy_get_protocol_data(it->data) &&
        inet_pton(AF_INET6, strchr(identity, '@')+1, &expected) == 1 && !memcmp(&actual, &expected, 16))
      known = TRUE;
    g_free(identity);
  }
  g_slist_free(buddies);
  for (it = barev_conversations; it; it = it->next) {
    BonjourJabberConversation *conversation = it->data;
    if (conversation->account == account && conversation->ip &&
        inet_pton(AF_INET6, conversation->ip, &expected) == 1 && !memcmp(&actual, &expected, 16))
      ++connections;
  }
  return known && connections < 4;
}

static void
_send_data_write_cb(gpointer data, gint source, PurpleInputCondition cond)
{
  BonjourJabberConversation *bconv = data;
  PurpleBuddy *pb;
  BonjourBuddy *bb;
  int ret, writelen;

  if (!bconv || bconv->closing || bconv->close_timeout != 0)
    return;

  pb = bconv->pb;
  bb = pb ? purple_buddy_get_protocol_data(pb) : NULL;

  if (!pb || !bb || bb->conversation != bconv || source != bconv->socket) {
    purple_debug_warning("barev",
                         "_send_data_write_cb: stale conversation callback; removing handler\n");
    if (bconv->tx_handler != 0) {
      guint handler = bconv->tx_handler;
      bconv->tx_handler = 0;
      purple_input_remove(handler);
    }
    return;
  }

  writelen = purple_circ_buffer_get_max_read(bconv->tx_buf);

  if (writelen == 0) {
    purple_input_remove(bconv->tx_handler);
    bconv->tx_handler = 0;
    return;
  }

  ret = send(bconv->socket, bconv->tx_buf->outptr, writelen, MSG_NOSIGNAL);

  if (ret < 0 && barev_sock_transient())
    return;
  else if (ret <= 0) {
    PurpleConversation *conv = NULL;
    PurpleAccount *account = NULL;
    const char *error = g_strerror(errno);

    purple_debug_error("barev", "Error sending message to buddy %s error: %s\n",
           purple_buddy_get_name(pb), error ? error : "(null)");

    account = purple_buddy_get_account(pb);

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
    if (conv != NULL)
      purple_conversation_write(conv, NULL,
          _("Unable to send message."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));

    async_bonjour_jabber_close_conversation(bconv);
    return;
  }

  purple_circ_buffer_mark_read(bconv->tx_buf, ret);
}

static gint _send_data(PurpleBuddy *pb, char *message)
{
  gint ret;
  int len;
  BonjourBuddy *bb;
  BonjourJabberConversation *bconv;

  if (!pb || !message)
    return -1;

  len = strlen(message);

  bb = purple_buddy_get_protocol_data(pb);
  if (!bb || !bb->conversation) {
    purple_debug_warning("barev", "_send_data: no conversation for buddy %s\n",
                         pb ? purple_buddy_get_name(pb) : "(null)");
    return -1;
  }

  bconv = bb->conversation;

  if (bconv->closing || bconv->close_timeout != 0)
    return -1;

  /* If we're not ready to actually send, append it to the buffer */
  if (bconv->tx_handler != 0
      || bconv->connect_data != NULL
      || bconv->sent_stream_start != FULLY_SENT
      || !bconv->recv_stream_start
      || purple_circ_buffer_get_max_read(bconv->tx_buf) > 0) {
    ret = -1;
    errno = EAGAIN;
  } else {
    ret = send(bconv->socket, message, len, MSG_NOSIGNAL);
  }

  if (ret == -1 && barev_sock_transient())
    ret = 0;
  else if (ret <= 0) {
    PurpleConversation *conv;
    PurpleAccount *account;
    const char *error = g_strerror(errno);

    purple_debug_error("barev", "Error sending message to buddy %s error: %s\n",
           purple_buddy_get_name(pb), error ? error : "(null)");

    account = purple_buddy_get_account(pb);

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
    if (conv != NULL)
      purple_conversation_write(conv, NULL,
          _("Unable to send message."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));

    async_bonjour_jabber_close_conversation(bconv);
    return -1;
  }

  if (ret < len) {
    /* Don't interfere with the stream starting */
    if (bconv->sent_stream_start == FULLY_SENT && bconv->recv_stream_start && bconv->tx_handler == 0)
      bconv->tx_handler = purple_input_add(bconv->socket, PURPLE_INPUT_WRITE,
        _send_data_write_cb, bconv);
    purple_circ_buffer_append(bconv->tx_buf, message + ret, len - ret);
  }

  return ret;
}

static void
barev_send_current_presence_to_buddy(PurpleBuddy *pb)
{
    PurpleAccount *account;
    PurpleStatus *status;
    PurpleStatusType *stype;
    const char *id;
    const char *message;
    gchar *stripped;
    const char *show = NULL;
    gboolean offline = FALSE;

    if (!pb) return;

    account = purple_buddy_get_account(pb);
    if (!account) return;

    status = purple_account_get_active_status(account);
    if (!status) return;

    stype = purple_status_get_type(status);
    id = stype ? purple_status_type_get_id(stype) : NULL;

    purple_debug_info("barev",
        "barev_send_current_presence_to_buddy: %s account_status=%s\n",
        purple_buddy_get_name(pb), id ? id : "(null)");

    if (id && g_strcmp0(id, BONJOUR_STATUS_ID_OFFLINE) == 0) {
        offline = TRUE;
    } else if (id && g_strcmp0(id, BONJOUR_STATUS_ID_AWAY) == 0) {
        show = "away";
    } else if (id && g_strcmp0(id, BONJOUR_STATUS_ID_BUSY) == 0) {
        show = "dnd";
    } else {
        show = NULL;
    }

    message = purple_status_get_attr_string(status, "message");
    if (!message) message = "";
    stripped = purple_markup_strip_html(message);

    bonjour_jabber_send_presence(pb, show, stripped, offline);

    g_free(stripped);
}

int
bonjour_jabber_send_presence(PurpleBuddy *pb,
                             const char *show,
                             const char *status_msg,
                             gboolean offline)
{
    BonjourBuddy *bb;
    BonjourJabberConversation *bconv;
    PurpleAccount *account;
    const char *from;
    xmlnode *presence_node, *child;
    char *xml;
    int ret;

    if (pb == NULL)
        return -1;

    bb = purple_buddy_get_protocol_data(pb);
    if (!bb) {
        purple_debug_info("barev", "send_presence: buddy has no protocol data\n");
        return -1;
    }

    bconv = bb->conversation;
    if (!bconv || bconv->socket < 0) {
        purple_debug_info("barev",
                          "send_presence: %s has no active conversation\n",
                          purple_buddy_get_name(pb));
        return -1;
    }

    presence_node = xmlnode_new("presence");

    if (offline) {
        xmlnode_set_attrib(presence_node, "type", "unavailable");
    }

    account = purple_buddy_get_account(pb);
    from = bonjour_jabber_get_local_jid(bconv);
    if (!from)
        from = "";
    if (*from)
        xmlnode_set_attrib(presence_node, "from", from);

    if (!offline && show && *show) {
        child = xmlnode_new_child(presence_node, "show");
        xmlnode_insert_data(child, show, strlen(show));
    }

    if (status_msg && *status_msg) {
        child = xmlnode_new_child(presence_node, "status");
        xmlnode_insert_data(child, status_msg, strlen(status_msg));
    }

    /* Barev: XEP-0153 avatar hash advertisement */
    barev_presence_add_avatar_update(presence_node, account);

    xml = bonjour_jabber_packet_xml(pb, presence_node);
    xmlnode_free(presence_node);

    ret = (_send_data(pb, xml) >= 0);

    g_free(xml);

    return ret;
}

void
bonjour_jabber_stream_ended(BonjourJabberConversation *bconv)
{
  purple_debug_info("barev", "Received conversation close notification from %s\n",
    bconv->pb ? purple_buddy_get_name(bconv->pb) :
    (bconv->buddy_name ? bconv->buddy_name : "(unknown)"));

  /* The destructor clears the back-pointer only when this is still the
   * buddy's current conversation.  A stale EOF must not erase a newer one. */
  bonjour_jabber_close_conversation(bconv);
}

static void
_client_socket_handler(gpointer data, gint socket, PurpleInputCondition condition)
{
  BonjourJabberConversation *bconv = data;
  gssize len;
  static char message[4096];

  if (!bconv || bconv->closing || bconv->close_timeout != 0)
    return;

  if (socket != bconv->socket) {
    purple_debug_warning("barev",
                         "Ignoring stale read callback for socket %d (current %d)\n",
                         socket, bconv->socket);
    return;
  }

  /* Read the data from the socket */
  if ((len = recv(socket, message, sizeof(message) - 1, 0)) < 0) {
    /* There have been an error reading from the socket */
    if (len != -1 || !barev_sock_transient()) {
      const char *err = g_strerror(errno);

      purple_debug_warning("barev",
          "receive of %" G_GSSIZE_FORMAT " error: %s\n",
          len, err ? err : "(null)");

      bonjour_jabber_close_conversation(bconv);

      /* I guess we really don't need to notify the user.
       * If they try to send another message it'll reconnect */
    }
    return;
  } else if (len == 0) { /* The other end has closed the socket */
    const gchar *name = NULL;

    /* Try multiple sources for the name */
    if (bconv->pb) {
      name = purple_buddy_get_name(bconv->pb);
    }
    if (!name && bconv->buddy_name) {
      name = bconv->buddy_name;
    }
    if (!name) {
      name = "(unknown)";
    }

    purple_debug_warning("barev", "Connection closed (without stream end) by %s.\n", name);
    bonjour_jabber_stream_ended(bconv);
    return;
  }

  message[len] = '\0';

  purple_debug_info("barev", "Receive: -%s- %" G_GSSIZE_FORMAT " bytes\n", message, len);
  bonjour_parser_process(bconv, message, len);
}



struct _stream_start_data {
  char *msg;
};


static void
_start_stream(gpointer data, gint source, PurpleInputCondition condition)
{
  BonjourJabberConversation *bconv = data;
  struct _stream_start_data *ss;
  int len, ret;

  if (!bconv || bconv->closing || bconv->close_timeout != 0)
    return;

  if (source != bconv->socket || bconv->stream_data == NULL) {
    purple_debug_warning("barev", "Ignoring stale stream-start callback\n");
    return;
  }

  ss = bconv->stream_data;

  len = strlen(ss->msg);

  /* Start Stream */
  ret = send(source, ss->msg, len, MSG_NOSIGNAL);

  if (ret == -1 && barev_sock_transient())
    return;
  else if (ret <= 0) {
    const char *err = g_strerror(errno);
    PurpleConversation *conv;
    const char *bname = bconv->buddy_name;

    if(bconv->pb)
      bname = purple_buddy_get_name(bconv->pb);

    purple_debug_error("barev", "Error starting stream with buddy %s at %s error: %s\n",
           bname ? bname : "(unknown)", bconv->ip, err ? err : "(null)");

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bname, bconv->account);
    if (conv != NULL)
      purple_conversation_write(conv, NULL,
          _("Unable to send the message, the conversation couldn't be started."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));

    bonjour_jabber_close_conversation(bconv);
    return;
  }

  /* This is EXTREMELY unlikely to happen */
  if (ret < len) {
    char *tmp = g_strdup(ss->msg + ret);
    g_free(ss->msg);
    ss->msg = tmp;
    return;
  }

  g_free(ss->msg);
  g_free(ss);
  bconv->stream_data = NULL;

  /* Stream started; process the send buffer if there is one */
  purple_input_remove(bconv->tx_handler);
  bconv->tx_handler = 0;
  bconv->sent_stream_start = FULLY_SENT;

  bonjour_jabber_stream_started(bconv);
}

static gboolean bonjour_jabber_send_stream_init(BonjourJabberConversation *bconv, int client_socket)
{
  int ret, len;
  char *stream_start;
  const char *bname = bconv->buddy_name;

  if (!bname || !bonjour_validate_endpoints(bconv, bname)) return FALSE;
  {
    char *from = g_markup_escape_text(bonjour_jabber_get_local_jid(bconv), -1);
    char *to = g_markup_escape_text(bname, -1);
    stream_start = g_strdup_printf(DOCTYPE, from, to);
    g_free(from); g_free(to);
  }
  len = strlen(stream_start);

  bconv->sent_stream_start = PARTIALLY_SENT;

  /* Start the stream */
  ret = send(client_socket, stream_start, len, MSG_NOSIGNAL);

  if (ret == -1 && barev_sock_transient())
    ret = 0;
  else if (ret <= 0) {
    const char *err = g_strerror(errno);

    purple_debug_error("barev", "Error starting stream with buddy %s at %s error: %s\n",
           (*bname) ? bname : "(unknown)", bconv->ip, err ? err : "(null)");

    if (bconv->pb) {
      PurpleConversation *conv;
      conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bname, bconv->account);
      if (conv != NULL)
        purple_conversation_write(conv, NULL,
            _("Unable to send the message, the conversation couldn't be started."),
            PURPLE_MESSAGE_SYSTEM, time(NULL));
    }

    g_free(stream_start);

    return FALSE;
  }

  /* This is unlikely to happen */
  if (ret < len) {
    struct _stream_start_data *ss = g_new(struct _stream_start_data, 1);
    ss->msg = g_strdup(stream_start + ret);
    bconv->stream_data = ss;
    /* Finish sending the stream start */
    bconv->tx_handler = purple_input_add(client_socket,
      PURPLE_INPUT_WRITE, _start_stream, bconv);
  } else
    bconv->sent_stream_start = FULLY_SENT;

  g_free(stream_start);

  return TRUE;
}

/* This gets called when we've successfully sent our <stream:stream />
 * AND when we've received a <stream:stream /> */
void bonjour_jabber_stream_started(BonjourJabberConversation *bconv) {

  if (!bconv || bconv->closing || bconv->close_timeout != 0)
    return;

  purple_debug_info("barev",
      "stream_started: bconv=%p sent=%d recv=%d pb=%s closing=%d close_timeout=%u\n",
      bconv, bconv->sent_stream_start, bconv->recv_stream_start,
      bconv->pb ? purple_buddy_get_name(bconv->pb) : "(null)",
      bconv->closing, bconv->close_timeout);

  if (bconv->sent_stream_start == NOT_SENT &&
      !bonjour_jabber_send_stream_init(bconv, bconv->socket)) {
    const char *err = g_strerror(errno);
    const char *bname = bconv->buddy_name;

    if (bconv->pb)
      bname = purple_buddy_get_name(bconv->pb);

    purple_debug_error("barev",
                       "Error starting stream with buddy %s at %s error: %s\n",
                       bname ? bname : "(unknown)", bconv->ip,
                       err ? err : "(null)");

    if (bconv->pb) {
      PurpleConversation *conv;
      conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
                                                   bname, bconv->account);
      if (conv != NULL)
        purple_conversation_write(conv, NULL,
          _("Unable to send the message, the conversation couldn't be started."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));
    }

    /* We don't want to recieve anything else */
    if (bconv->rx_handler != 0) {
      guint handler = bconv->rx_handler;
      bconv->rx_handler = 0;
      purple_input_remove(handler);
    }

    if (bconv->socket >= 0) {
      close(bconv->socket);
      bconv->socket = -1;
    }

    /* This must be asynchronous because it destroys the parser and we
     * may be in the middle of parsing.
     */
    async_bonjour_jabber_close_conversation(bconv);
    return;
  }

  /* If the stream has been completely started and we know who we're talking
   * to, we can start doing stuff.
   */
  if (bconv->sent_stream_start == FULLY_SENT &&
      bconv->recv_stream_start &&
      bconv->pb) {

    PurpleBuddy *pb = bconv->pb;
    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);

    purple_debug_info("barev",
        "stream_started: FULLY_SENT block firing for %s (ping_timer=%u)\n",
        purple_buddy_get_name(pb), bconv->ping_timer);

    if (bb) {
      barev_refresh_account_jid(bconv);
      bonjour_buddy_cancel_deferred_offline(bb);
      bonjour_jabber_start_ping(bconv);
#ifdef USE_VV
      purple_prpl_got_media_caps(bconv->account,
                                 purple_buddy_get_name(pb));
#endif
    }

    /* and now the original buffered-send code: */
    if (purple_circ_buffer_get_max_read(bconv->tx_buf) > 0) {
      /* Watch for when we can write the buffered messages */
      bconv->tx_handler = purple_input_add(bconv->socket,
                                           PURPLE_INPUT_WRITE,
                                           _send_data_write_cb, bconv);
      /* We can probably write the data right now. */
      _send_data_write_cb(bconv, bconv->socket, PURPLE_INPUT_WRITE);
    }

    barev_send_current_presence_to_buddy(pb);

    /* Drain queued messages now that the stream is fully established. */
    if (bb && bb->pending_messages) {
      BonjourData *bd = bconv->account && bconv->account->gc
                        ? bconv->account->gc->proto_data : NULL;
      BonjourJabber *jdata = bd ? bd->jabber_data : NULL;
      const char *name = purple_buddy_get_name(pb);
      if (jdata && name) {
        purple_debug_info("barev",
            "stream_started: draining %u queued messages for %s\n",
            g_slist_length(bb->pending_messages), name);
        while (bb->pending_messages) {
          gchar *queued = bb->pending_messages->data;
          if (bonjour_jabber_send_message(jdata, name, queued) <= 0)
            break;
          bb->pending_messages = g_slist_delete_link(bb->pending_messages,
                                                     bb->pending_messages);
          g_free(queued);
        }
      }
    }

  } else if (bconv->sent_stream_start == FULLY_SENT &&
             bconv->recv_stream_start &&
             bconv->pb == NULL) {

    /* Peer is not in the whitelist (no buddy matched by JID or IP).
     * Send a not-authorized stream error and close immediately. */
    purple_debug_warning("barev",
        "stream_started: rejecting unknown peer %s (not in contact list)\n",
        bconv->buddy_name ? bconv->buddy_name : bconv->ip ? bconv->ip : "(unknown)");

    static const char reject_xml[] =
        "<stream:error>"
        "<not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
        "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>"
        "Not in contact list"
        "</text>"
        "</stream:error>"
        "</stream:stream>";

    if (bconv->socket >= 0)
      send(bconv->socket, reject_xml, sizeof(reject_xml) - 1, MSG_NOSIGNAL);

    async_bonjour_jabber_close_conversation(bconv);
  }
}



#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

static void
_server_socket_handler(gpointer data, int server_socket, PurpleInputCondition condition)
{
  BonjourJabber *jdata = data;
  common_sockaddr_t their_addr;
  socklen_t sin_size = sizeof(common_sockaddr_t);
  int client_socket;
  char addrstr[NI_MAXHOST]; /* NI_MAXHOST is 1025, plenty of space */
  const char *address_text = NULL;

  if (condition != PURPLE_INPUT_READ)
    return;

  memset(&their_addr, 0, sin_size);

  if ((client_socket = accept(server_socket, &their_addr.sa, &sin_size)) == -1) {
    purple_debug_error("barev", "accept() failed: %s\n", g_strerror(errno));
    return;
  }

  _purple_network_set_common_socket_flags(client_socket);

  /* Use getnameinfo to get the IP address - it handles IPv6 scope IDs automatically */
  if (getnameinfo(&their_addr.sa, sin_size,
                  addrstr, sizeof(addrstr),
                  NULL, 0, NI_NUMERICHOST) != 0) {
    purple_debug_error("barev", "getnameinfo failed: %s\n", g_strerror(errno));
    close(client_socket);
    return;
  }

  address_text = addrstr;
  purple_debug_info("barev", "Received incoming connection from %s.\n", address_text);



  /* Check if we got a valid address */
  if (!address_text || strlen(address_text) == 0) {
    purple_debug_error("barev", "Failed to extract IP address\n");
    close(client_socket);
    return;
  }

  purple_debug_info("barev", "Received incoming connection from %s.\n", address_text);

  /* Create conversation for this connection */
  BonjourJabberConversation *bconv = bonjour_jabber_conv_new(NULL, jdata->account, address_text);
  if (!bconv) {
    purple_debug_warning("barev", "Rejecting unknown or over-limit peer %s\n", address_text);
    close(client_socket);
    return;
  }
  bconv->incoming = TRUE;
  bconv->socket = client_socket;

  if (!bonjour_validate_endpoints(bconv, NULL)) {
    bonjour_jabber_close_conversation(bconv);
    return;
  }

  bconv->rx_handler = purple_input_add(client_socket, PURPLE_INPUT_READ, _client_socket_handler, bconv);
  purple_debug_info("barev",
                    "Accepted incoming conversation %p fd=%d from %s\n",
                    bconv, client_socket, address_text);

  /* Add to pending conversations list */
  jdata->pending_conversations = g_slist_prepend(jdata->pending_conversations, bconv);
}

static int
start_serversocket_listening(int port, int socket, struct sockaddr *addr, size_t addr_size, gboolean ip6, gboolean allow_port_fallback)
{
  int ret_port = port;

  purple_debug_info("barev", "Attempting to bind IPv%d socket to port %d.\n", ip6 ? 6 : 4, port);

  /* Try to use the specified port - if it isn't available, use a random port */
  if (bind(socket, addr, addr_size) != 0) {

    purple_debug_info("barev", "Unable to bind to specified "
        "port %i: %s\n", port, g_strerror(errno));

    if (!allow_port_fallback) {
      purple_debug_warning("barev", "Not attempting random port assignment.\n");
      return -1;
    }
#ifdef PF_INET6
    if (ip6)
      ((struct sockaddr_in6 *) addr)->sin6_port = 0;
    else
#endif
    ((struct sockaddr_in *) addr)->sin_port = 0;

    if (bind(socket, addr, addr_size) != 0) {
      purple_debug_error("barev", "Unable to bind IPv%d socket to port: %s\n", ip6 ? 6 : 4, g_strerror(errno));
      return -1;
    }
    ret_port = purple_network_get_port_from_fd(socket);
  }

  purple_debug_info("barev", "Bound IPv%d socket to port %d.\n", ip6 ? 6 : 4, ret_port);

  /* Attempt to listen on the bound socket */
  if (listen(socket, 10) != 0) {
    purple_debug_error("barev", "Unable to listen on IPv%d socket: %s\n", ip6 ? 6 : 4, g_strerror(errno));
    return -1;
  }

#if 0
  /* TODO: Why isn't this being used? */
  data->socket = purple_network_listen(jdata->port, SOCK_STREAM);

  if (jdata->socket == -1)
  {
    purple_debug_error("barev", "No se ha podido crear el socket\n");
  }
#endif

  return ret_port;
}

gint
bonjour_jabber_start(BonjourJabber *jdata)
{
  int ipv6_port = -1, ipv4_port = -1;

  /* Open a listening socket for incoming conversations */
#ifdef PF_INET6
  jdata->socket6 = socket(PF_INET6, SOCK_STREAM, 0);
#endif
  jdata->socket = socket(PF_INET, SOCK_STREAM, 0);
  if (jdata->socket == -1 && jdata->socket6 == -1) {
    purple_debug_error("barev", "Unable to create socket: %s",
        g_strerror(errno));
    return -1;
  }

#ifdef PF_INET6
  if (jdata->socket6 != -1) {
    struct sockaddr_in6 addr6;
#ifdef IPV6_V6ONLY
    int on = 1;
    if (setsockopt(jdata->socket6, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0) {
      purple_debug_error("barev", "couldn't force IPv6\n");
      close(jdata->socket6);
      jdata->socket6 = -1;
      if (jdata->socket != -1) {
        close(jdata->socket);
        jdata->socket = -1;
      }
      return -1;
    }
#endif
          memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(jdata->port);
          addr6.sin6_addr = in6addr_any;
    ipv6_port = start_serversocket_listening(jdata->port, jdata->socket6, (struct sockaddr *) &addr6, sizeof(addr6), TRUE, TRUE);
    /* Open a watcher in the socket we have just opened */
    if (ipv6_port > 0) {
      jdata->watcher_id6 = purple_input_add(jdata->socket6, PURPLE_INPUT_READ, _server_socket_handler, jdata);
      jdata->port = ipv6_port;
    } else {
      purple_debug_error("barev", "Failed to start listening on IPv6 socket.\n");
      close(jdata->socket6);
      jdata->socket6 = -1;
    }
  }
#endif
  if (jdata->socket != -1) {
    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(jdata->port);
    ipv4_port = start_serversocket_listening(jdata->port, jdata->socket, (struct sockaddr *) &addr4, sizeof(addr4), FALSE, TRUE);
    /* Open a watcher in the socket we have just opened */
    if (ipv4_port > 0) {
      jdata->watcher_id = purple_input_add(jdata->socket, PURPLE_INPUT_READ, _server_socket_handler, jdata);
      jdata->port = ipv4_port;
    } else {
      purple_debug_error("barev", "Failed to start listening on IPv4 socket.\n");
      close(jdata->socket);
      jdata->socket = -1;
    }
  }

  if (!(ipv6_port > 0 || ipv4_port > 0)) {
    purple_debug_error("barev", "Unable to listen on socket: %s",
        g_strerror(errno));
    return -1;
  }

  return jdata->port;
}

static void
_connected_to_buddy(gpointer data, gint source, const gchar *error)
{
  BonjourJabberConversation *bconv = data;
  PurpleBuddy *pb;
  BonjourBuddy *bb;

  if (!bconv) {
    if (source >= 0)
      close(source);
    return;
  }

  /* Reaching this callback means libpurple has completed and released this
   * proxy-connect operation.  Never try to cancel the old handle later. */
  bconv->connect_data = NULL;

  if (bconv->closing || bconv->close_timeout != 0) {
    if (source >= 0)
      close(source);
    return;
  }

  pb = bconv->pb;
  bb = pb ? purple_buddy_get_protocol_data(pb) : NULL;

  /* Debug log */
  purple_debug_info("barev", "_connected_to_buddy for %s, source=%d, error=%s\n",
                   pb ? purple_buddy_get_name(pb) : "(unknown)",
                   source, error ? error : "(null)");

  if (!pb || !bb || bb->conversation != bconv) {
    purple_debug_warning("barev", "Stale proxy-connect callback\n");
    if (source >= 0) close(source);
    bonjour_jabber_close_conversation(bconv);
    return;
  }

  if (source < 0) {
    PurpleConversation *conv = NULL;
    PurpleAccount *account = NULL;
    GSList *tmp = bb->ips;

    purple_debug_error("barev", "Error connecting to buddy %s at %s:%d (%s); Trying next IP address\n",
           purple_buddy_get_name(pb), bconv->ip, bb->port_p2pj,
           error ? error : "unknown error");

    /* There may be multiple entries for the same IP - one per
     * presence recieved (e.g. multiple interfaces).
     * We need to make sure that we find the previously used entry.
     */
    while (tmp && bconv->ip_link != tmp->data)
      tmp = g_slist_next(tmp);
    if (tmp)
      tmp = g_slist_next(tmp);

    account = purple_buddy_get_account(pb);

    if (tmp != NULL) {
      const gchar *ip;
      PurpleProxyConnectData *connect_data;
      gchar *host_for_connect;

      bconv->ip_link = ip = tmp->data;

      /* Format IP correctly for IPv6 */
      host_for_connect = format_host_for_proxy(ip);

      purple_debug_info("barev", "Starting conversation with %s at %s:%d (formatted: %s:%d)\n",
            purple_buddy_get_name(pb), ip, bb->port_p2pj,
            host_for_connect, bb->port_p2pj);

      connect_data = purple_proxy_connect(purple_account_get_connection(account),
                  account, host_for_connect, bb->port_p2pj,
                  _connected_to_buddy, bconv);

      g_free(host_for_connect);

      if (connect_data != NULL) {
        g_free(bconv->ip);
        bconv->ip = g_strdup(ip);
        bconv->connect_data = connect_data;

        return;
      }
    }

    purple_debug_error("barev", "No more addresses for buddy %s. Aborting", purple_buddy_get_name(pb));

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
    if (conv != NULL)
      purple_conversation_write(conv, NULL,
          _("Unable to send the message, the conversation couldn't be started."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));

    bonjour_jabber_close_conversation(bconv);
    return;
  }

  bconv->socket = source;

  {
    gchar *ygg_ip = get_local_yggdrasil_ip(source);
    if (ygg_ip) {
      g_free(bconv->local_ip);
      bconv->local_ip = ygg_ip;
      purple_debug_info("barev", "Outgoing connection local Yggdrasil IP: %s\n", bconv->local_ip);
    }
  }

  if (!bonjour_jabber_send_stream_init(bconv, source)) {
    const char *err = g_strerror(errno);
    PurpleConversation *conv = NULL;
    PurpleAccount *account = NULL;

    purple_debug_error("barev", "Error starting stream with buddy %s at %s:%d error: %s\n",
           purple_buddy_get_name(pb), bconv->ip, bb->port_p2pj, err ? err : "(null)");

    account = purple_buddy_get_account(pb);

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
    if (conv != NULL)
      purple_conversation_write(conv, NULL,
          _("Unable to send the message, the conversation couldn't be started."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));

    bonjour_jabber_close_conversation(bconv);
    return;
  }

  /* Start listening for the stream acknowledgement */
  bconv->rx_handler = purple_input_add(source,
    PURPLE_INPUT_READ, _client_socket_handler, bconv);
}

void
bonjour_jabber_conv_match_by_name(BonjourJabberConversation *bconv)
{
    PurpleBuddy *pb = NULL;
    BonjourBuddy *bb;
    BonjourData *data;
    GSList *buddies, *it;
    char *canonical;

    if (!bconv || bconv->closing || bconv->close_timeout) return;
    canonical = barev_address_identity(bconv->buddy_name, FALSE);
    data = bconv->account && bconv->account->gc ? bconv->account->gc->proto_data : NULL;
    if (!canonical || !data || !data->jabber_data ||
        !bonjour_validate_endpoints(bconv, canonical)) goto rejected;

    /* Match a complete canonical identity, never just a nickname or IP. */
    buddies = purple_find_buddies(bconv->account, NULL);
    for (it = buddies; it; it = it->next) {
        char *identity = bonjour_buddy_identity(it->data);
        if (identity && !strcmp(identity, canonical) &&
            (bconv->incoming || bconv->pb == it->data)) pb = it->data;
        g_free(identity);
        if (pb) break;
    }
    g_slist_free(buddies);
    if (!pb || !(bb = purple_buddy_get_protocol_data(pb))) goto rejected;

    g_free(bconv->buddy_name);
    bconv->buddy_name = canonical;
    canonical = NULL;
    if (!bonjour_candidate_wins_collision(pb, bb->conversation, bconv)) goto rejected;
    if (bb->conversation && bb->conversation != bconv) {
        BonjourJabberConversation *old = bb->conversation;
        /* Detach the losing stream so teardown cannot reset the winner. */
        bb->conversation = bconv;
        bonjour_jabber_close_conversation(old);
    }
    bconv->pb = pb;
    bb->conversation = bconv;
    data->jabber_data->pending_conversations =
        g_slist_remove(data->jabber_data->pending_conversations, bconv);
    return;

rejected:
    g_free(canonical);
    purple_debug_warning("barev", "Rejecting unexpected contact identity or duplicate stream\n");
    async_bonjour_jabber_close_conversation(bconv);
}



static void
_connected_to_buddy_direct(gpointer data, gint socket, PurpleInputCondition condition)
{
    BonjourJabberConversation *bconv = data;
    PurpleBuddy *pb;
    BonjourBuddy *bb;
    int error = 0;
    socklen_t len = sizeof(error);

    if (!bconv || bconv->closing || bconv->close_timeout != 0)
        return;

    pb = bconv->pb;
    bb = pb ? purple_buddy_get_protocol_data(pb) : NULL;

    if (bconv->connect_handler != 0) {
        guint handler = bconv->connect_handler;
        bconv->connect_handler = 0;
        purple_input_remove(handler);
    }

    if (!pb || !bb || bb->conversation != bconv || socket != bconv->socket) {
        purple_debug_warning("barev",
                             "Ignoring stale direct-connect callback for socket %d\n",
                             socket);
        if (socket >= 0 && socket != bconv->socket)
            close(socket);
        bonjour_jabber_close_conversation(bconv);
        return;
    }

    /* Check if connection succeeded */
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        error = errno;
    }

    if (error != 0) {
        purple_debug_error("barev", "Direct connection to %s failed: %s\n",
                         purple_buddy_get_name(pb), g_strerror(error));
        bonjour_jabber_close_conversation(bconv);
        return;
    }

    /* Connection successful! */
    purple_debug_info("barev",
                     "Direct connection to %s established (conversation=%p fd=%d)\n",
                     purple_buddy_get_name(pb), bconv, socket);

    {
        gchar *ygg_ip = get_local_yggdrasil_ip(socket);
        if (ygg_ip) {
            g_free(bconv->local_ip);
            bconv->local_ip = ygg_ip;
            purple_debug_info("barev", "Direct connection local Yggdrasil IP: %s\n", bconv->local_ip);
        }
    }

    /* Set up read handler */
    bconv->rx_handler = purple_input_add(socket, PURPLE_INPUT_READ,
                                         _client_socket_handler, bconv);

    /* Send stream init */
    if (!bonjour_jabber_send_stream_init(bconv, socket)) {
        purple_debug_error("barev", "Failed to send stream init\n");
        bonjour_jabber_close_conversation(bconv);
    }
}

static PurpleBuddy *
_find_or_start_conversation(BonjourJabber *jdata, const gchar *to)
{
  PurpleBuddy *pb = NULL;
  BonjourBuddy *bb = NULL;

  g_return_val_if_fail(jdata != NULL, NULL);
  g_return_val_if_fail(to != NULL, NULL);

  pb = purple_find_buddy(jdata->account, to);
  if (pb == NULL || (bb = purple_buddy_get_protocol_data(pb)) == NULL)
    /* You can not send a message to an offline buddy */
    return NULL;

  /* Check if there is a previously open conversation */
  if (bb->conversation == NULL)
  {
     purple_debug_info("barev", "Creating new conversation for %s (was NULL)\n", to);

    if (bb->ips == NULL || bb->ips->data == NULL) {
      /* No address known yet (e.g. bare-nick contact whose IP has not been
       * learned).  Connecting is impossible; don't dereference NULL. */
      purple_debug_warning("barev",
          "No known IP for buddy %s; cannot start conversation\n", to);
      return NULL;
    }

    char *identity = bonjour_buddy_identity(pb);
    struct in6_addr expected, target;
    const char *ip = bb->ips->data; /* Start with the first IP address. */
    gboolean valid = identity && inet_pton(AF_INET6, strchr(identity, '@')+1, &expected) == 1 &&
        inet_pton(AF_INET6, ip, &target) == 1 && !memcmp(&expected, &target, 16);
    g_free(identity);
    if (!valid) return NULL;

    purple_debug_info("barev", "Starting conversation with %s at %s:%d\n", to, ip, bb->port_p2pj);

    /* Check if this is an IPv6 address */
    if (is_ipv6_address(ip)) {
        /* For IPv6 addresses, connect directly without DNS */
        int sock = socket(AF_INET6, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct sockaddr_in6 addr6;
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(bb->port_p2pj);

            /* Parse IPv6 address */
            char clean_ip[INET6_ADDRSTRLEN];
            strncpy(clean_ip, ip, sizeof(clean_ip) - 1);
            clean_ip[sizeof(clean_ip) - 1] = '\0';

            /* Remove scope ID for inet_pton */
            char *percent = strchr(clean_ip, '%');
            if (percent) *percent = '\0';

            if (inet_pton(AF_INET6, clean_ip, &addr6.sin6_addr) == 1) {
                /* Handle scope ID if present */
                if (percent) {
                    /* Extract interface name or index */
                    char *scope_str = percent + 1;
                    unsigned int scope_id = if_nametoindex(scope_str);
                    if (scope_id == 0) {
                        /* Try to parse as number */
                        scope_id = atoi(scope_str);
                    }
                    if (scope_id > 0) {
                        addr6.sin6_scope_id = scope_id;
                    }
                }

                _purple_network_set_common_socket_flags(sock);

                /* Try to bind to source address, but don't fail if it doesn't work */
                const char *my_jid = bonjour_get_jid(jdata->account);
                if (my_jid) {
                    char *at_sign = strchr(my_jid, '@');
                    if (at_sign) {
                        char *my_ip = at_sign + 1;
                        struct sockaddr_in6 bind_addr;
                        memset(&bind_addr, 0, sizeof(bind_addr));
                        bind_addr.sin6_family = AF_INET6;

                        if (inet_pton(AF_INET6, my_ip, &bind_addr.sin6_addr) == 1) {
                            if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
                                purple_debug_warning("barev",
                                    "Failed to bind to %s: %s (continuing anyway)\n",
                                    my_ip, g_strerror(errno));
                            } else {
                                purple_debug_info("barev", "Bound socket to %s\n", my_ip);
                            }
                        } else {
                            purple_debug_warning("barev",
                                "Could not parse our own IP %s for binding\n", my_ip);
                        }
                    }
                }

                if (connect(sock, (struct sockaddr*)&addr6, sizeof(addr6)) == 0 ||
                    barev_connect_pending()) {
                    /* Connection successful or in progress */
                    BonjourJabberConversation *bconv;

                    bconv = bonjour_jabber_conv_new(pb, jdata->account, ip);
                    if (!bconv) { close(sock); return NULL; }
                    bconv->remote_port = bb->port_p2pj;
                    bb->conversation = bconv;
                    purple_debug_info("barev", "Setting bb->conversation for %s to %p\n",
                                      purple_buddy_get_name(pb), bconv);
                    bconv->socket = sock;

                    /* Set up handler for when connection completes */
                    bconv->connect_handler = purple_input_add(sock, PURPLE_INPUT_WRITE,
                                                              _connected_to_buddy_direct, bconv);

                    purple_debug_info("barev", "Direct IPv6 connection to %s:%d\n",
                                     ip, bb->port_p2pj);
                    return pb;
                } else {
                    purple_debug_error("barev", "connect() failed: %s\n", g_strerror(errno));
                    close(sock);
                }
            } else {
                purple_debug_error("barev", "inet_pton failed for IPv6: %s\n", ip);
                close(sock);
            }
        }

        /* Fall through to proxy_connect if direct fails */
    }

    /* For IPv4 or if direct IPv6 failed, use purple_proxy_connect */
    PurpleProxyConnectData *connect_data;
    PurpleProxyInfo *proxy_info;

    /* Make sure that the account always has a proxy of "none". */
    proxy_info = purple_account_get_proxy_info(jdata->account);
    if (proxy_info == NULL) {
      proxy_info = purple_proxy_info_new();
      purple_account_set_proxy_info(jdata->account, proxy_info);
    }
    purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_NONE);

    /* Format host for proxy - IPv6 needs brackets */
    gchar *host_for_connect;
    if (strchr(ip, ':')) {
        host_for_connect = g_strdup_printf("[%s]", ip);
    } else {
        host_for_connect = g_strdup(ip);
    }

    purple_debug_info("barev", "Using proxy_connect with host: %s, port: %d\n",
                     host_for_connect, bb->port_p2pj);

    BonjourJabberConversation *bconv;

    bconv = bonjour_jabber_conv_new(pb, jdata->account, ip);
    if (!bconv) { g_free(host_for_connect); return NULL; }
    bconv->ip_link = ip;
    bconv->remote_port = bb->port_p2pj;
    bb->conversation = bconv;

    connect_data = purple_proxy_connect(
                purple_account_get_connection(jdata->account),
                jdata->account,
                host_for_connect, bb->port_p2pj, _connected_to_buddy, bconv);

    g_free(host_for_connect);

    if (connect_data == NULL) {
      purple_debug_error("barev", "Unable to connect to buddy (%s).\n", to);
      bonjour_jabber_close_conversation(bconv);
      return NULL;
    }

    purple_debug_info("barev", "Setting bb->conversation for %s to %p\n",
                  purple_buddy_get_name(pb), bconv);
    bconv->connect_data = connect_data;
    bconv->tx_handler = 0;
  }
  return pb;
}

int
bonjour_jabber_open_stream(BonjourJabber *jdata, const char *to)
{
    PurpleBuddy *pb;
    BonjourBuddy *bb;

    pb = _find_or_start_conversation(jdata, to);
    if (!pb)
        return 0;

    bb = purple_buddy_get_protocol_data(pb);
    if (!bb)
        return 0;

    /* Stream start is handled automatically in _connected_to_buddy()
     * via bonjour_jabber_send_stream_init(), so nothing else to do. */
    return 1;
}

int
bonjour_jabber_send_message(BonjourJabber *jdata, const gchar *to, const gchar *body)
{
    xmlnode *message_node, *node, *node2;
    gchar *message = NULL, *xhtml = NULL;
    PurpleBuddy *pb;
    BonjourBuddy *bb;
    int ret;

    pb = _find_or_start_conversation(jdata, to);
    if (pb == NULL || (bb = purple_buddy_get_protocol_data(pb)) == NULL) {
        purple_debug_info("barev",
                          "Can't send a message to an offline buddy (%s).\n", to);
        /* You can not send a message to an offline buddy */
        return -10000;
    }

    /* Barev auto-connect and similar callers may pass an empty body.
     * In that case, just ensure the stream/connection exists and return.
     */
    if (body == NULL || *body == '\0') {
        purple_debug_info("barev",
                          "Empty message body for %s – opening/keeping stream only.\n",
                          to);
        return 0;
    }

    /* Queue if stream not fully established. Relying on tx_buf here is
     * unreliable: if the TCP connection attempt fails the bconv is destroyed
     * and tx_buf goes with it. bb->pending_messages survives bconv
     * destruction and is drained when the next successful stream fires
     * the FULLY_SENT block. */
    if (bb->conversation == NULL ||
        bb->conversation->connect_data != NULL ||
        bb->conversation->sent_stream_start != FULLY_SENT ||
        !bb->conversation->recv_stream_start) {
        bb->pending_messages = g_slist_append(bb->pending_messages, g_strdup(body));
        purple_debug_info("barev",
            "queued message for %s (queue depth %u)\n",
            to, g_slist_length(bb->pending_messages));
        PurpleConversation *conv = purple_find_conversation_with_account(
            PURPLE_CONV_TYPE_IM, to, jdata->account);
        if (conv)
            purple_conversation_write(conv, NULL,
                _("Message queued: will be delivered when the contact connects."),
                PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time(NULL));
        return 1;
    }

    purple_markup_html_to_xhtml(body, &xhtml, &message);

    if (message == NULL || *message == '\0') {
        g_free(xhtml);
        purple_debug_warning("barev",
                             "Converted message for %s is empty; not sending.\n",
                             to);
        return 0;
    }

    message_node = xmlnode_new("message");
    xmlnode_set_attrib(message_node, "to", bb->name ? bb->name : "");

    /* Ensure we never pass NULL to xmlnode_set_attrib */
    const char *from = bonjour_jabber_get_local_jid(bb->conversation);
    if (!from)
        from = "";
    xmlnode_set_attrib(message_node, "from", from);
    xmlnode_set_attrib(message_node, "type", "chat");

    /* Enclose the message from the UI within a "body" node */
    node = xmlnode_new_child(message_node, "body");
    xmlnode_insert_data(node, message, strlen(message));
    g_free(message);

    node = xmlnode_new_child(message_node, "html");
    xmlnode_set_namespace(node, "http://www.w3.org/1999/xhtml");

    node = xmlnode_new_child(node, "body");
    message = g_strdup_printf("<font>%s</font>", xhtml);
    node2 = xmlnode_from_str(message, strlen(message));
    g_free(xhtml);
    g_free(message);
    xmlnode_insert_child(node, node2);

    node = xmlnode_new_child(message_node, "x");
    xmlnode_set_namespace(node, "jabber:x:event");
    xmlnode_insert_child(node, xmlnode_new("composing"));

    message = bonjour_jabber_packet_xml(pb, message_node);
    xmlnode_free(message_node);

    ret = (_send_data(pb, message) >= 0);

    g_free(message);

    return ret;
}

static gboolean
_async_bonjour_jabber_close_conversation_cb(gpointer data)
{
  BonjourJabberConversation *bconv = data;

  if (!bconv || bconv->closing)
    return FALSE;

  bconv->close_timeout = 0;
  bonjour_jabber_close_conversation(bconv);
  return FALSE;
}

void
async_bonjour_jabber_close_conversation(BonjourJabberConversation *bconv)
{
  BonjourJabber *jdata = NULL;

  if (!bconv || bconv->closing || bconv->close_timeout != 0)
    return;

  if (bconv->account && bconv->account->gc &&
      PURPLE_CONNECTION_IS_VALID(bconv->account->gc) &&
      bconv->account->gc->proto_data) {
    BonjourData *bd = bconv->account->gc->proto_data;
    jdata = bd ? bd->jabber_data : NULL;
  }

  if (jdata)
    jdata->pending_conversations =
        g_slist_remove(jdata->pending_conversations, bconv);

  /* close_timeout makes this conversation logically dead immediately.  Keep
   * the buddy back-pointer until the destructor runs so it can clear only this
   * exact conversation and update presence correctly. */
  purple_debug_info("barev",
                    "Scheduling asynchronous close of conversation %p fd=%d\n",
                    bconv, bconv->socket);
  bconv->close_timeout =
      purple_timeout_add(0, _async_bonjour_jabber_close_conversation_cb, bconv);
}

void
bonjour_jabber_close_conversation(BonjourJabberConversation *bconv)
{
  BonjourData *bd = NULL;
  PurpleBuddy *pb = NULL;
  BonjourBuddy *bb = NULL;
  gboolean was_current = FALSE;

  if (!bconv || bconv->closing)
    return;

  /* Never free the parser context from inside a libxml SAX callback: libxml
   * would keep using it after we return.  Defer to the event loop instead. */
  if (bconv->in_parser) {
    async_bonjour_jabber_close_conversation(bconv);
    return;
  }

  bconv->closing = TRUE;

  purple_debug_info("barev",
                    "Closing conversation %p fd=%d direction=%s peer=%s\n",
                    bconv, bconv->socket,
                    bconv->incoming ? "incoming" : "outgoing",
                    bconv->buddy_name ? bconv->buddy_name :
                    (bconv->pb ? purple_buddy_get_name(bconv->pb) : "(unknown)"));

  /* A synchronous close supersedes a previously queued asynchronous close. */
  if (bconv->close_timeout != 0) {
    guint timeout = bconv->close_timeout;
    bconv->close_timeout = 0;
    purple_timeout_remove(timeout);
  }

  bonjour_jabber_stop_ping(bconv);

  if (bconv->frame_timer) {
    guint timer = bconv->frame_timer;
    bconv->frame_timer = 0;
    purple_timeout_remove(timer);
  }

  if (bconv->account && bconv->account->gc &&
      PURPLE_CONNECTION_IS_VALID(bconv->account->gc) &&
      bconv->account->gc->proto_data) {
    bd = bconv->account->gc->proto_data;
    if (bd && bd->jabber_data) {
      bd->jabber_data->pending_conversations =
          g_slist_remove(bd->jabber_data->pending_conversations, bconv);
    }
  }

  pb = bconv->pb;
  if (pb) {
    bb = purple_buddy_get_protocol_data(pb);
    was_current = (bb && bb->conversation == bconv);

    /* Clear this in the one function which owns destruction.  Requiring every
     * caller to clear it after g_free() left several stale-pointer paths. */
    if (was_current) {
      barev_avatar_request_clear(&bb->avatar_request);
      bb->conversation = NULL;
      barev_images_lost(pb);
    }

    if (was_current && bconv->account && bconv->account->gc &&
        PURPLE_CONNECTION_IS_VALID(bconv->account->gc))
      bonjour_buddy_defer_offline(bb);
  }

  /* Cancel file transfers which have not started yet. */
  if (was_current && bd) {
    GSList *xfers = bd->xfer_lists;
    while (xfers != NULL) {
      PurpleXfer *xfer = xfers->data;
      GSList *next = xfers->next;

      if (purple_strequal(xfer->who, purple_buddy_get_name(pb)) &&
          (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_NOT_STARTED ||
           purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_UNKNOWN)) {
        purple_xfer_cancel_remote(xfer);
      }
      xfers = next;
    }
  }

  /* Remove every source before closing the descriptor or freeing callback
   * data.  connect_handler is distinct from rx_handler so a stale connect
   * completion cannot remove a newer read watcher. */
  if (bconv->connect_handler != 0) {
    guint handler = bconv->connect_handler;
    bconv->connect_handler = 0;
    purple_input_remove(handler);
  }
  if (bconv->rx_handler != 0) {
    guint handler = bconv->rx_handler;
    bconv->rx_handler = 0;
    purple_input_remove(handler);
  }
  if (bconv->tx_handler != 0) {
    guint handler = bconv->tx_handler;
    bconv->tx_handler = 0;
    purple_input_remove(handler);
  }

  /* Do not finalise an intentionally open <stream:stream> while tearing down:
   * finalisation invokes SAX callbacks and reports a false premature-EOF. */
  bonjour_parser_destroy(bconv);

  if (bconv->socket >= 0) {
    if (bconv->sent_stream_start == FULLY_SENT) {
      size_t len = strlen(STREAM_END);
      if (send(bconv->socket, STREAM_END, len, MSG_NOSIGNAL) != (gssize)len) {
        purple_debug_info("barev",
                          "Could not send stream end while closing: %s\n",
                          g_strerror(errno));
      }
    }
    close(bconv->socket);
    bconv->socket = -1;
  }

  if (bconv->connect_data != NULL) {
    PurpleProxyConnectData *connect_data = bconv->connect_data;
    bconv->connect_data = NULL;
    purple_proxy_connect_cancel(connect_data);
  }

  if (bconv->stream_data != NULL) {
    struct _stream_start_data *ss = bconv->stream_data;
    bconv->stream_data = NULL;
    g_free(ss->msg);
    g_free(ss);
  }

  if (bconv->tx_buf)
    purple_circ_buffer_destroy(bconv->tx_buf);

  /* Terminate any active Jingle sessions on this connection */
  if (bconv->jingle_sessions) {
    barev_jingle_terminate_sessions(bconv);
  }

  g_free(bconv->buddy_name);
  g_free(bconv->ip);
  g_free(bconv->local_ip);
  barev_conversations = g_slist_remove(barev_conversations, bconv);
  g_free(bconv);
}

void
bonjour_jabber_stop(BonjourJabber *jdata)
{
  /* Remove watchers before closing their descriptors.  Otherwise a reused fd
   * can make a queued server callback run against an unrelated socket. */
  if (jdata->watcher_id > 0) {
    purple_input_remove(jdata->watcher_id);
    jdata->watcher_id = 0;
  }
  if (jdata->watcher_id6 > 0) {
    purple_input_remove(jdata->watcher_id6);
    jdata->watcher_id6 = 0;
  }
  if (jdata->socket >= 0) {
    close(jdata->socket);
    jdata->socket = -1;
  }
  if (jdata->socket6 >= 0) {
    close(jdata->socket6);
    jdata->socket6 = -1;
  }

  /* Close all the conversation sockets and remove all the watchers after sending end streams */
  if (jdata->account->gc != NULL) {
    GSList *buddies, *l;

    buddies = purple_find_buddies(jdata->account, NULL);
    for (l = buddies; l; l = l->next) {
      BonjourBuddy *bb = purple_buddy_get_protocol_data((PurpleBuddy*) l->data);
      if (bb && bb->conversation)
        bonjour_jabber_close_conversation(bb->conversation);
    }

    g_slist_free(buddies);
  }

  while (jdata->pending_conversations != NULL) {
    BonjourJabberConversation *bconv = jdata->pending_conversations->data;

    /* Detach the node *before* closing: close_conversation() no-ops on an
     * already-closing conversation, which used to spin this loop forever. */
    jdata->pending_conversations =
        g_slist_delete_link(jdata->pending_conversations,
                            jdata->pending_conversations);
    if (bconv != NULL)
      bonjour_jabber_close_conversation(bconv);
  }
}

XepIq *
xep_iq_new(void *data, XepIqType type, const char *to, const char *from, const char *id)
{
  xmlnode *iq_node = NULL;
  XepIq *iq = NULL;

  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail(to != NULL, NULL);
  g_return_val_if_fail(id != NULL, NULL);

  iq_node = xmlnode_new("iq");

  xmlnode_set_attrib(iq_node, "to", to);
  xmlnode_set_attrib(iq_node, "from", from);
  xmlnode_set_attrib(iq_node, "id", id);
  switch (type) {
    case XEP_IQ_SET:
      xmlnode_set_attrib(iq_node, "type", "set");
      break;
    case XEP_IQ_GET:
      xmlnode_set_attrib(iq_node, "type", "get");
      break;
    case XEP_IQ_RESULT:
      xmlnode_set_attrib(iq_node, "type", "result");
      break;
    case XEP_IQ_ERROR:
      xmlnode_set_attrib(iq_node, "type", "error");
      break;
    case XEP_IQ_NONE:
    default:
      xmlnode_set_attrib(iq_node, "type", "none");
      break;
  }

  iq = g_new0(XepIq, 1);
  iq->node = iq_node;
  iq->type = type;
  iq->data = ((BonjourData*)data)->jabber_data;
  iq->to = (char*)to;

  return iq;
}

int
xep_iq_send_and_free(XepIq *iq)
{
  int ret = -1;
  PurpleBuddy *pb = NULL;

  if (iq == NULL)
    return -1;

  /* start the talk, reuse the message socket  */
  pb = _find_or_start_conversation((BonjourJabber*) iq->data, iq->to);
  /* Send the message */
  if (pb != NULL) {
    /* Convert xml node into stream */
    gchar *msg = bonjour_jabber_packet_xml(pb, iq->node);
    ret = _send_data(pb, msg);
    g_free(msg);
  }

  xmlnode_free(iq->node);
  iq->node = NULL;
  g_free(iq);

  return (ret >= 0) ? 0 : -1;
}

int
bonjour_jabber_send_xml(BonjourJabberConversation *bconv, xmlnode *node)
{
  gchar *str;
  int ret = -1;
  BonjourBuddy *bb;

  if (!bconv || !node || !bconv->pb || bconv->closing || bconv->close_timeout)
    return -1;
  bb = purple_buddy_get_protocol_data(bconv->pb);
  if (!bb || bb->conversation != bconv) return -1;
  str = bonjour_jabber_packet_xml(bconv->pb, node);
  if (!str)
    return -1;
  ret = _send_data(bconv->pb, str);
  g_free(str);
  return ret;
}

static guint barev_jingle_id_counter = 0;

gchar *
bonjour_jabber_next_id(void)
{
  return g_strdup_printf("j-%lu-%u",
                         (unsigned long)time(NULL),
                         ++barev_jingle_id_counter);
}

/* Barev: return local IPs suitable for Yggdrasil file-transfer.
 * We only return IPv6 addresses that look "global" (i.e. not
 * link-local, not ULA, not loopback). On your hosts those
 * are exactly the Yggdrasil addresses.
 *
 * Each list element is a g_malloc'ed string; caller must g_free().
 */

/*
 * Barev: return local IPs suitable for Yggdrasil file-transfer.
 *
 * We only return IPv6 addresses that:
 *   - are not link-local / ULA / loopback, and
 *   - look like Yggdrasil (first hextet in 0x0200–0x03FF).
 *
 * Each list element is a g_malloc'ed string; caller must g_free().
 */
GSList *
bonjour_jabber_get_local_ips(int fd)
{
    GSList *ips = NULL;
    struct ifaddrs *ifap = NULL, *ifa;
    int ret;

    (void)fd; /* unused, keep signature compatible */

    ret = getifaddrs(&ifap);
    if (ret != 0 || !ifap) {
        purple_debug_error("barev",
                           "Barev: getifaddrs failed: %s\n",
                           g_strerror(errno));
        return NULL;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        struct sockaddr *sa;
        char host[NI_MAXHOST];

        if (!ifa->ifa_addr)
            continue;

        sa = ifa->ifa_addr;

        /* We only care about IPv6 addresses for Yggdrasil */
        if (sa->sa_family != AF_INET6)
            continue;

        if (getnameinfo(sa, sizeof(struct sockaddr_in6),
                        host, sizeof(host),
                        NULL, 0, NI_NUMERICHOST) != 0) {
            continue;
        }

        /* Filter out obvious "local" IPv6 ranges:
         *
         * fe80::/10   - link-local
         * fc00::/7    - ULA (fc.. or fd..)
         * ::1         - loopback
         */
        if (g_str_has_prefix(host, "fe80:") ||
            g_str_has_prefix(host, "fc")    ||
            g_str_has_prefix(host, "fd")    ||
            g_str_equal(host, "::1")) {
            purple_debug_info("barev",
                              "Barev: skipping local IPv6 %s on %s\n",
                              host,
                              ifa->ifa_name ? ifa->ifa_name : "?");
            continue;
        }

        /* Now only keep Yggdrasil-style globals (e.g. 201:..., 304:..., etc.)
         * and drop normal global IPv6 like 2001:xxxx:... */
        if (!is_yggdrasil_addr(host)) {
            purple_debug_info("barev",
                              "Barev: skipping non-Yggdrasil global IPv6 %s on %s\n",
                              host,
                              ifa->ifa_name ? ifa->ifa_name : "?");
            continue;
        }

        purple_debug_info("barev",
                          "Barev: adding candidate Yggdrasil IPv6 %s on %s\n",
                          host,
                          ifa->ifa_name ? ifa->ifa_name : "?");

        ips = g_slist_prepend(ips, g_strdup(host));
    }

    freeifaddrs(ifap);
    return g_slist_reverse(ips);
}

void
append_iface_if_linklocal(char *ip, guint32 interface_param) {
  struct in6_addr in6_addr;
  int len_remain = INET6_ADDRSTRLEN - strlen(ip);

  if (len_remain <= 1)
    return;

  if (inet_pton(AF_INET6, ip, &in6_addr) != 1 ||
      !IN6_IS_ADDR_LINKLOCAL(&in6_addr))
    return;

  snprintf(ip + strlen(ip), len_remain, "%%%d",
     interface_param);
}


/* Other ping functions */
/* Send ping request */
void bonjour_jabber_send_ping_request(BonjourJabberConversation *bconv) {
  if (!bconv || bconv->closing || bconv->close_timeout != 0 ||
      bconv->socket < 0 || !bconv->pb) {
    return;
  }

  /* Generate ping ID */
  g_free(bconv->last_ping_id);
  bconv->last_ping_id = generate_ping_id();

  /* Create ping IQ */
  xmlnode *iq = xmlnode_new("iq");
  xmlnode_set_attrib(iq, "type", "get");
  xmlnode_set_attrib(iq, "id", bconv->last_ping_id);
  xmlnode_set_attrib(iq, "from", bonjour_jabber_get_local_jid(bconv));
  xmlnode_set_attrib(iq, "to", purple_buddy_get_name(bconv->pb));

  xmlnode *ping = xmlnode_new_child(iq, "ping");
  xmlnode_set_namespace(ping, "urn:xmpp:ping");

  char *xml = bonjour_jabber_packet_xml(bconv->pb, iq);
  xmlnode_free(iq);

  BonjourBuddy *bb_ping = purple_buddy_get_protocol_data(bconv->pb);
  _send_data(bconv->pb, xml);
  g_free(xml);

  /* _send_data may have freed bconv on a send error; bail out if so */
  if (bb_ping == NULL || bb_ping->conversation != bconv)
    return;

  purple_debug_info("barev", "Sent ping to %s (id: %s)\n",
                   purple_buddy_get_name(bconv->pb), bconv->last_ping_id);

  /* Start response timeout timer */
  if (bconv->ping_response_timer) {
    purple_timeout_remove(bconv->ping_response_timer);
    bconv->ping_response_timer = 0;
  }
  bconv->ping_response_timer = purple_timeout_add_seconds(PING_TIMEOUT,
                                                         bonjour_jabber_ping_timeout_cb,
                                                         bconv);
}

/* Handle incoming ping request */
gboolean bonjour_jabber_handle_ping(xmlnode *packet, BonjourJabberConversation *bconv) {
  if (!packet || !bconv || bconv->closing || bconv->close_timeout != 0)
    return FALSE;

  const char *type = xmlnode_get_attrib(packet, "type");
  const char *id = xmlnode_get_attrib(packet, "id");

  if (type && g_ascii_strcasecmp(type, "get") == 0) {
    /* Check for ping element */
    xmlnode *ping = xmlnode_get_child_with_namespace(packet, "ping", "urn:xmpp:ping");
    if (!ping) {
      ping = xmlnode_get_child_with_namespace(packet, "ping", "urn:yggb:ping");
    }

    if (ping) {
      xmlnode *response = xmlnode_new("iq");
      xmlnode_set_attrib(response, "type", "result");
      xmlnode_set_attrib(response, "id", id ? id : "");
      xmlnode_set_attrib(response, "to", xmlnode_get_attrib(packet, "from"));
      xmlnode_set_attrib(response, "from", xmlnode_get_attrib(packet, "to"));

      char *xml = bconv->pb ? bonjour_jabber_packet_xml(bconv->pb, response) : NULL;
      xmlnode_free(response);

      gboolean send_ok = FALSE;
      if (bconv->pb) {
        /* Capture bb before _send_data: on a broken socket _send_data calls
         * bonjour_jabber_close_conversation() which g_free(bconv), making
         * bconv a dangling pointer.  We detect this via bb->conversation. */
        BonjourBuddy *bb = purple_buddy_get_protocol_data(bconv->pb);
        _send_data(bconv->pb, xml);
        send_ok = (bb != NULL && bb->conversation == bconv);
      }
      g_free(xml);

      if (!send_ok)
        return TRUE;

      purple_debug_info("barev", "Responded to ping from %s\n",
                       xmlnode_get_attrib(packet, "from"));

      /* A ping only proves transport liveness.  Do not replace the explicit
       * presence state or clear its status message. */
      if (bconv->pb) {
          bconv->last_activity = time(NULL);
          bconv->ping_failures = 0;
      }

      return TRUE;
    }
  }

  return FALSE;
}

void
bonjour_jabber_send_typing(PurpleBuddy *pb, PurpleTypingState state)
{
    BonjourBuddy *bb;
    BonjourJabber *jdata;
    xmlnode *message_node, *cs;
    gchar *xml;
    const char *from;
    PurpleAccount *account;
    PurpleConnection *gc;
    BonjourData *bd;

    if (!pb) return;

    bb = purple_buddy_get_protocol_data(pb);
    if (!bb) return;

    if (!bb->conversation) return;

    account = bb->conversation->account;
    if (!account) return;

    gc = purple_account_get_connection(account);
    if (!gc) return;

    bd = gc->proto_data;
    if (!bd) return;

    jdata = bd->jabber_data;
    if (!jdata) return;

    message_node = xmlnode_new("message");
    xmlnode_set_attrib(message_node, "to", bb->name ? bb->name : "");

    from = bonjour_jabber_get_local_jid(bb->conversation);
    xmlnode_set_attrib(message_node, "from", from ? from : "");
    xmlnode_set_attrib(message_node, "type", "chat");

    /* XEP-0085 chat states */
    if (state == PURPLE_TYPING) {
        cs = xmlnode_new_child(message_node, "composing");
    } else {
        /* treat everything else as "not typing" */
        cs = xmlnode_new_child(message_node, "active");
    }
    xmlnode_set_namespace(cs, "http://jabber.org/protocol/chatstates");

    xml = bonjour_jabber_packet_xml(pb, message_node);
    xmlnode_free(message_node);

    _send_data(pb, xml);
    g_free(xml);
}
