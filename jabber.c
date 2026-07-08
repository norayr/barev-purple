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
#include <sys/socket.h>
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
#include "parser.h"
#include "bonjour.h"
#include "buddy.h"
#include "bonjour_ft.h"
#include "libpurple/server.h"

#include "buddyicon.h"
#include "notify.h"
#include "imgstore.h"

#ifdef _SIZEOF_ADDR_IFREQ
#  define HX_SIZE_OF_IFREQ(a) _SIZEOF_ADDR_IFREQ(a)
#else
#  define HX_SIZE_OF_IFREQ(a) sizeof(a)
#endif

#ifndef HAVE_GETIFADDRS
#define HAVE_GETIFADDRS 1
#endif

/* TODO: specify version='1.0' and send stream features */
#define DOCTYPE "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
    "<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" from=\"%s\" to=\"%s\">"


#define PING_INTERVAL 30      /* Send ping every 30 seconds */
#define PING_TIMEOUT 10       /* Wait 10 seconds for response */
#define MAX_PING_FAILURES 3   /* Mark offline after 3 consecutive failures */

#define BAREV_VCARD_NS         "vcard-temp"
#define BAREV_VCARD_UPDATE_NS  "vcard-temp:x:update"

static guint barev_avatar_id_counter = 0;
static gint _send_data(PurpleBuddy *pb, char *message);
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

    account = purple_buddy_get_account(pb);
    from = account ? bonjour_get_jid(account) : "";
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

    xml = xmlnode_to_str(iq, NULL);
    xmlnode_free(iq);

    purple_debug_info("bonjour", "Barev: sending vCard GET to %s id=%s\n", to, id);
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

    if (account && name)
        purple_buddy_icons_set_for_user(account, name, NULL, 0, NULL);
}

static void
barev_handle_vcard_result(PurpleBuddy *pb, xmlnode *vcard)
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
    if (!photo) {
        barev_clear_buddy_icon(pb, bb);
        return;
    }

    binval = xmlnode_get_child(photo, "BINVAL");
    if (!binval) {
        barev_clear_buddy_icon(pb, bb);
        return;
    }

    b64 = xmlnode_get_data(binval);
    if (!b64 || !*b64) {
        g_free(b64);
        barev_clear_buddy_icon(pb, bb);
        return;
    }

    raw = g_base64_decode(b64, &raw_len);
    g_free(b64);

    if (!raw || raw_len == 0) {
        g_free(raw);
        barev_clear_buddy_icon(pb, bb);
        return;
    }

    sha1 = barev_sha1_hex(raw, raw_len);
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

    if (!packet || !pb) return FALSE;
    if (!purple_strequal(packet->name, "iq")) return FALSE;

    vcard = xmlnode_get_child_with_namespace(packet, "vCard", BAREV_VCARD_NS);
    if (!vcard) return FALSE;

    type = xmlnode_get_attrib(packet, "type");
    id   = xmlnode_get_attrib(packet, "id");

    if (type && !g_ascii_strcasecmp(type, "get")) {
        /* Peer requests our vCard: reply with PHOTO if we have an account icon */
        PurpleAccount *account = purple_buddy_get_account(pb);
        const char *from = account ? bonjour_get_jid(account) : "";
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

        xml = xmlnode_to_str(iq, NULL);
        xmlnode_free(iq);

        _send_data(pb, xml);
        g_free(xml);

        return TRUE;
    }

    if (type && !g_ascii_strcasecmp(type, "result")) {
        /* always update buddy icon */
        barev_handle_vcard_result(pb, vcard);

        /* if this id was requested by "Get Info", show a userinfo popup */
        if (id && barev_vcard_userinfo) {
            BarevVcardReq *r = g_hash_table_lookup(barev_vcard_userinfo, id);
            if (r) {
                PurpleConnection *gc = purple_account_get_connection(r->account);
                PurpleNotifyUserInfo *info = purple_notify_user_info_new();

                gchar *fn = NULL;
                xmlnode *fn_node = xmlnode_get_child(vcard, "FN");
                if (fn_node) fn = xmlnode_get_data(fn_node);

                purple_notify_user_info_add_pair_plaintext(info, "JID", r->who);
                if (fn && *fn) purple_notify_user_info_add_pair_plaintext(info, "Full Name", fn);

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
    purple_debug_error("bonjour", "xep_iq_parse: NULL input\n");
    return;
    }
    if (!packet) {
        purple_debug_error("bonjour", "xep_iq_parse: NULL packet!\n");
        return;
    }
    if (!pb) {
        purple_debug_error("bonjour", "xep_iq_parse: NULL buddy!\n");
        return;
    }

    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
    if (!bb) {
        purple_debug_error("bonjour", "xep_iq_parse: No buddy data!\n");
        return;
    }
    if (!bb->conversation) {
        purple_debug_error("bonjour", "xep_iq_parse: No conversation!\n");
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
        purple_debug_error("bonjour", "NULL parameter in safe_set_buddy_status\n");
        return;
    }

    PurpleStatusType *stype = purple_account_get_status_type(account, status_id);
    if (!stype) {
        purple_debug_error("bonjour", "No status type '%s' for account\n", status_id);
        return;
    }

    if (attr_name && attr_value) {
        purple_prpl_got_user_status(account, who, status_id, attr_name, attr_value, NULL);
    } else {
        purple_prpl_got_user_status(account, who, status_id, NULL);
    }
}

/* Get the JID for a specific conversation based on its actual source IP */
static const char *
bonjour_get_conversation_jid(BonjourJabberConversation *bconv)
{
    static char jid_buf[512];
    const char *username = purple_account_get_username(bconv->account);

    if (bconv->local_ip && *bconv->local_ip) {
        g_snprintf(jid_buf, sizeof(jid_buf), "%s@%s", username, bconv->local_ip);
    } else {
        /* Fallback to account-wide JID */
        const char *global_jid = bonjour_get_jid(bconv->account);
        g_strlcpy(jid_buf, global_jid, sizeof(jid_buf));
    }

    return jid_buf;
}

/* Validate that JID IP matches actual connection IP */
static gboolean
validate_ip_consistency(BonjourJabberConversation *bconv, const char *from_jid)
{
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    char peer_ip[INET6_ADDRSTRLEN];
    char *at_sign, *jid_ip;
    gboolean valid = FALSE;
    PurpleBuddy *pb;
    BonjourBuddy *bb;

    if (!from_jid || !bconv || bconv->socket < 0)
        return FALSE;

    /* Get the buddy and its data */
    pb = bconv->pb;
    if (!pb) {
        purple_debug_warning("bonjour", "validate_ip_consistency: no buddy attached\n");
        return FALSE;
    }

    bb = purple_buddy_get_protocol_data(pb);
    if (!bb) {
        purple_debug_warning("bonjour", "validate_ip_consistency: no buddy data\n");
        return FALSE;
    }

    /* Get actual peer IP from socket */
    if (getpeername(bconv->socket, (struct sockaddr *)&peer_addr, &peer_addr_len) != 0) {
        purple_debug_error("bonjour", "Failed to get peer address: %s\n", strerror(errno));
        return FALSE;
    }

    if (peer_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&peer_addr;
        inet_ntop(AF_INET6, &addr6->sin6_addr, peer_ip, INET6_ADDRSTRLEN);

        /* Remove scope ID if present (e.g., %eth0) */
        char *percent = strchr(peer_ip, '%');
        if (percent) *percent = '\0';

        /* First, check if the connection IP is in the buddy's known IP list */
        GSList *ip_iter = bb->ips;
        while (ip_iter) {
            const char *known_ip = ip_iter->data;
            if (known_ip && g_ascii_strcasecmp(known_ip, peer_ip) == 0) {
                /* If this conversation knows the remote destination port (outgoing), enforce it too. */
                if (bconv->remote_port > 0 && bb->port_p2pj > 0 && bb->port_p2pj != bconv->remote_port) {
                    purple_debug_warning("bonjour",
                        "Port mismatch for %s: roster port %d, connected port %d (rejecting)\n",
                        purple_buddy_get_name(pb), bb->port_p2pj, bconv->remote_port);
                    return FALSE;
                }

                purple_debug_info("bonjour",
                    "IP validation OK: connection from %s is in buddy's IP list\n",
                    peer_ip);
                return TRUE;
            }
            ip_iter = ip_iter->next;
        }

        /* If not in the list, check if it matches the JID's IP as a fallback */
        at_sign = strchr(from_jid, '@');
        if (!at_sign) {
            purple_debug_error("bonjour", "Invalid JID format (no @): %s\n", from_jid);
            return FALSE;
        }

        jid_ip = g_strdup(at_sign + 1);

        /* Compare IPs (case-insensitive for hex) */
        if (g_ascii_strcasecmp(jid_ip, peer_ip) == 0) {

            /* Enforce roster port if this is an outgoing conversation. */
            if (bconv->remote_port > 0 && bb->port_p2pj > 0 && bb->port_p2pj != bconv->remote_port) {
                purple_debug_warning("bonjour",
                    "Port mismatch for %s: roster port %d, connected port %d (rejecting)\n",
                    purple_buddy_get_name(pb), bb->port_p2pj, bconv->remote_port);
                g_free(jid_ip);
                return FALSE;
            }


            valid = TRUE;
            purple_debug_info("bonjour", "IP validation OK: JID=%s matches peer\n", jid_ip);
        } else {
            purple_debug_error("bonjour",
                "IP MISMATCH! JID says '%s' but connected from '%s', and '%s' is not in buddy's IP list. REJECTING!\n",
                jid_ip, peer_ip, peer_ip);

            /* Send error response before closing */
            const char *error_msg =
                "<stream:error>"
                "<host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>"
                "IP address mismatch: Your JID must match your connection IP or be in known IPs"
                "</text>"
                "</stream:error>"
                "</stream:stream>";
            send(bconv->socket, error_msg, strlen(error_msg), MSG_NOSIGNAL);
        }

        g_free(jid_ip);
    }

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

    if (existing->closing || existing->close_timeout != 0 || existing->socket < 0)
        return TRUE;

    /* Two connections in the same direction are duplicates.  Keep the first
     * one instead of allowing a late callback to replace a working stream. */
    if (existing->incoming == candidate->incoming)
        return FALSE;

    local_jid = bonjour_get_jid(candidate->account);
    remote_jid = pb ? purple_buddy_get_name(pb) : NULL;

    if (!local_jid || !remote_jid)
        return FALSE;

    prefer_outgoing = (g_ascii_strcasecmp(local_jid, remote_jid) < 0);
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

  purple_debug_warning("bonjour", "Ping timeout for %s (failures: %d)\n",
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
  if (now - bconv->last_activity > PING_INTERVAL * 2) {
    PurpleBuddy *pb = bconv->pb;
    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
    bonjour_jabber_send_ping_request(bconv);
    /* bonjour_jabber_send_ping_request may have freed bconv on a send error.
     * Detect this via bb->conversation and do not reschedule a dead timer. */
    if (!bb || bb->conversation != bconv)
      return FALSE;
  } else {
    purple_debug_info("bonjour", "Skipping ping for %s - recent activity\n",
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

  purple_debug_info("bonjour", "Started ping mechanism for %s\n",
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

    purple_debug_info("bonjour", "Received ping response from %s\n",
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
 * Tries getsockname() first; if that doesn't yield a Yggdrasil address,
 * falls back to bonjour_jabber_get_local_ips().
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

    /* getsockname gave nothing useful — enumerate interfaces */
    GSList *ips = bonjour_jabber_get_local_ips(-1);
    if (ips) {
        gchar *ip = g_strdup((const char *)ips->data);
        g_slist_free_full(ips, g_free);
        return ip;
    }

    return NULL;
}

/* Barev/XEP-0174 helper:
 * Match "localpart@whatever" to a buddy whose name starts with "localpart@".
 * This lets us treat "inky@barev.local" the same as "inky@201:..." as long as
 * the nick ("inky") is the same.
 */
static PurpleBuddy *
bonjour_find_buddy_by_localpart(PurpleAccount *account, const char *jid)
{
    const char *at;
    gchar *local = NULL;
    PurpleBlistNode *gnode, *cnode, *bnode;
    PurpleBuddy *found = NULL;
    int matches = 0;

    if (!account || !jid)
        return NULL;

    at = strchr(jid, '@');
    if (!at || at == jid)
        return NULL;

    /* local = "inky" for "inky@barev.local" */
    local = g_strndup(jid, (gsize)(at - jid));
    if (!local)
        return NULL;

    for (gnode = purple_blist_get_root(); gnode; gnode = gnode->next) {
        if (!PURPLE_BLIST_NODE_IS_GROUP(gnode))
            continue;

        for (cnode = gnode->child; cnode; cnode = cnode->next) {
            if (!PURPLE_BLIST_NODE_IS_CONTACT(cnode))
                continue;

            for (bnode = cnode->child; bnode; bnode = bnode->next) {
                PurpleBuddy *buddy;
                const char *name;

                if (!PURPLE_BLIST_NODE_IS_BUDDY(bnode))
                    continue;

                buddy = (PurpleBuddy *)bnode;

                if (purple_buddy_get_account(buddy) != account)
                    continue;

                name = purple_buddy_get_name(buddy);
                if (!name)
                    continue;

                /* Look for "local@" prefix or exact bare-nick match */
                if ((g_str_has_prefix(name, local) && name[strlen(local)] == '@') ||
                    g_str_equal(name, local)) {
                    matches++;
                    if (matches == 1) {
                        found = buddy;
                    } else {
                        /* Ambiguous: more than one buddy shares the same localpart */
                        purple_debug_warning("bonjour",
                            "bonjour_find_buddy_by_localpart: ambiguous localpart '%s' for '%s' (at least '%s' and '%s')\n",
                            local, jid,
                            found ? purple_buddy_get_name(found) : "(null)",
                            name);
                        g_free(local);
                        return NULL;
                    }
                }
            }
        }
    }

    if (found) {
        purple_debug_info("bonjour",
            "bonjour_find_buddy_by_localpart: '%s' -> '%s'\n",
            jid, purple_buddy_get_name(found));
    }

    g_free(local);
    return found;
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

        /* Only hand to file-transfer parser if IQ actually has children */
        if (packet->child != NULL) {
            xep_iq_parse(packet, pb);
        }

        return;
    }

    purple_debug_warning("bonjour", "Unknown packet: %s\n",
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
        g_free(bb->status);
        bb->status = show_text ? g_strdup(show_text) : NULL;
        g_free(bb->msg);
        bb->msg = status_text ? g_strdup(status_text) : NULL;
    }

    {
        PurpleStatusType *stype = purple_account_get_status_type(account, status_id);
        if (!stype) {
            purple_debug_warning("bonjour",
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
        if (x) {
            xmlnode *p = xmlnode_get_child(x, "photo");
            gchar *new_hash = p ? xmlnode_get_data(p) : NULL;

            /* Does libpurple think we already have an icon for this buddy? */
            gboolean have_icon = (purple_buddy_get_icon(pb) != NULL);

            purple_debug_info("bonjour",
                "Barev: presence avatar update for %s: hash='%s' old='%s' have_icon=%d\n",
                name,
                new_hash ? new_hash : "(none)",
                bb->phsh ? bb->phsh : "(none)",
                have_icon ? 1 : 0);

            if (!new_hash || !*new_hash) {
                if (new_hash) g_free(new_hash);
                barev_clear_buddy_icon(pb, bb);
            } else {
                gboolean changed = (!bb->phsh || !purple_strequal(bb->phsh, new_hash));

                if (changed) {
                    g_free(bb->phsh);
                    bb->phsh = g_strdup(new_hash);
                }

                /* IMPORTANT: fetch vCard if changed OR no icon yet */
                if (changed || !have_icon) {
                    purple_debug_info("bonjour",
                        "Barev: requesting vCard for %s (changed=%d have_icon=%d)\n",
                        name, changed ? 1 : 0, have_icon ? 1 : 0);

                    bonjour_jabber_request_vcard(pb, FALSE);
                }

                g_free(new_hash);
            }
        }
    }

    purple_debug_info("bonjour",
                      "Presence: %s show='%s' status='%s'\n",
                      name,
                      show_text ? show_text : "(none)",
                      status_text ? status_text : "(none)");

    g_free(show_text);
    g_free(status_text);
}

static BonjourJabberConversation *
bonjour_jabber_conv_new(PurpleBuddy *pb, PurpleAccount *account, const char *ip) {

  BonjourJabberConversation *bconv = g_new0(BonjourJabberConversation, 1);
  bconv->socket = -1;
  bconv->tx_buf = purple_circ_buffer_new(512);
  bconv->tx_handler = 0;
  bconv->rx_handler = 0;
  bconv->pb = pb;
  bconv->account = account;
  bconv->ip = g_strdup(ip);

  bconv->remote_port = -1;

  /* Initialize ping fields */
  bconv->ping_timer = 0;
  bconv->ping_response_timer = 0;
  bconv->last_ping_id = NULL;
  bconv->last_activity = time(NULL);
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
        purple_debug_error("bonjour", "message_to_ui: pb is NULL\n");
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
    purple_debug_error("bonjour", "No body or html node found, discarding message.\n");
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
    purple_debug_error("bonjour", "No html body or regular body found.\n");
    return;
  }

  /* Send the message to the UI */
  serv_got_im(gc, purple_buddy_get_name(pb), body, 0, time(NULL));

  g_free(body);
}

struct _match_buddies_by_address_t {
  const char *address;
  GSList *matched_buddies;
};

static void
_match_buddies_by_address(gpointer value, gpointer data)
{
  PurpleBuddy *pb = value;
  BonjourBuddy *bb = NULL;
  struct _match_buddies_by_address_t *mbba = data;

  bb = purple_buddy_get_protocol_data(pb);

  /*
   * If the current PurpleBuddy's data is not null, then continue to determine
   * whether one of the buddies IPs matches the target IP.
   */
  if (bb != NULL)
  {
    const char *ip;
    GSList *tmp = bb->ips;

    while(tmp) {
      ip = tmp->data;
      if (ip != NULL && g_ascii_strcasecmp(ip, mbba->address) == 0) {
        mbba->matched_buddies = g_slist_prepend(mbba->matched_buddies, pb);
        break;
      }
      tmp = tmp->next;
    }
  }
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
    purple_debug_warning("bonjour",
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

  if (ret < 0 && errno == EAGAIN)
    return;
  else if (ret <= 0) {
    PurpleConversation *conv = NULL;
    PurpleAccount *account = NULL;
    const char *error = g_strerror(errno);

    purple_debug_error("bonjour", "Error sending message to buddy %s error: %s\n",
           purple_buddy_get_name(pb), error ? error : "(null)");

    account = purple_buddy_get_account(pb);

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
    if (conv != NULL)
      purple_conversation_write(conv, NULL,
          _("Unable to send message."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));

    bonjour_jabber_close_conversation(bconv);
    return;
  }

  purple_circ_buffer_mark_read(bconv->tx_buf, ret);
}

static gint _send_data(PurpleBuddy *pb, char *message)
{
  gint ret;
  int len = strlen(message);
  BonjourBuddy *bb;
  BonjourJabberConversation *bconv;

  if (!pb || !message)
    return -1;

  bb = purple_buddy_get_protocol_data(pb);
  if (!bb || !bb->conversation) {
    purple_debug_warning("bonjour", "_send_data: no conversation for buddy %s\n",
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

  if (ret == -1 && errno == EAGAIN)
    ret = 0;
  else if (ret <= 0) {
    PurpleConversation *conv;
    PurpleAccount *account;
    const char *error = g_strerror(errno);

    purple_debug_error("bonjour", "Error sending message to buddy %s error: %s\n",
           purple_buddy_get_name(pb), error ? error : "(null)");

    account = purple_buddy_get_account(pb);

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
    if (conv != NULL)
      purple_conversation_write(conv, NULL,
          _("Unable to send message."),
          PURPLE_MESSAGE_SYSTEM, time(NULL));

    bonjour_jabber_close_conversation(bconv);
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

    purple_debug_info("bonjour",
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
        purple_debug_info("bonjour", "send_presence: buddy has no protocol data\n");
        return -1;
    }

    bconv = bb->conversation;
    if (!bconv || bconv->socket < 0) {
        purple_debug_info("bonjour",
                          "send_presence: %s has no active conversation\n",
                          purple_buddy_get_name(pb));
        return -1;
    }

    presence_node = xmlnode_new("presence");

    if (offline) {
        xmlnode_set_attrib(presence_node, "type", "unavailable");
    }

    account = purple_buddy_get_account(pb);
    from = account ? bonjour_get_jid(account) : NULL;
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

    xml = xmlnode_to_str(presence_node, NULL);
    xmlnode_free(presence_node);

    ret = (_send_data(pb, xml) >= 0);

    g_free(xml);

    return ret;
}

void
bonjour_jabber_stream_ended(BonjourJabberConversation *bconv)
{
  purple_debug_info("bonjour", "Received conversation close notification from %s\n",
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
    purple_debug_warning("bonjour",
                         "Ignoring stale read callback for socket %d (current %d)\n",
                         socket, bconv->socket);
    return;
  }

  /* Read the data from the socket */
  if ((len = recv(socket, message, sizeof(message) - 1, 0)) < 0) {
    /* There have been an error reading from the socket */
    if (len != -1 || errno != EAGAIN) {
      const char *err = g_strerror(errno);

      purple_debug_warning("bonjour",
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

    purple_debug_warning("bonjour", "Connection closed (without stream end) by %s.\n", name);
    bonjour_jabber_stream_ended(bconv);
    return;
  }

  message[len] = '\0';

  purple_debug_info("bonjour", "Receive: -%s- %" G_GSSIZE_FORMAT " bytes\n", message, len);
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
    purple_debug_warning("bonjour", "Ignoring stale stream-start callback\n");
    return;
  }

  ss = bconv->stream_data;

  len = strlen(ss->msg);

  /* Start Stream */
  ret = send(source, ss->msg, len, MSG_NOSIGNAL);

  if (ret == -1 && errno == EAGAIN)
    return;
  else if (ret <= 0) {
    const char *err = g_strerror(errno);
    PurpleConversation *conv;
    const char *bname = bconv->buddy_name;

    if(bconv->pb)
      bname = purple_buddy_get_name(bconv->pb);

    purple_debug_error("bonjour", "Error starting stream with buddy %s at %s error: %s\n",
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

  if (bconv->pb != NULL)
    bname = purple_buddy_get_name(bconv->pb);

  /* If we have no idea who "to" is, use an empty string.
   * If we don't know now, it is because the other side isn't playing nice, so they can't complain. */
  if (bname == NULL)
    bname = "";

  stream_start = g_strdup_printf(DOCTYPE, bonjour_get_conversation_jid(bconv), bname);
  len = strlen(stream_start);

  bconv->sent_stream_start = PARTIALLY_SENT;

  /* Start the stream */
  ret = send(client_socket, stream_start, len, MSG_NOSIGNAL);

  if (ret == -1 && errno == EAGAIN)
    ret = 0;
  else if (ret <= 0) {
    const char *err = g_strerror(errno);

    purple_debug_error("bonjour", "Error starting stream with buddy %s at %s error: %s\n",
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

  purple_debug_info("bonjour",
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

    purple_debug_error("bonjour",
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

    purple_debug_info("bonjour",
        "stream_started: FULLY_SENT block firing for %s (ping_timer=%u)\n",
        purple_buddy_get_name(pb), bconv->ping_timer);

    if (bb) {
      /* Start ping mechanism */
      bonjour_jabber_start_ping(bconv);
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
        purple_debug_info("bonjour",
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
    purple_debug_warning("bonjour",
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
    purple_debug_error("bonjour", "accept() failed: %s\n", g_strerror(errno));
    return;
  }

  _purple_network_set_common_socket_flags(client_socket);

  /* Use getnameinfo to get the IP address - it handles IPv6 scope IDs automatically */
  if (getnameinfo(&their_addr.sa, sin_size,
                  addrstr, sizeof(addrstr),
                  NULL, 0, NI_NUMERICHOST) != 0) {
    purple_debug_error("bonjour", "getnameinfo failed: %s\n", g_strerror(errno));
    close(client_socket);
    return;
  }

  address_text = addrstr;
  purple_debug_info("bonjour", "Received incoming connection from %s.\n", address_text);



  /* Check if we got a valid address */
  if (!address_text || strlen(address_text) == 0) {
    purple_debug_error("bonjour", "Failed to extract IP address\n");
    close(client_socket);
    return;
  }

  purple_debug_info("bonjour", "Received incoming connection from %s.\n", address_text);

  /* Rest of the function remains the same... */
  struct _match_buddies_by_address_t *mbba;
  GSList *buddies;

  mbba = g_new0(struct _match_buddies_by_address_t, 1);
  mbba->address = address_text;

  buddies = purple_find_buddies(jdata->account, NULL);
  g_slist_foreach(buddies, _match_buddies_by_address, mbba);
  g_slist_free(buddies);

  if (mbba->matched_buddies == NULL)
    purple_debug_warning("bonjour", "No buddy matched IP %s - proceeding to stream negotiation\n", address_text);

  /* Clean up match structure */
  if (mbba->matched_buddies)
    g_slist_free(mbba->matched_buddies);
  g_free(mbba);

  /* Create conversation for this connection */
  BonjourJabberConversation *bconv = bonjour_jabber_conv_new(NULL, jdata->account, address_text);
  bconv->incoming = TRUE;
  bconv->socket = client_socket;

  {
    gchar *ygg_ip = get_local_yggdrasil_ip(client_socket);
    if (ygg_ip) {
      g_free(bconv->local_ip);
      bconv->local_ip = ygg_ip;
      purple_debug_info("bonjour", "Incoming connection local Yggdrasil IP: %s\n", bconv->local_ip);
    }
  }

  bconv->rx_handler = purple_input_add(client_socket, PURPLE_INPUT_READ, _client_socket_handler, bconv);
  purple_debug_info("bonjour",
                    "Accepted incoming conversation %p fd=%d from %s\n",
                    bconv, client_socket, address_text);

  /* Add to pending conversations list */
  jdata->pending_conversations = g_slist_prepend(jdata->pending_conversations, bconv);
}

static int
start_serversocket_listening(int port, int socket, struct sockaddr *addr, size_t addr_size, gboolean ip6, gboolean allow_port_fallback)
{
  int ret_port = port;

  purple_debug_info("bonjour", "Attempting to bind IPv%d socket to port %d.\n", ip6 ? 6 : 4, port);

  /* Try to use the specified port - if it isn't available, use a random port */
  if (bind(socket, addr, addr_size) != 0) {

    purple_debug_info("bonjour", "Unable to bind to specified "
        "port %i: %s\n", port, g_strerror(errno));

    if (!allow_port_fallback) {
      purple_debug_warning("bonjour", "Not attempting random port assignment.\n");
      return -1;
    }
#ifdef PF_INET6
    if (ip6)
      ((struct sockaddr_in6 *) addr)->sin6_port = 0;
    else
#endif
    ((struct sockaddr_in *) addr)->sin_port = 0;

    if (bind(socket, addr, addr_size) != 0) {
      purple_debug_error("bonjour", "Unable to bind IPv%d socket to port: %s\n", ip6 ? 6 : 4, g_strerror(errno));
      return -1;
    }
    ret_port = purple_network_get_port_from_fd(socket);
  }

  purple_debug_info("bonjour", "Bound IPv%d socket to port %d.\n", ip6 ? 6 : 4, ret_port);

  /* Attempt to listen on the bound socket */
  if (listen(socket, 10) != 0) {
    purple_debug_error("bonjour", "Unable to listen on IPv%d socket: %s\n", ip6 ? 6 : 4, g_strerror(errno));
    return -1;
  }

#if 0
  /* TODO: Why isn't this being used? */
  data->socket = purple_network_listen(jdata->port, SOCK_STREAM);

  if (jdata->socket == -1)
  {
    purple_debug_error("bonjour", "No se ha podido crear el socket\n");
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
    purple_debug_error("bonjour", "Unable to create socket: %s",
        g_strerror(errno));
    return -1;
  }

#ifdef PF_INET6
  if (jdata->socket6 != -1) {
    struct sockaddr_in6 addr6;
#ifdef IPV6_V6ONLY
    int on = 1;
    if (setsockopt(jdata->socket6, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0) {
      purple_debug_error("bonjour", "couldn't force IPv6\n");
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
      purple_debug_error("bonjour", "Failed to start listening on IPv6 socket.\n");
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
      purple_debug_error("bonjour", "Failed to start listening on IPv4 socket.\n");
      close(jdata->socket);
      jdata->socket = -1;
    }
  }

  if (!(ipv6_port > 0 || ipv4_port > 0)) {
    purple_debug_error("bonjour", "Unable to listen on socket: %s",
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
  purple_debug_info("bonjour", "_connected_to_buddy for %s, source=%d, error=%s\n",
                   pb ? purple_buddy_get_name(pb) : "(unknown)",
                   source, error ? error : "(null)");

  if (!pb || !bb || bb->conversation != bconv) {
    purple_debug_warning("bonjour", "Stale proxy-connect callback\n");
    if (source >= 0) close(source);
    bonjour_jabber_close_conversation(bconv);
    return;
  }

  if (source < 0) {
    PurpleConversation *conv = NULL;
    PurpleAccount *account = NULL;
    GSList *tmp = bb->ips;

    purple_debug_error("bonjour", "Error connecting to buddy %s at %s:%d (%s); Trying next IP address\n",
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

      purple_debug_info("bonjour", "Starting conversation with %s at %s:%d (formatted: %s:%d)\n",
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

    purple_debug_error("bonjour", "No more addresses for buddy %s. Aborting", purple_buddy_get_name(pb));

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
      purple_debug_info("bonjour", "Outgoing connection local Yggdrasil IP: %s\n", bconv->local_ip);
    }
  }

  if (!bonjour_jabber_send_stream_init(bconv, source)) {
    const char *err = g_strerror(errno);
    PurpleConversation *conv = NULL;
    PurpleAccount *account = NULL;

    purple_debug_error("bonjour", "Error starting stream with buddy %s at %s:%d error: %s\n",
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
    PurpleBuddy     *pb     = NULL;
    BonjourBuddy    *bb     = NULL;
    BonjourJabber   *jdata  = NULL;
    PurpleAccount   *account;

    g_return_if_fail(bconv != NULL);
    g_return_if_fail(bconv->ip != NULL);

    account = bconv->account;
    if (!account || !account->gc || !account->gc->proto_data) {
        purple_debug_error("bonjour",
                           "conv_match_by_name: missing account or connection\n");
        return;
    }

    jdata = ((BonjourData*) account->gc->proto_data)->jabber_data;
    if (!jdata) {
        purple_debug_error("bonjour",
                           "conv_match_by_name: no jabber_data\n");
        return;
    }

    /* If we have no buddy_name at all, we can only try IP matching. */
    if (!bconv->buddy_name) {
        purple_debug_info("bonjour",
                          "conv_match_by_name: buddy_name is NULL, trying IP match only\n");
        bonjour_jabber_conv_match_by_ip(bconv);
        return;
    }

    pb = purple_find_buddy(account, bconv->buddy_name);

    if (!pb) {
        purple_debug_info("bonjour",
                          "conv_match_by_name: no buddy named '%s'\n",
                          bconv->buddy_name ? bconv->buddy_name : "(null)");

        /* 2) Barev-style fallback: localpart match, but only if UNIQUE. */
        pb = bonjour_find_buddy_by_localpart(account, bconv->buddy_name);

        if (!pb) {
            purple_debug_info("bonjour",
                "conv_match_by_name: no unique buddy named/localpart '%s'; trying IP match for %s\n",
                bconv->buddy_name ? bconv->buddy_name : "(null)",
                bconv->ip ? bconv->ip : "(no ip)");

            /* 3) IP match — preserve buddy_name across the call: conv_match_by_ip
             * clears it internally, but the second validate_ip_consistency below
             * needs it as a JID fallback when the matched buddy is a bare nick. */
            gchar *saved_buddy_name = g_strdup(bconv->buddy_name);
            bonjour_jabber_conv_match_by_ip(bconv);
            if (bconv->buddy_name == NULL)
                bconv->buddy_name = saved_buddy_name;
            else
                g_free(saved_buddy_name);
            if (bconv->closing || bconv->close_timeout != 0)
                return;
            pb = bconv->pb;
        }
    }

    /* If still nothing, we cannot attach this conversation. */
    if (!pb) {
        purple_debug_warning("bonjour",
            "conv_match_by_name: unable to match conversation (buddy_name='%s', ip='%s')\n",
            bconv->buddy_name ? bconv->buddy_name : "(null)",
            bconv->ip ? bconv->ip : "(no ip)");
        return;
    }

    /* Attach the buddy to this conversation (whatever your code does next). */
    bconv->pb = pb;

    /* We have a PurpleBuddy – get its BonjourBuddy data. */
    bb = purple_buddy_get_protocol_data(pb);
    if (!bb) {
        purple_debug_warning("bonjour",
                             "conv_match_by_name: buddy '%s' has no protocol data; trying IP match\n",
                             purple_buddy_get_name(pb));

        /* Fall back to IP match */
        gchar *saved_buddy_name2 = g_strdup(bconv->buddy_name);
        bonjour_jabber_conv_match_by_ip(bconv);
        if (bconv->buddy_name == NULL)
            bconv->buddy_name = saved_buddy_name2;
        else
            g_free(saved_buddy_name2);
        if (bconv->closing || bconv->close_timeout != 0)
            return;
        pb = bconv->pb;

        if (!pb) {
            purple_debug_warning("bonjour",
                                 "conv_match_by_name: IP match failed after missing protocol data\n");
            return;
        }

        bb = purple_buddy_get_protocol_data(pb);
        if (!bb) {
            purple_debug_warning("bonjour",
                                 "conv_match_by_name: IP-matched buddy '%s' still has no protocol data\n",
                                 purple_buddy_get_name(pb));
            return;
        }

        /* Ensure conversation points at the new pb */
        bconv->pb = pb;
    }


    purple_debug_info("bonjour",
                      "Matched buddy %s to incoming conversation \"from\" attrib "
                      "(buddy_name=%s, conv IP=%s)\n",
                      purple_buddy_get_name(pb),
                      bconv->buddy_name ? bconv->buddy_name : "(null)",
                      bconv->ip ? bconv->ip : "(null)");

    bconv->pb = pb;

    /* Validate the candidate before disturbing an already working stream.
     * If the buddy is stored as a bare nick (no '@'), the buddy name has no IP
     * to check against; use the stream's from-JID instead, which carries the
     * peer's claimed IP that getpeername() will verify.
     *
     * Exception: when the buddy was added with a hostname JID (e.g.
     * "inky@lovelace") and bb->ips is still empty, validate_ip_consistency
     * would extract "lovelace" as the expected IP and reject the real Yggdrasil
     * peer address.  Skip the check in that case — the IP-learning block below
     * will record the address verified by getpeername() and persist it. */
    {
      const char *jid_for_validation = purple_buddy_get_name(pb);
      if (!strchr(jid_for_validation, '@'))
          jid_for_validation = bconv->buddy_name;

      gboolean skip_ip_check = FALSE;
      bb = purple_buddy_get_protocol_data(pb);
      if (bb && !bb->ips) {
        const char *at = strchr(jid_for_validation, '@');
        if (at) {
          struct in6_addr dummy;
          if (inet_pton(AF_INET6, at + 1, &dummy) != 1)
            skip_ip_check = TRUE;
        }
      }

      if (skip_ip_check) {
        purple_debug_info("bonjour",
            "conv_match_by_name: skipping IP validation for hostname buddy '%s'"
            " with no known IPs — will learn IP from this connection\n",
            purple_buddy_get_name(pb));
      } else if (!validate_ip_consistency(bconv, jid_for_validation)) {
        purple_debug_error("bonjour",
          "Closing connection due to IP mismatch for %s\n",
          purple_buddy_get_name(pb));
        async_bonjour_jabber_close_conversation(bconv);
        return;
      }
    }

    /* If the buddy had no known IPs (bare-nick or hostname entry), learn this
     * IP now that the connection has been accepted. */
    bb = purple_buddy_get_protocol_data(pb);
    if (bb && !bb->ips && bconv->ip) {
        bb->ips = g_slist_append(NULL, g_strdup(bconv->ip));
        bonjour_buddy_save_to_blist(pb, bconv->ip,
            bb->port_p2pj > 0 ? bb->port_p2pj : BONJOUR_DEFAULT_PORT);
        purple_debug_info("bonjour",
            "Learned IP %s for buddy %s from verified connection\n",
            bconv->ip, purple_buddy_get_name(pb));
        /* Persist immediately so the IP survives an unclean shutdown */
        barev_save_persistent_contacts(bconv->account);
    }

    if (bb->conversation != NULL && bb->conversation != bconv) {
      BonjourJabberConversation *existing = bb->conversation;

      if (!bonjour_candidate_wins_collision(pb, existing, bconv)) {
        purple_debug_info("bonjour",
            "Keeping existing %s connection for %s; rejecting duplicate %s connection\n",
            existing->incoming ? "incoming" : "outgoing",
            purple_buddy_get_name(pb),
            bconv->incoming ? "incoming" : "outgoing");
        async_bonjour_jabber_close_conversation(bconv);
        return;
      }

      purple_debug_info("bonjour",
          "Replacing existing %s connection for %s with deterministic %s winner\n",
          existing->incoming ? "incoming" : "outgoing",
          purple_buddy_get_name(pb),
          bconv->incoming ? "incoming" : "outgoing");
      bonjour_jabber_close_conversation(existing);
    }

    /* Attach conv. to buddy and remove from pending list */
    jdata->pending_conversations =
        g_slist_remove(jdata->pending_conversations, bconv);
    bb->conversation = bconv;

    purple_debug_info("bonjour", "Setting bb->conversation for %s to %p\n",
                  purple_buddy_get_name(pb), bconv);

    /* Normalize buddy_name to the canonical buddy name, e.g. "inky@201:..." */
    if (bconv->buddy_name) {
        g_free(bconv->buddy_name);
    }
    bconv->buddy_name = g_strdup(purple_buddy_get_name(pb));

    purple_debug_info("bonjour",
                      "conv_match_by_name: matched conversation to buddy '%s'\n",
                      bconv->buddy_name);
}



void bonjour_jabber_conv_match_by_ip(BonjourJabberConversation *bconv) {
  BonjourJabber *jdata = ((BonjourData*) bconv->account->gc->proto_data)->jabber_data;
  struct _match_buddies_by_address_t *mbba;
  GSList *buddies;

  /* This routine is a fallback matcher.  Do not leave a previous tentative
   * association in place if every IP candidate is rejected. */
  bconv->pb = NULL;

  /* Normalize IPv6 address if needed */
  if (bconv->ip && strchr(bconv->ip, ':')) {
    /* This is an IPv6 address - normalize it */
    char normalized_ip[INET6_ADDRSTRLEN];
    struct in6_addr addr6;

    if (inet_pton(AF_INET6, bconv->ip, &addr6) == 1) {
      if (inet_ntop(AF_INET6, &addr6, normalized_ip, sizeof(normalized_ip))) {
        /* Update the IP to normalized form */
        g_free(bconv->ip);
        bconv->ip = g_strdup(normalized_ip);
        purple_debug_info("bonjour", "Normalized IPv6 address to: %s\n", bconv->ip);
      }
    }
  }

  purple_debug_info("bonjour", "Trying to match buddy by IP: %s\n", bconv->ip);

  mbba = g_new0(struct _match_buddies_by_address_t, 1);
  mbba->address = bconv->ip;

  buddies = purple_find_buddies(jdata->account, NULL);
  g_slist_foreach(buddies, _match_buddies_by_address, mbba);
  g_slist_free(buddies);

  /* We've failed to match a buddy - give up */
  if (mbba->matched_buddies == NULL) {
    purple_debug_warning("bonjour", "Failed to match buddy by IP %s - keeping connection open for stream negotiation\n", bconv->ip);
    g_free(mbba);

    /* Don't close the connection yet - wait for stream header */
    /* The buddy might be identified by the 'from' attribute in the stream */
    return;
  }

  /* We've found our buddy */
  GSList *buddies_in = mbba->matched_buddies;
  while(buddies_in) {
    PurpleBuddy *pb = buddies_in->data;
    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);

    purple_debug_info("bonjour", "Matched buddy %s to incoming connection from %s\n",
      purple_buddy_get_name(pb), bconv->ip);

    /* Check that we're not connecting to ourselves */
    if (purple_strequal(purple_account_get_username(pb->account), pb->name)) {
      purple_debug_info("bonjour", "We don't want to talk to ourselves\n");
      /* We can't delete the bconv here, but we can unassociate ourselves from it */
      bconv->pb = NULL;
      g_slist_free(mbba->matched_buddies);
      g_free(mbba);
      return;
    }

   if (bconv->buddy_name &&
        PURPLE_BLIST_NODE_SHOULD_SAVE((PurpleBlistNode *)pb) &&
        !purple_strequal(bconv->buddy_name, purple_buddy_get_name(pb))) {
      /* Allow bare-nick buddies (Haze strips @ip during roster sync) to match
       * a full JID stream-from when the localpart is the same — the IP match
       * already confirmed which endpoint we are talking to. */
      const char *pb_name = purple_buddy_get_name(pb);
      const char *at = strchr(bconv->buddy_name, '@');
      gboolean localpart_ok = (!strchr(pb_name, '@') && at &&
                               (gsize)(at - bconv->buddy_name) == strlen(pb_name) &&
                               strncmp(bconv->buddy_name, pb_name, strlen(pb_name)) == 0);
      if (!localpart_ok) {
        purple_debug_warning("barev",
            "Buddy %s is manually saved but remote claims to be '%s' (IP %s) - "
            "rejecting IP-only match (name mismatch)\n",
            pb_name, bconv->buddy_name, bconv->ip);
        buddies_in = buddies_in->next;
        continue;
      }
      purple_debug_info("bonjour",
          "Bare-nick buddy '%s' accepting stream from '%s' by localpart (IP already verified)\n",
          pb_name, bconv->buddy_name);
    }

    g_free(bconv->buddy_name);
    bconv->buddy_name = NULL;

    bconv->pb = pb;

    if (!validate_ip_consistency(bconv, purple_buddy_get_name(pb))) {
      purple_debug_error("bonjour",
        "Closing connection due to IP mismatch for %s\n",
        purple_buddy_get_name(pb));
      async_bonjour_jabber_close_conversation(bconv);
      g_slist_free(mbba->matched_buddies);
      g_free(mbba);
      return;
    }

    if (bb->conversation != NULL && bb->conversation != bconv) {
      BonjourJabberConversation *existing = bb->conversation;

      if (!bonjour_candidate_wins_collision(pb, existing, bconv)) {
        purple_debug_info("bonjour",
            "Keeping existing %s connection for %s; rejecting duplicate %s connection\n",
            existing->incoming ? "incoming" : "outgoing",
            purple_buddy_get_name(pb),
            bconv->incoming ? "incoming" : "outgoing");
        async_bonjour_jabber_close_conversation(bconv);
        g_slist_free(mbba->matched_buddies);
        g_free(mbba);
        return;
      }

      purple_debug_info("bonjour",
          "Replacing existing %s connection for %s with deterministic %s winner\n",
          existing->incoming ? "incoming" : "outgoing",
          purple_buddy_get_name(pb),
          bconv->incoming ? "incoming" : "outgoing");
      bonjour_jabber_close_conversation(existing);
    }

    bb->conversation = bconv;
    purple_debug_info("bonjour", "Setting bb->conversation for %s to %p\n",
                  purple_buddy_get_name(pb), bconv);

    /* Break because we only want to match one buddy */
    break;
  }

  if (bconv->pb == NULL) {
    purple_debug_warning("barev",
        "All IP-matched buddies for %s were rejected (likely name mismatches) - "
        "connection remains unassociated\n", bconv->ip);
  }


  g_slist_free(mbba->matched_buddies);
  g_free(mbba);

  /* Only an associated conversation leaves the pending set.  Otherwise keep
   * it there so shutdown/EOF cleanup still owns it. */
  if (bconv->pb != NULL && jdata->pending_conversations) {
    jdata->pending_conversations = g_slist_remove(jdata->pending_conversations, bconv);
  }

  /* We've associated the conversation with a buddy.  Yay! */
  /* If the stream has been completely started and we know who we're talking to, we can start doing stuff. */
  /* I don't think the circ_buffer can actually contain anything without a buddy being associated, but lets be explicit. */
  if (bconv->sent_stream_start == FULLY_SENT && bconv->recv_stream_start && bconv->pb != NULL
      && purple_circ_buffer_get_max_read(bconv->tx_buf) > 0) {
    /* Watch for when we can write the buffered messages */
    bconv->tx_handler = purple_input_add(bconv->socket, PURPLE_INPUT_WRITE,
      _send_data_write_cb, bconv);
    /* We can probably write the data right now. */
    _send_data_write_cb(bconv, bconv->socket, PURPLE_INPUT_WRITE);
  }

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
        purple_debug_warning("bonjour",
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
        purple_debug_error("bonjour", "Direct connection to %s failed: %s\n",
                         purple_buddy_get_name(pb), g_strerror(error));
        bonjour_jabber_close_conversation(bconv);
        return;
    }

    /* Connection successful! */
    purple_debug_info("bonjour",
                     "Direct connection to %s established (conversation=%p fd=%d)\n",
                     purple_buddy_get_name(pb), bconv, socket);

    {
        gchar *ygg_ip = get_local_yggdrasil_ip(socket);
        if (ygg_ip) {
            g_free(bconv->local_ip);
            bconv->local_ip = ygg_ip;
            purple_debug_info("bonjour", "Direct connection local Yggdrasil IP: %s\n", bconv->local_ip);
        }
    }

    /* Set up read handler */
    bconv->rx_handler = purple_input_add(socket, PURPLE_INPUT_READ,
                                         _client_socket_handler, bconv);

    /* Send stream init */
    if (!bonjour_jabber_send_stream_init(bconv, socket)) {
        purple_debug_error("bonjour", "Failed to send stream init\n");
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
     purple_debug_info("bonjour", "Creating new conversation for %s (was NULL)\n", to);
    const char *ip = bb->ips->data; /* Start with the first IP address. */

    purple_debug_info("bonjour", "Starting conversation with %s at %s:%d\n", to, ip, bb->port_p2pj);

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
                                purple_debug_warning("bonjour",
                                    "Failed to bind to %s: %s (continuing anyway)\n",
                                    my_ip, g_strerror(errno));
                            } else {
                                purple_debug_info("bonjour", "Bound socket to %s\n", my_ip);
                            }
                        } else {
                            purple_debug_warning("bonjour",
                                "Could not parse our own IP %s for binding\n", my_ip);
                        }
                    }
                }

                if (connect(sock, (struct sockaddr*)&addr6, sizeof(addr6)) == 0 ||
                    (errno == EINPROGRESS)) {
                    /* Connection successful or in progress */
                    BonjourJabberConversation *bconv;

                    bconv = bonjour_jabber_conv_new(pb, jdata->account, ip);
                    bconv->remote_port = bb->port_p2pj;
                    bb->conversation = bconv;
                    purple_debug_info("bonjour", "Setting bb->conversation for %s to %p\n",
                                      purple_buddy_get_name(pb), bconv);
                    bconv->socket = sock;

                    /* Set up handler for when connection completes */
                    bconv->connect_handler = purple_input_add(sock, PURPLE_INPUT_WRITE,
                                                              _connected_to_buddy_direct, bconv);

                    purple_debug_info("bonjour", "Direct IPv6 connection to %s:%d\n",
                                     ip, bb->port_p2pj);
                    return pb;
                } else {
                    purple_debug_error("bonjour", "connect() failed: %s\n", g_strerror(errno));
                    close(sock);
                }
            } else {
                purple_debug_error("bonjour", "inet_pton failed for IPv6: %s\n", ip);
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

    purple_debug_info("bonjour", "Using proxy_connect with host: %s, port: %d\n",
                     host_for_connect, bb->port_p2pj);

    BonjourJabberConversation *bconv;

    bconv = bonjour_jabber_conv_new(pb, jdata->account, ip);
    bconv->ip_link = ip;
    bconv->remote_port = bb->port_p2pj;
    bb->conversation = bconv;

    connect_data = purple_proxy_connect(
                purple_account_get_connection(jdata->account),
                jdata->account,
                host_for_connect, bb->port_p2pj, _connected_to_buddy, bconv);

    g_free(host_for_connect);

    if (connect_data == NULL) {
      purple_debug_error("bonjour", "Unable to connect to buddy (%s).\n", to);
      bonjour_jabber_close_conversation(bconv);
      return NULL;
    }

    purple_debug_info("bonjour", "Setting bb->conversation for %s to %p\n",
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
        purple_debug_info("bonjour",
                          "Can't send a message to an offline buddy (%s).\n", to);
        /* You can not send a message to an offline buddy */
        return -10000;
    }

    /* Barev auto-connect and similar callers may pass an empty body.
     * In that case, just ensure the stream/connection exists and return.
     */
    if (body == NULL || *body == '\0') {
        purple_debug_info("bonjour",
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
        purple_debug_info("bonjour",
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
        purple_debug_warning("bonjour",
                             "Converted message for %s is empty; not sending.\n",
                             to);
        return 0;
    }

    message_node = xmlnode_new("message");
    xmlnode_set_attrib(message_node, "to", bb->name ? bb->name : "");

    /* Ensure we never pass NULL to xmlnode_set_attrib */
    const char *from = bonjour_get_jid(jdata->account);
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

    message = xmlnode_to_str(message_node, NULL);
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
  purple_debug_info("bonjour",
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

  bconv->closing = TRUE;

  purple_debug_info("bonjour",
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
    if (was_current)
      bb->conversation = NULL;

    if (was_current && bconv->account && bconv->account->gc &&
        PURPLE_CONNECTION_IS_VALID(bconv->account->gc)) {
      purple_prpl_got_user_status(bconv->account,
                                  purple_buddy_get_name(pb),
                                  BONJOUR_STATUS_ID_OFFLINE,
                                  NULL);
    }
  }

  /* Cancel file transfers which have not started yet. */
  if (pb && bd) {
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
        purple_debug_info("bonjour",
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

  g_free(bconv->buddy_name);
  g_free(bconv->ip);
  g_free(bconv->local_ip);
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
    bonjour_jabber_close_conversation(jdata->pending_conversations->data);
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

  /* start the talk, reuse the message socket  */
  pb = _find_or_start_conversation((BonjourJabber*) iq->data, iq->to);
  /* Send the message */
  if (pb != NULL) {
    /* Convert xml node into stream */
    gchar *msg = xmlnode_to_str(iq->node, NULL);
    ret = _send_data(pb, msg);
    g_free(msg);
  }

  xmlnode_free(iq->node);
  iq->node = NULL;
  g_free(iq);

  return (ret >= 0) ? 0 : -1;
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
        purple_debug_error("bonjour",
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
            purple_debug_info("bonjour",
                              "Barev: skipping local IPv6 %s on %s\n",
                              host,
                              ifa->ifa_name ? ifa->ifa_name : "?");
            continue;
        }

        /* Now only keep Yggdrasil-style globals (e.g. 201:..., 304:..., etc.)
         * and drop normal global IPv6 like 2001:xxxx:... */
        if (!is_yggdrasil_addr(host)) {
            purple_debug_info("bonjour",
                              "Barev: skipping non-Yggdrasil global IPv6 %s on %s\n",
                              host,
                              ifa->ifa_name ? ifa->ifa_name : "?");
            continue;
        }

        purple_debug_info("bonjour",
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
  xmlnode_set_attrib(iq, "from", bonjour_get_jid(bconv->account));
  xmlnode_set_attrib(iq, "to", purple_buddy_get_name(bconv->pb));

  xmlnode *ping = xmlnode_new_child(iq, "ping");
  xmlnode_set_namespace(ping, "urn:xmpp:ping");

  char *xml = xmlnode_to_str(iq, NULL);
  xmlnode_free(iq);

  BonjourBuddy *bb_ping = purple_buddy_get_protocol_data(bconv->pb);
  _send_data(bconv->pb, xml);
  g_free(xml);

  /* _send_data may have freed bconv on a send error; bail out if so */
  if (bb_ping == NULL || bb_ping->conversation != bconv)
    return;

  purple_debug_info("bonjour", "Sent ping to %s (id: %s)\n",
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

      char *xml = xmlnode_to_str(response, NULL);
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

      purple_debug_info("bonjour", "Responded to ping from %s\n",
                       xmlnode_get_attrib(packet, "from"));

      /* Proof of life: if they can ping us, they are online. */
      if (bconv->pb) {
          PurpleAccount *acct = purple_buddy_get_account(bconv->pb);
          const char *who = purple_buddy_get_name(bconv->pb);
          bconv->last_activity = time(NULL);
          bconv->ping_failures = 0;
          bconv->recv_stream_start = TRUE;
          purple_prpl_got_user_status(acct, who, BONJOUR_STATUS_ID_AVAILABLE, NULL);
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

    from = bonjour_get_jid(jdata->account);
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

    xml = xmlnode_to_str(message_node, NULL);
    xmlnode_free(message_node);

    _send_data(pb, xml);
    g_free(xml);
}


