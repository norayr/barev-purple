/*
 * purple - Barev Protocol Plugin
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
#include <glib.h>
#ifndef _WIN32
#include <pwd.h>
#else
#define UNICODE
#include <winsock2.h>
#include <windows.h>
#include <lm.h>
#endif

#include "internal.h"

#include <account.h>
#include <accountopt.h>
#include <debug.h>
#include <util.h>
#include <version.h>

#include "bonjour.h"
#include "jabber.h"
#include "buddy.h"
#include "bonjour_ft.h"

#include <request.h> //for purple_request_fields
#include <blist.h> // for barev
#include <eventloop.h>
#include "libpurple/server.h" //for typing notifications

#include <errno.h>
#include <sys/socket.h>



typedef struct {
  PurpleConnection *pc;
  PurpleBuddy *buddy;
} BarevAddBuddyData;

static void bonjour_set_status(PurpleAccount *account, PurpleStatus *status);
static void bonjour_login(PurpleAccount *account);

static void bonjour_login_barev(PurpleAccount *account);

static void bonjour_get_info(PurpleConnection *gc, const char *who);

/* Structure for parsing manual buddy format */
typedef struct {
  char *nick;
  char *ipv6_address;
  int port;
} BarevBuddyInfo;

static unsigned int
bonjour_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state)
{
    PurpleAccount *account;
    PurpleBuddy *pb;
    BonjourBuddy *bb;

    if (!gc || !who) return 0;

    account = purple_connection_get_account(gc);
    pb = purple_find_buddy(account, who);
    if (!pb) return 0;

    bb = purple_buddy_get_protocol_data(pb);
    if (!bb) return 0;

    /* Send a pure chat-state message (no body) */
    bonjour_jabber_send_typing(pb, state);

    /* libpurple expects “how long until you consider it stale” */
    return BAREV_CHATSTATE_TIMEOUT_SECONDS;
}

/* Helper function to check if a socket is really connected */
static gboolean
is_socket_really_connected(int socket_fd)
{
    int error = 0;
    socklen_t len = sizeof(error);

    if (socket_fd < 0)
        return FALSE;

    /* Check for pending socket errors */
    if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0) {
        return FALSE; /* getsockopt itself failed */
    }

    if (error != 0) {
        /* Socket has an error, consider it dead */
        errno = error;
        return FALSE;
    }

    /* Try to peek a byte */
    char buf;
    int result = recv(socket_fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);

    /*
     * recv() semantics:
     *   > 0 : there is data -> definitely alive
     *   == 0: orderly shutdown (EOF) -> closed
     *   < 0 : error; EAGAIN/EWOULDBLOCK means "no data now" but socket OK
     */
    if (result > 0)
        return TRUE;

    if (result == 0)
        return FALSE; /* closed by peer */

    /* result < 0 */
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return TRUE;  /* no data yet, but socket is fine */

    return FALSE;      /* real error */
}

/* Parse buddy string in format: nick@ipv6_address */
static BarevBuddyInfo *
parse_barev_buddy_string(const char *buddy_str)
{
  BarevBuddyInfo *info;
  char *at_sign;
  char *str_copy;
  char *colon_pos;
  char *percent_pos;

  if (!buddy_str || strlen(buddy_str) == 0) {
    purple_debug_error("bonjour", "Empty buddy string\n");
    return NULL;
  }

  /* Check for minimum length - at least "a@b" */
  if (strlen(buddy_str) < 3) {
    purple_debug_error("bonjour", "Buddy string too short: '%s'\n", buddy_str);
    return NULL;
  }

  info = g_new0(BarevBuddyInfo, 1);
  str_copy = g_strdup(buddy_str);

  /* Look for @ separator - REQUIRED for Barev buddies */
  at_sign = strchr(str_copy, '@');
  if (!at_sign) {
    purple_debug_error("bonjour", "Invalid Barev buddy format '%s' - must be nick@ipv6\n", buddy_str);
    g_free(info);
    g_free(str_copy);
    return NULL;
  }

  /* Check that @ is not at the beginning or end */
  if (at_sign == str_copy || *(at_sign + 1) == '\0') {
    purple_debug_error("bonjour", "Invalid Barev buddy format '%s' - @ at wrong position\n", buddy_str);
    g_free(info);
    g_free(str_copy);
    return NULL;
  }

  /* Extract nick */
  *at_sign = '\0';
  info->nick = g_strdup(str_copy);

  /* Validate nick is not empty */
  if (!info->nick || strlen(info->nick) == 0) {
    purple_debug_error("bonjour", "Invalid Barev buddy format '%s' - empty nickname\n", buddy_str);
    g_free(info->nick);
    g_free(info);
    g_free(str_copy);
    return NULL;
  }

  /* Extract IPv6 address */
  char *ipv6_start = at_sign + 1;
  info->ipv6_address = g_strdup(ipv6_start);
  info->port = BONJOUR_DEFAULT_PORT; /* Default port */

  /* Validate IPv6 is not empty */
  if (!info->ipv6_address || strlen(info->ipv6_address) == 0) {
    purple_debug_error("bonjour", "Invalid Barev buddy format '%s' - empty IPv6 address\n", buddy_str);
    g_free(info->nick);
    g_free(info->ipv6_address);
    g_free(info);
    g_free(str_copy);
    return NULL;
  }

  /* Check for IPv6 scope identifier (after %) */
  percent_pos = strchr(info->ipv6_address, '%');
  if (percent_pos) {
    /* Has scope ID, port would be after another colon if present */
    colon_pos = strrchr(info->ipv6_address, ':');
    if (colon_pos && colon_pos > percent_pos) {
      /* Port specified after scope ID, like 2001:db8::1%eth0:5299 */
      char *port_str = colon_pos + 1;
      if (*port_str != '\0') {
        info->port = atoi(port_str);
        *colon_pos = '\0'; /* Remove port from IP string */
      }
    }
  } else {
    /* No scope ID, check for port at the end (last colon after the last colon in IPv6) */
    /* This is tricky because IPv6 has colons. We'll look for pattern: ]:port or :port after double colon */
    if (info->ipv6_address[0] == '[') {
      /* Bracketed IPv6: [2001:db8::1]:5299 */
      char *bracket_end = strchr(info->ipv6_address, ']');
      if (bracket_end && *(bracket_end + 1) == ':') {
        char *port_str = bracket_end + 2;
        if (*port_str != '\0') {
          info->port = atoi(port_str);
          *(bracket_end + 1) = '\0'; /* Remove :port */
          /* Also remove the closing bracket */
          *bracket_end = '\0';
        }
      }
    } else {
      /* Simple IPv6, look for pattern after last colon that's not part of IPv6 */
      /* For simplicity, we'll assume no port specification without brackets for now */
    }
  }

  purple_debug_info("bonjour", "Parsed Barev buddy: nick=%s, ipv6=%s, port=%d\n",
    info->nick, info->ipv6_address, info->port);

  g_free(str_copy);
  return info;
}

static gboolean
barev_auto_connect_timer(gpointer data)
{
  PurpleConnection *gc = data;
  BonjourData *bd;
  GSList *buddies;

  if (!gc)
    return FALSE;

  bd = gc->proto_data;

  if (!PURPLE_CONNECTION_IS_CONNECTED(gc) || !bd || !bd->jabber_data)
    return FALSE;

  purple_debug_info("bonjour", "Barev: auto-connecting to buddies\n");

  buddies = purple_find_buddies(gc->account, NULL);
  for (GSList *l = buddies; l; l = l->next) {
    PurpleBuddy *pb = l->data;
    BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
    const char *who = purple_buddy_get_name(pb);

    if (!bb) {
      purple_debug_info("bonjour", "Barev: buddy %s has no protocol data\n",
                        who ? who : "(null)");
      continue;
    }

    if (!bb->ips || !bb->ips->data) {
      purple_debug_info("bonjour", "Barev: buddy %s has no IP addresses\n",
                        who ? who : "(null)");
      continue;
    }

    if (bb->conversation) {
      BonjourJabberConversation *bconv = bb->conversation;

      /*
       * Don't claim "really connected" if the XMPP stream has never started.
       * That means connect() may still be in progress, or the peer never answered.
       */
      if (!bconv->recv_stream_start) {
        purple_debug_info("bonjour",
                          "Barev: buddy %s has pending conversation (no stream yet), not treating as connected\n",
                          who ? who : "(null)");
        continue;
      }

      if (bconv->socket >= 0 && is_socket_really_connected(bconv->socket)) {
        purple_debug_info("bonjour",
                          "Barev: buddy %s really connected\n",
                          who ? who : "(null)");
        continue;
      }

      /* Socket or stream is dead – clean up and let the loop reconnect */
      purple_debug_info("bonjour",
                        "Barev: buddy %s has DEAD connection, cleaning\n",
                        who ? who : "(null)");

      if (bconv->socket >= 0) {
        close(bconv->socket);
        bconv->socket = -1;
      }

      bonjour_jabber_close_conversation(bconv);
      bb->conversation = NULL;
    }

    purple_debug_info("bonjour", "Barev: attempting connection to %s at %s\n",
                      who ? who : "(null)", (char *)bb->ips->data);

    /* Just ensure a stream/connection exists */
    bonjour_jabber_open_stream(bd->jabber_data, purple_buddy_get_name(pb));
  }

  g_slist_free(buddies);
  return TRUE;
}

static gchar *
barev_contacts_filename(PurpleAccount *account)
{
  /* This small helper is only intended for the migration functions below */
  /* to migrate from ~/.purple/barev-contacts-<username>.txt to just blist.xml */
  /* Once the migration is done, we may consider removing these functions */
  return g_strdup_printf("%s" G_DIR_SEPARATOR_S "barev-contacts-%s.txt",
                         purple_user_dir(),
                         purple_account_get_username(account));
}

/**
 * One-time migration: if the legacy flat contacts file still exists, read
 * every entry, create or locate the corresponding PurpleBuddy, persist its
 * IP and port via bonjour_buddy_save_to_blist(), and then delete the flat
 * file.  On all subsequent logins the file is gone so the function returns
 * immediately.
 */
static void
barev_migrate_flat_file_to_blist(PurpleAccount *account)
{
    gchar   *filename, *contents = NULL;
    gsize    len = 0;
    char   **lines;
    guint    i;
    PurpleGroup *group;

    filename = barev_contacts_filename(account);

    if (!g_file_get_contents(filename, &contents, &len, NULL)) {
        g_free(filename);
        return;   /* Nothing to migrate */
    }

    purple_debug_info("bonjour", "Migrating %s to blist.xml\n", filename);

    /* Ensure the destination group exists */
    group = purple_find_group(BONJOUR_GROUP_NAME);
    if (!group) {
        group = purple_group_new(BONJOUR_GROUP_NAME);
        purple_blist_add_group(group, NULL);
    }

    lines = g_strsplit(contents, "\n", 0);
    for (i = 0; lines[i]; i++) {
        char   **parts;
        const char *id_or_name, *ip, *port_str;
        int         port;
        char       *jid   = NULL;
        PurpleBuddy *pb;
        char       *trimmed;

        trimmed = g_strstrip(lines[i]);
        if (!*trimmed || *trimmed == '#')
            continue;

        parts = g_strsplit(trimmed, ",", 3);
        if (!parts[0] || !parts[1]) { g_strfreev(parts); continue; }

        id_or_name = parts[0];
        ip         = parts[1];
        port_str   = parts[2];
        port       = (port_str && *port_str) ? atoi(port_str) : BONJOUR_DEFAULT_PORT;

        /*
         * Old format: "nick@ip , ip , port"   (parts[0] contains '@')
         * New format: "nick    , ip , port"   (parts[0] has no '@')
         */
        if (strchr(id_or_name, '@') != NULL)
            jid = g_strdup(id_or_name);
        else
            jid = g_strdup_printf("%s@%s", id_or_name, ip);

        pb = purple_find_buddy(account, jid);
        if (!pb) {
            const char *at;
            pb = purple_buddy_new(account, jid, NULL);
            purple_blist_add_buddy(pb, NULL, group, NULL);

            /* Set alias to the localpart (nick) */
            at = strchr(jid, '@');
            if (at && at != jid) {
                char *nick = g_strndup(jid, (gsize)(at - jid));
                purple_blist_alias_buddy(pb, nick);
                g_free(nick);
            }
        }

        /* Persist IP + port as blist settings (also clears NO_SAVE) */
        bonjour_buddy_save_to_blist(pb, ip, port);

        purple_debug_info("bonjour", "Migrated contact: %s ip=%s port=%d\n",
                          jid, ip, port);

        g_free(jid);
        g_strfreev(parts);
    }

    g_strfreev(lines);
    g_free(contents);

    /* Remove the old file — migration is done */
    if (remove(filename) != 0)
        purple_debug_warning("bonjour",
            "Could not remove old contacts file %s: %s\n",
            filename, g_strerror(errno));
    else
        purple_debug_info("bonjour", "Migration complete; %s removed\n", filename);

    g_free(filename);
}

static void
barev_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    BonjourBuddy *bb;
    BarevBuddyInfo *info;
    const char *full_buddy_name = purple_buddy_get_name(buddy);

    purple_debug_info("bonjour", "Barev: adding buddy %s\n", full_buddy_name);

    /* Parse buddy string - MUST be in format nick@ipv6 */
    info = parse_barev_buddy_string(full_buddy_name);
    if (!info) {
        purple_debug_error("bonjour", "Failed to parse buddy %s - must be nick@ipv6\n",
                           full_buddy_name);
        purple_notify_error(gc, "Invalid Buddy Format",
                            "Barev buddies must be in format: nick@ipv6_address",
                            full_buddy_name);

        purple_account_remove_buddy(gc->account, buddy, group);
        purple_blist_remove_buddy(buddy);
        return;
    }

    /* Create BonjourBuddy */
    bb = g_new0(BonjourBuddy, 1);

    /* Store full JID-like name in bb->name, so Jabber side uses the same string */
    bb->name    = g_strdup(full_buddy_name);   /* e.g. "inky@201:..." */
    bb->account = gc->account;
    bb->port_p2pj = info->port;

    if (info->ipv6_address) {
        bb->ips = g_slist_append(NULL, g_strdup(info->ipv6_address));
        purple_debug_info("bonjour", "Barev: buddy %s has IPv6: %s\n",
                          info->nick, info->ipv6_address);
    } else {
        purple_debug_error("bonjour", "Barev: buddy %s has no IPv6!\n", info->nick);
        /* If no IPv6, this is also invalid */
        bonjour_buddy_delete(bb);
        g_free(info->nick);
        g_free(info->ipv6_address);
        g_free(info);

        purple_account_remove_buddy(gc->account, buddy, group);
        purple_blist_remove_buddy(buddy);
        return;
    }

    /* Default metadata */
    bb->first  = g_strdup(info->nick);
    bb->last   = g_strdup("");
    bb->status = g_strdup("offline");
    bb->msg    = g_strdup("");

    /* Attach to Purple buddy */
    purple_buddy_set_protocol_data(buddy, bb);

    /* Human-friendly alias: just nick */
    purple_blist_alias_buddy(buddy, info->nick);

    /* Persist contact to blist.xml */
    bonjour_buddy_save_to_blist(buddy, info->ipv6_address, info->port);

    /* Do NOT mark them online here – we only do that when a stream is up */
    purple_prpl_got_user_status(gc->account,
                                full_buddy_name,
                                BONJOUR_STATUS_ID_OFFLINE,
                                NULL);

    g_free(info->nick);
    g_free(info->ipv6_address);
    g_free(info);
}

static char *default_firstname;
static char *default_lastname;

const char *
bonjour_get_jid(PurpleAccount *account)
{
  PurpleConnection *conn = purple_account_get_connection(account);
  BonjourData *bd = conn->proto_data;
  return bd->jid;
}

static void
bonjour_removeallfromlocal(PurpleConnection *conn, PurpleGroup *bonjour_group)
{
  PurpleAccount *account = purple_connection_get_account(conn);
  PurpleBlistNode *cnode, *cnodenext, *bnode, *bnodenext;
  PurpleBuddy *buddy;

  if (bonjour_group == NULL)
    return;

  /* Go through and remove all buddies that belong to this account */
  for (cnode = purple_blist_node_get_first_child((PurpleBlistNode *) bonjour_group); cnode; cnode = cnodenext) {
    cnodenext = purple_blist_node_get_sibling_next(cnode);
    if (!PURPLE_BLIST_NODE_IS_CONTACT(cnode))
      continue;
    for (bnode = purple_blist_node_get_first_child(cnode); bnode; bnode = bnodenext) {
      bnodenext = purple_blist_node_get_sibling_next(bnode);
      if (!PURPLE_BLIST_NODE_IS_BUDDY(bnode))
        continue;
      buddy = (PurpleBuddy *) bnode;
      if (purple_buddy_get_account(buddy) != account)
        continue;
      purple_account_remove_buddy(account, buddy, NULL);
      purple_blist_remove_buddy(buddy);
    }
  }

}

static void
bonjour_login_barev(PurpleAccount *account)
{
  PurpleConnection *gc;
  BonjourData *bd;
  PurpleStatus *status;
  PurplePresence *presence;

  g_return_if_fail(account != NULL);

  gc = purple_account_get_connection(account);
  g_return_if_fail(gc != NULL);

  purple_debug_info("bonjour", "=== BAREV MODE STARTUP ===\n");
  purple_debug_info("bonjour", "Account: %s\n",
                    purple_account_get_username(account));

  bd = g_new0(BonjourData, 1);
  purple_connection_set_protocol_data(gc, bd);

  const char *accname = purple_account_get_username(account);
  if (!accname || !*accname)
      accname = "barev";

  /* Prefer a local IPv6 (e.g. Yggdrasil) as our domain */
  GSList *ips = bonjour_jabber_get_local_ips(-1);
  const char *self_ip = ips ? (const char *)ips->data : NULL;

  if (self_ip && *self_ip) {
      /* nick@ipv6 */
      bd->jid = g_strdup_printf("%s@%s", accname, self_ip);
      purple_debug_info("bonjour", "Our JID: %s\n", bd->jid);
  } else {
      /* Fallback */
      purple_debug_warning("bonjour", "No local IPv6 address found, using fallback\n");
      bd->jid = g_strdup_printf("%s@localhost", accname);
  }

  /* free list from bonjour_jabber_get_local_ips() */
  if (ips) {
      g_slist_free_full(ips, g_free);
  }

  bd->jabber_data = g_new0(BonjourJabber, 1);
  bd->jabber_data->account = account;
  bd->jabber_data->port =
      purple_account_get_int(account, "port", BONJOUR_DEFAULT_PORT);

  if (bonjour_jabber_start(bd->jabber_data) == -1) {
    purple_connection_error_reason(gc,
      PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
      _("Unable to listen for incoming IM connections"));
    g_free(bd->jabber_data);
    g_free(bd->jid);
    g_free(bd);
    return;
  }

  purple_debug_info("bonjour", "Jabber listener started on port %d\n",
                    bd->jabber_data->port);

  /* Set initial presence */
  presence = purple_account_get_presence(account);
  if (!presence) {
      purple_debug_error("bonjour", "No presence for account!\n");
  } else {
      status = purple_presence_get_active_status(presence);
      if (!status) {
          purple_debug_error("bonjour", "No active status!\n");
      }
  }

  purple_connection_set_state(gc, PURPLE_CONNECTED);

  purple_debug_info("bonjour", "=== BAREV MODE READY ===\n");

  /* 1. Migrate flat file → blist.xml (one-time; no-op on subsequent logins) */
  barev_migrate_flat_file_to_blist(account);

  /* 2. Reconstruct protocol data for every saved contact in blist.xml */
  bonjour_buddies_load_from_blist(account);

  /* 3. For any remaining buddies with no protocol_data yet, build bb from name */
  GSList *buddies = purple_find_buddies(account, NULL);
  purple_debug_info("bonjour", "Found %d existing buddies\n",
                    g_slist_length(buddies));

  for (GSList *l = buddies; l; l = l->next) {
    PurpleBuddy *buddy = l->data;
    if (!purple_buddy_get_protocol_data(buddy)) {
      barev_add_buddy(gc, buddy, NULL);
    }
  }
  g_slist_free(buddies);

  /* 4. Start auto-connect timer: keep streams up while reachable */
  bd->reconnect_timer = purple_timeout_add_seconds(30,
                                                   barev_auto_connect_timer,
                                                   gc);
  purple_debug_info("bonjour", "Auto-connect timer started (30s)\n");
}

static void
bonjour_login(PurpleAccount *account)
{
  /* Barev-only build: no mDNS support, always use Barev mode */
  bonjour_login_barev(account);
}

static void
bonjour_close(PurpleConnection *connection)
{
  PurpleGroup *bonjour_group;
  BonjourData *bd = connection->proto_data;

  bonjour_group = purple_find_group(BONJOUR_GROUP_NAME);

  /* Remove all the bonjour buddies */
  bonjour_removeallfromlocal(connection, bonjour_group);

  /* Barev-only: just stop Jabber listener, no mDNS */
  if (bd != NULL && bd->jabber_data != NULL)
  {
    bonjour_jabber_stop(bd->jabber_data);
    g_free(bd->jabber_data);
  }

  if (bd != NULL && bd->reconnect_timer != 0) {
    purple_timeout_remove(bd->reconnect_timer);
    bd->reconnect_timer = 0;
  }

  /* Delete the bonjour group */
  if (bonjour_group != NULL)
    purple_blist_remove_group(bonjour_group);

  /* Cancel any file transfers (unchanged) */
  while (bd != NULL && bd->xfer_lists != NULL)
  {
    GList *lxfer = bd->xfer_lists->data;
    while (lxfer != NULL)
    {
      PurpleXfer *xfer = lxfer->data;
      if (xfer->type == PURPLE_XFER_RECEIVE)
        purple_xfer_cancel_remote(xfer);
      else
        purple_xfer_cancel_local(xfer);
      lxfer = g_list_delete_link(lxfer, lxfer);
    }
    bd->xfer_lists = g_slist_delete_link(bd->xfer_lists, bd->xfer_lists);
  }

  connection->proto_data = NULL;
  g_free(bd);
}

static const char *
bonjour_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
  return BONJOUR_ICON_NAME;
}

static int
bonjour_send_im(PurpleConnection *connection, const char *to, const char *msg, PurpleMessageFlags flags)
{
  if(!to || !msg)
    return 0;

  return bonjour_jabber_send_message(((BonjourData*)(connection->proto_data))->jabber_data, to, msg);
}

static void
bonjour_set_status(PurpleAccount *account, PurpleStatus *status)
{
  PurpleConnection *gc;
  BonjourData *bd;
  const char *message;
  gchar *stripped;
  const char *protocol_id;
  gboolean is_barev = FALSE;

  if (!account)
    return;

  gc = purple_account_get_connection(account);
  if (!gc)
    return;

  bd = gc->proto_data;
  if (!bd)
    return;

  protocol_id = purple_account_get_protocol_id(account);
  if (protocol_id &&
      (strstr(protocol_id, "barev") ||
       strstr(protocol_id, "prpl-barev")))
    is_barev = TRUE;

  message = purple_status_get_attr_string(status, "message");
  if (!message)
    message = "";
  stripped = purple_markup_strip_html(message);

  /* Figure out which logical state we are in */
  PurpleStatusType *stype = purple_status_get_type(status);
  const char *id = stype ? purple_status_type_get_id(stype) : NULL;

  gboolean offline = FALSE;
  const char *show = NULL;          /* XMPP <show> */

  if (id && g_strcmp0(id, BONJOUR_STATUS_ID_OFFLINE) == 0) {
    offline = TRUE;
  } else if (id && g_strcmp0(id, BONJOUR_STATUS_ID_AWAY) == 0) {
    show = "away";
  } else if (id && g_strcmp0(id, BONJOUR_STATUS_ID_BUSY) == 0) {
    show = "dnd";
  } else {
    /* Default: available */
    show = NULL;
  }

  /* Barev: send XMPP-ish presence to peers */
  if (is_barev && bd->jabber_data) {
    GSList *buddies = purple_find_buddies(account, NULL);
    for (GSList *l = buddies; l; l = l->next) {
      PurpleBuddy *pb = l->data;
      BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);

      if (!bb || !bb->conversation)
        continue;

      bonjour_jabber_send_presence(pb, show, stripped, offline);

      /* If going offline, also send stream end */
      if (offline && bb->conversation->socket >= 0) {
        size_t len = strlen(STREAM_END);
        send(bb->conversation->socket, STREAM_END, len, 0);
      }
    }
    g_slist_free(buddies);
  }

  g_free(stripped);
}

static void
bonjour_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
  /* Barev-only build: always use Barev add buddy logic */
  barev_add_buddy(gc, buddy, group);
}

static void bonjour_remove_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group) {
  BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);

  if (bb) {
    purple_debug_info("bonjour", "Removing buddy: %s\n", purple_buddy_get_name(buddy));

    /* Clean up the conversation if it exists */
    if (bb->conversation) {
        bonjour_jabber_close_conversation(bb->conversation);
        bb->conversation = NULL;
    }

    /* Delete the protocol data */
    bonjour_buddy_delete(bb);
    purple_buddy_set_protocol_data(buddy, NULL);
  } else {
    /* Nothing to do — Purple removes the node from blist.xml automatically */
    purple_debug_info("bonjour", "Removing buddy without protocol data: %s\n",
                      purple_buddy_get_name(buddy));
  }
}

static GList *
bonjour_status_types(PurpleAccount *account)
{
  GList *status_types = NULL;
  PurpleStatusType *type;

  g_return_val_if_fail(account != NULL, NULL);

  type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
                       BONJOUR_STATUS_ID_AVAILABLE,
                       NULL, TRUE, TRUE, FALSE,
                       "message", _("Message"),
                       purple_value_new(PURPLE_TYPE_STRING), NULL);
  status_types = g_list_append(status_types, type);

  type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY,
                       BONJOUR_STATUS_ID_AWAY,
                       NULL, TRUE, TRUE, FALSE,
                       "message", _("Message"),
                       purple_value_new(PURPLE_TYPE_STRING), NULL);
  status_types = g_list_append(status_types, type);

  type = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE,
                       BONJOUR_STATUS_ID_BUSY,
                       _("Do Not Disturb"), TRUE, TRUE, FALSE,
                       "message", _("Message"),
                       purple_value_new(PURPLE_TYPE_STRING), NULL);
  status_types = g_list_append(status_types, type);

  type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE,
                   BONJOUR_STATUS_ID_OFFLINE,
                   NULL, TRUE, TRUE, FALSE);
  status_types = g_list_append(status_types, type);

  return status_types;
}

static void
bonjour_convo_closed(PurpleConnection *connection, const char *who)
{
  PurpleBuddy *buddy = purple_find_buddy(connection->account, who);
  BonjourBuddy *bb;

  if (buddy == NULL || (bb = purple_buddy_get_protocol_data(buddy)) == NULL)
  {
    /*
     * This buddy is not in our buddy list, and therefore does not really
     * exist, so we won't have any data about them.
     */
    return;
  }

  bonjour_jabber_close_conversation(bb->conversation);
  bb->conversation = NULL;
}

static void
bonjour_set_buddy_icon(PurpleConnection *conn, PurpleStoredImage *img)
{
    PurpleAccount *account;
    PurpleStatus *status;
    const char *message;
    gchar *stripped;
    gboolean offline = FALSE;
    const char *show = NULL;
    GSList *buddies, *l;

    (void)img;

    if (!conn || !(account = conn->account))
        return;

    status = purple_account_get_active_status(account);
    if (!status)
        return;

    message = purple_status_get_attr_string(status, "message");
    if (!message)
        message = "";

    stripped = purple_markup_strip_html(message);

    /* Same mapping logic as bonjour_set_status() */
    {
        PurpleStatusType *stype = purple_status_get_type(status);
        const char *id = stype ? purple_status_type_get_id(stype) : NULL;

        if (id && g_strcmp0(id, BONJOUR_STATUS_ID_OFFLINE) == 0) {
            offline = TRUE;
        } else if (id && g_strcmp0(id, BONJOUR_STATUS_ID_AWAY) == 0) {
            show = "away";
        } else if (id && g_strcmp0(id, BONJOUR_STATUS_ID_BUSY) == 0) {
            show = "dnd";
        } else {
            show = NULL;
        }
    }

    /* Notify only buddies that currently have an active pipe */
    buddies = purple_find_buddies(account, NULL);
    for (l = buddies; l; l = l->next) {
        PurpleBuddy *pb = (PurpleBuddy *)l->data;
        BonjourBuddy *bb = pb ? purple_buddy_get_protocol_data(pb) : NULL;

        if (bb && bb->conversation) {
            bonjour_jabber_send_presence(pb, show, stripped, offline);
        }
    }
    g_slist_free(buddies);

    g_free(stripped);
}

static char *
bonjour_status_text(PurpleBuddy *buddy)
{
  const PurplePresence *presence;
  const PurpleStatus *status;
  const char *message;
  gchar *ret = NULL;

  presence = purple_buddy_get_presence(buddy);
  status = purple_presence_get_active_status(presence);

  message = purple_status_get_attr_string(status, "message");

  if (message != NULL) {
    ret = g_markup_escape_text(message, -1);
    purple_util_chrreplace(ret, '\n', ' ');
  }

  return ret;
}

static void
bonjour_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
  PurplePresence *presence;
  PurpleStatus *status;
  BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);
  const char *status_description;
  const char *message;

  presence = purple_buddy_get_presence(buddy);
  status = purple_presence_get_active_status(presence);
  message = purple_status_get_attr_string(status, "message");

  if (purple_presence_is_available(presence))
    status_description = purple_status_get_name(status);
  else if (purple_presence_is_idle(presence))
    status_description = _("Idle");
  else
    status_description = purple_status_get_name(status);

  purple_notify_user_info_add_pair(user_info, _("Status"), status_description);
  if (message != NULL)
    purple_notify_user_info_add_pair(user_info, _("Message"), message);

  if (bb == NULL) {
    purple_debug_error("bonjour", "Got tooltip request for a buddy without protocol data.\n");
    return;
  }

  /* Only show first/last name if there is a nickname set (to avoid duplication) */
  if (bb->nick != NULL && *bb->nick != '\0') {
    if (bb->first != NULL && *bb->first != '\0')
      purple_notify_user_info_add_pair(user_info, _("First name"), bb->first);
    if (bb->last != NULL && *bb->last != '\0')
      purple_notify_user_info_add_pair(user_info, _("Last name"), bb->last);
  }

  if (bb->email != NULL && *bb->email != '\0')
    purple_notify_user_info_add_pair(user_info, _("Email"), bb->email);

  if (bb->AIM != NULL && *bb->AIM != '\0')
    purple_notify_user_info_add_pair(user_info, _("AIM Account"), bb->AIM);

  if (bb->jid != NULL && *bb->jid != '\0')
    purple_notify_user_info_add_pair(user_info, _("XMPP Account"), bb->jid);
}

static void
bonjour_do_group_change(PurpleBuddy *buddy, const char *new_group) {
  PurpleBlistNodeFlags oldflags;

  if (buddy == NULL)
    return;

  oldflags = purple_blist_node_get_flags((PurpleBlistNode *)buddy);

  /* If we're moving them out of the bonjour group, make them persistent */
  if (purple_strequal(new_group, BONJOUR_GROUP_NAME))
    purple_blist_node_set_flags((PurpleBlistNode *)buddy, oldflags | PURPLE_BLIST_NODE_FLAG_NO_SAVE);
  else
    purple_blist_node_set_flags((PurpleBlistNode *)buddy, oldflags ^ PURPLE_BLIST_NODE_FLAG_NO_SAVE);

}

static void
bonjour_group_buddy(PurpleConnection *connection, const char *who, const char *old_group, const char *new_group)
{
  PurpleBuddy *buddy = purple_find_buddy(connection->account, who);

  bonjour_do_group_change(buddy, new_group);

}

static void
bonjour_rename_group(PurpleConnection *connection, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
  GList *cur;
  const char *new_group;
  PurpleBuddy *buddy;

  new_group = purple_group_get_name(group);

  for (cur = moved_buddies; cur; cur = cur->next) {
    buddy = cur->data;
    bonjour_do_group_change(buddy, new_group);
  }

}

static gboolean
bonjour_can_receive_file(PurpleConnection *connection, const char *who)
{
  PurpleBuddy *buddy = purple_find_buddy(connection->account, who);

  return (buddy != NULL && purple_buddy_get_protocol_data(buddy) != NULL);
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
  /* These shouldn't happen here because they are allocated in _init() */

  g_free(default_firstname);
  g_free(default_lastname);

  return TRUE;
}

static PurplePlugin *my_protocol = NULL;

static PurplePluginProtocolInfo prpl_info =
{
  OPT_PROTO_NO_PASSWORD,
  NULL,                                                    /* user_splits */
  NULL,                                                    /* protocol_options */
  {"png,gif,jpeg", 0, 0, 96, 96, 65535, PURPLE_ICON_SCALE_DISPLAY}, /* icon_spec */
  bonjour_list_icon,                                       /* list_icon */
  NULL,                                                    /* list_emblem */
  bonjour_status_text,                                     /* status_text */
  bonjour_tooltip_text,                                    /* tooltip_text */
  bonjour_status_types,                                    /* status_types */
  NULL,                                                    /* blist_node_menu */
  NULL,                                                    /* chat_info */
  NULL,                                                    /* chat_info_defaults */
  bonjour_login,                                           /* login */
  bonjour_close,                                           /* close */
  bonjour_send_im,                                         /* send_im */
  NULL,                                                    /* set_info */
  bonjour_send_typing,                                     /* send_typing */
  bonjour_get_info,                                        /* get_info */
  bonjour_set_status,                                      /* set_status */
  NULL,                                                    /* set_idle */
  NULL,                                                    /* change_passwd */
  bonjour_add_buddy,                                       /* add_buddy */
  NULL,                                                    /* add_buddies */
  bonjour_remove_buddy,                                    /* remove_buddy */
  NULL,                                                    /* remove_buddies */
  NULL,                                                    /* add_permit */
  NULL,                                                    /* add_deny */
  NULL,                                                    /* rem_permit */
  NULL,                                                    /* rem_deny */
  NULL,                                                    /* set_permit_deny */
  NULL,                                                    /* join_chat */
  NULL,                                                    /* reject_chat */
  NULL,                                                    /* get_chat_name */
  NULL,                                                    /* chat_invite */
  NULL,                                                    /* chat_leave */
  NULL,                                                    /* chat_whisper */
  NULL,                                                    /* chat_send */
  NULL,                                                    /* keepalive */
  NULL,                                                    /* register_user */
  NULL,                                                    /* get_cb_info */
  NULL,                                                    /* get_cb_away */
  NULL,                                                    /* alias_buddy */
  bonjour_group_buddy,                                     /* group_buddy */
  bonjour_rename_group,                                    /* rename_group */
  NULL,                                                    /* buddy_free */
  bonjour_convo_closed,                                    /* convo_closed */
  NULL,                                                    /* normalize */
  bonjour_set_buddy_icon,                                  /* set_buddy_icon */
  NULL,                                                    /* remove_group */
  NULL,                                                    /* get_cb_real_name */
  NULL,                                                    /* set_chat_topic */
  NULL,                                                    /* find_blist_chat */
  NULL,                                                    /* roomlist_get_list */
  NULL,                                                    /* roomlist_cancel */
  NULL,                                                    /* roomlist_expand_category */
  bonjour_can_receive_file,                                /* can_receive_file */
  bonjour_send_file,                                       /* send_file */
  bonjour_new_xfer,                                        /* new_xfer */
  NULL,                                                    /* offline_message */
  NULL,                                                    /* whiteboard_prpl_ops */
  NULL,                                                    /* send_raw */
  NULL,                                                    /* roomlist_room_serialize */
  NULL,                                                    /* unregister_user */
  NULL,                                                    /* send_attention */
  NULL,                                                    /* get_attention_types */
  sizeof(PurplePluginProtocolInfo),                        /* struct_size */
  NULL,                                                    /* get_account_text_table */
  NULL,                                                    /* initiate_media */
  NULL,                                                    /* get_media_caps */
  NULL,                                                    /* get_moods */
  NULL,                                                    /* set_public_alias */
  NULL,                                                    /* get_public_alias */
  NULL,                                                    /* add_buddy_with_invite */
  NULL,                                                    /* add_buddies_with_invite */
  NULL,                                                    /* get_cb_alias */
  NULL,                                                    /* chat_can_receive_file */
  NULL,                                                    /* chat_send_file */
};

static PurplePluginInfo info =
{
  PURPLE_PLUGIN_MAGIC,
  PURPLE_MAJOR_VERSION,
  PURPLE_MINOR_VERSION,
  PURPLE_PLUGIN_PROTOCOL,                           /**< type           */
  NULL,                                             /**< ui_requirement */
  0,                                                /**< flags          */
  NULL,                                             /**< dependencies   */
  PURPLE_PRIORITY_DEFAULT,                          /**< priority       */

  "prpl-barev",                                     /**< id             */
  "Barev",                                          /**< name           */
  DISPLAY_VERSION,                                  /**< version        */
                                                    /**  summary        */
  N_("Barev Protocol Plugin"),
                                                    /**  description    */
  N_("Barev Protocol Plugin"),
  NULL,                                             /**< author         */
  PURPLE_WEBSITE,                                   /**< homepage       */

  NULL,                                             /**< load           */
  plugin_unload,                                    /**< unload         */
  NULL,                                             /**< destroy        */

  NULL,                                             /**< ui_info        */
  &prpl_info,                                       /**< extra_info     */
  NULL,                                             /**< prefs_info     */
  NULL,

  /* padding */
  NULL,
  NULL,
  NULL,
  NULL
};

#ifdef WIN32
static gboolean
_set_default_name_cb(gpointer data) {
  gchar *fullname = data;
  const char *splitpoint;
  GList *tmp = prpl_info.protocol_options;
  PurpleAccountOption *option;

  if (!fullname) {
    purple_debug_info("bonjour", "Unable to look up First and Last name or Username from system; using defaults.\n");
    return FALSE;
  }

  g_free(default_firstname);
  g_free(default_lastname);

  /* Split the real name into a first and last name */
  splitpoint = strchr(fullname, ' ');
  if (splitpoint != NULL) {
    default_firstname = g_strndup(fullname, splitpoint - fullname);
    default_lastname = g_strdup(&splitpoint[1]);
  } else {
    default_firstname = g_strdup(fullname);
    default_lastname = g_strdup("");
  }
  g_free(fullname);


  for(; tmp != NULL; tmp = tmp->next) {
    option = tmp->data;
    if (purple_strequal("first", purple_account_option_get_setting(option)))
      purple_account_option_set_default_string(option, default_firstname);
    else if (purple_strequal("last", purple_account_option_get_setting(option)))
      purple_account_option_set_default_string(option, default_lastname);
  }

  return FALSE;
}

static gpointer
_win32_name_lookup_thread(gpointer data) {
  gchar *fullname = NULL;
  wchar_t username[UNLEN + 1];
  DWORD dwLenUsername = UNLEN + 1;

  GetUserNameW((LPWSTR) &username, &dwLenUsername);

  if (username != NULL && *username != '\0') {
    LPBYTE servername = NULL;
    LPBYTE info = NULL;

    NetGetDCName(NULL, NULL, &servername);

    /* purple_debug_info("bonjour", "Looking up the full name from the %s.\n", (servername ? "domain controller" : "local machine")); */

    if (NetUserGetInfo((LPCWSTR) servername, username, 10, &info) == NERR_Success
        && info != NULL && ((LPUSER_INFO_10) info)->usri10_full_name != NULL
        && *(((LPUSER_INFO_10) info)->usri10_full_name) != '\0') {
      fullname = g_utf16_to_utf8(
        ((LPUSER_INFO_10) info)->usri10_full_name,
        -1, NULL, NULL, NULL);
    }
    /* Fall back to the local machine if we didn't get the full name from the domain controller */
    else if (servername != NULL) {
      /* purple_debug_info("bonjour", "Looking up the full name from the local machine"); */

      if (info != NULL) NetApiBufferFree(info);
      info = NULL;

      if (NetUserGetInfo(NULL, username, 10, &info) == NERR_Success
          && info != NULL && ((LPUSER_INFO_10) info)->usri10_full_name != NULL
          && *(((LPUSER_INFO_10) info)->usri10_full_name) != '\0') {
        fullname = g_utf16_to_utf8(
          ((LPUSER_INFO_10) info)->usri10_full_name,
          -1, NULL, NULL, NULL);
      }
    }

    if (info != NULL) NetApiBufferFree(info);
    if (servername != NULL) NetApiBufferFree(servername);

    if (!fullname)
      fullname = g_utf16_to_utf8(username, -1, NULL, NULL, NULL);
  }

  purple_timeout_add(0, _set_default_name_cb, fullname);

  return NULL;
}
#endif

static void
initialize_default_account_values(void)
{
#ifndef _WIN32
  struct passwd *info;
#endif
  const char *fullname = NULL, *splitpoint, *tmp;
  gchar *conv = NULL;

#ifndef _WIN32
  /* Try to figure out the user's real name */
  info = getpwuid(getuid());
  if ((info != NULL) && (info->pw_gecos != NULL) && (info->pw_gecos[0] != '\0'))
    fullname = info->pw_gecos;
  else if ((info != NULL) && (info->pw_name != NULL) && (info->pw_name[0] != '\0'))
    fullname = info->pw_name;
  else if (((fullname = getlogin()) != NULL) && (fullname[0] == '\0'))
    fullname = NULL;
#else
  /* The Win32 username lookup functions are synchronous so we do it in a thread */
  g_thread_create(_win32_name_lookup_thread, NULL, FALSE, NULL);
#endif

  /* Make sure fullname is valid UTF-8.  If not, try to convert it. */
  if (fullname != NULL && !g_utf8_validate(fullname, -1, NULL)) {
    fullname = conv = g_locale_to_utf8(fullname, -1, NULL, NULL, NULL);
    if (conv == NULL || *conv == '\0')
      fullname = NULL;
  }

  if (fullname == NULL)
    fullname = _("Purple Person");

  /* Split the real name into a first and last name */
  splitpoint = strchr(fullname, ' ');
  if (splitpoint != NULL) {
    default_firstname = g_strndup(fullname, splitpoint - fullname);
    tmp = &splitpoint[1];

    /* The last name may be followed by a comma and additional data.
     * Only use the last name itself.
     */
    splitpoint = strchr(tmp, ',');
    if (splitpoint != NULL)
      default_lastname = g_strndup(tmp, splitpoint - tmp);
    else
      default_lastname = g_strdup(tmp);
  } else {
    default_firstname = g_strdup(fullname);
    default_lastname = g_strdup("");
  }

  g_free(conv);
}

static void
init_plugin(PurplePlugin *plugin)
{
  PurpleAccountOption *option;

  initialize_default_account_values();

  /* Creating the options for the protocol */
  option = purple_account_option_int_new(_("Local Port"), "port", BONJOUR_DEFAULT_PORT);
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

  option = purple_account_option_string_new(_("First name"), "first", default_firstname);
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

  option = purple_account_option_string_new(_("Last name"), "last", default_lastname);
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

  option = purple_account_option_string_new(_("Email"), "email", "");
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

  option = purple_account_option_string_new(_("AIM Account"), "AIM", "");
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

  option = purple_account_option_string_new(_("XMPP Account"), "jid", "");
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

  my_protocol = plugin;
}

static void
bonjour_get_info(PurpleConnection *gc, const char *who)
{
    PurpleAccount *account;
    PurpleBuddy *pb;
    BonjourBuddy *bb = NULL;
    PurpleNotifyUserInfo *info;

    if (!gc || !who)
        return;

    account = purple_connection_get_account(gc);
    pb = purple_find_buddy(account, who);
    if (pb)
        bb = purple_buddy_get_protocol_data(pb);

     if (pb && bb && bb->conversation && bb->conversation->socket >= 0) {
         /* Only go into the async "Retrieving..." path if we truly sent the IQ */
         if (bonjour_jabber_request_vcard(pb, TRUE))
             return;
     }


    /* No stream: show whatever we know locally */
    info = purple_notify_user_info_new();
    purple_notify_user_info_add_pair_plaintext(info, "JID", who);

    if (bb) {
        if (bb->status)
            purple_notify_user_info_add_pair_plaintext(info, "Show", bb->status);
        if (bb->msg)
            purple_notify_user_info_add_pair_plaintext(info, "Status", bb->msg);
        if (bb->phsh)
            purple_notify_user_info_add_pair_plaintext(info, "Avatar SHA1", bb->phsh);
    }

    purple_notify_userinfo(gc, who, info, NULL, NULL);
    purple_notify_user_info_destroy(info);
}

PURPLE_INIT_PLUGIN(bonjour, init_plugin, info);
