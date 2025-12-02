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
#include "dns_sd_proxy.h"
#endif

#include "internal.h"

#include "account.h"
#include "accountopt.h"
#include "debug.h"
#include "util.h"
#include "version.h"

#include "bonjour.h"
#include "mdns_common.h"
#include "jabber.h"
#include "buddy.h"
#include "bonjour_ft.h"

#include "request.h" //for purple_request_fields
#include "libpurple/blist.h" // for barev
#include "eventloop.h"


typedef struct {
  PurpleConnection *pc;
  PurpleBuddy *buddy;
} BarevAddBuddyData;

static void bonjour_set_status(PurpleAccount *account, PurpleStatus *status);
static void bonjour_login(PurpleAccount *account);


/* Structure for parsing manual buddy format */
typedef struct {
  char *nick;
  char *ipv6_address;
  int port;
} BarevBuddyInfo;

/* Parse buddy string in format: nick or nick@ipv6_address */
static BarevBuddyInfo *
parse_barev_buddy_string(const char *buddy_str)
{
  BarevBuddyInfo *info;
  char *at_sign;
  char *str_copy;

  if (!buddy_str || strlen(buddy_str) == 0) {
    purple_debug_error("bonjour", "Empty buddy string\n");
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

  /* Extract nick */
  *at_sign = '\0';
  info->nick = g_strdup(str_copy);

  /* Extract IPv6 address */
  char *ipv6_start = at_sign + 1;
  info->ipv6_address = g_strdup(ipv6_start);
  info->port = 5298; /* Default port */

  /* Check for port at end (after last colon) - be careful with IPv6 */
  /* Port format would be: nick@[ipv6]:port or nick@ipv6%5298 */

  g_free(str_copy);

  purple_debug_info("bonjour", "Parsed Barev buddy: nick=%s, ipv6=%s, port=%d\n",
    info->nick, info->ipv6_address, info->port);

  return info;
}

static gboolean
barev_auto_connect_timer(gpointer data)
{
  PurpleConnection *gc = data;
  BonjourData *bd = gc->proto_data;
  GSList *buddies;

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

    /* Skip if already connected */
    if (bb->conversation && bb->conversation->socket >= 0) {
      purple_debug_info("bonjour", "Barev: buddy %s already connected\n",
                        who ? who : "(null)");
      continue;
    }

    purple_debug_info("bonjour", "Barev: attempting connection to %s at %s\n",
                      who, (char*)bb->ips->data);

    /* Just ensure a stream/connection exists */
    bonjour_jabber_open_stream(bd->jabber_data, purple_buddy_get_name(pb));
  }

  g_slist_free(buddies);
  return TRUE;
}

static gboolean barev_should_autoconnect_buddy(PurpleBuddy *buddy)
{
    BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);

    if (!bb)
        return FALSE;

    /* Only manual Barev buddies: we require an IP and no active conv */
    if (!bb->ips)
        return FALSE;

    if (bb->conversation != NULL)
        return FALSE; /* already connected */

    return TRUE;
}

static gboolean
barev_reconnect_cb(gpointer data)
{
  PurpleConnection *gc = data;
  PurpleAccount *account;
  BonjourData *bd;
  PurpleBlistNode *node;

  if (!gc)
    return FALSE;

  account = purple_connection_get_account(gc);
  bd = gc->proto_data;

  if (!account || !bd || !bd->jabber_data)
    return FALSE; /* stop timer */

  for (node = purple_blist_get_root(); node;
       node = purple_blist_node_next(node, FALSE)) {

    if (!PURPLE_BLIST_NODE_IS_BUDDY(node))
      continue;

    PurpleBuddy *buddy = (PurpleBuddy *)node;
    if (purple_buddy_get_account(buddy) != account)
      continue;

    if (!barev_should_autoconnect_buddy(buddy))
      continue;

    BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);
    if (!bb || !bb->ips)
      continue;

    const char *who = purple_buddy_get_name(buddy);

    purple_debug_info("bonjour", "Barev: auto-connecting to %s\n",
                      who ? who : "(null)");

    /* Try to open / re-open the stream */
    bonjour_jabber_open_stream(bd->jabber_data, who);
  }

  return TRUE; /* keep timer */
}



static gchar * barev_contacts_filename(PurpleAccount *account)
{
  const char *user_dir = purple_user_dir();
  const char *accname = purple_account_get_username(account);
  /* accname for Bonjour is usually machinename, but that’s fine. */

  return g_strdup_printf("%s" G_DIR_SEPARATOR_S "barev-contacts-%s.txt",
                         user_dir, accname);
}


static void barev_load_contacts(PurpleAccount *account)
{
  gchar *filename = barev_contacts_filename(account);
  char *contents = NULL;
  gsize len = 0;
  char **lines;
  guint i;

  if (!g_file_get_contents(filename, &contents, &len, NULL)) {
    g_free(filename);
    return; /* no contacts yet */
  }

  lines = g_strsplit(contents, "\n", 0);

  for (i = 0; lines[i] != NULL; i++) {
    char *line = lines[i];
    char **parts;
    char *name, *ip, *port_str;
    int port;

    if (*line == '\0' || *line == '#')
      continue; /* skip empty/comments */

    parts = g_strsplit(line, "\t", 3);
    if (!parts[0] || !parts[1]) {
      g_strfreev(parts);
      continue;
    }

    name = parts[0];
    ip = parts[1];
    port_str = parts[2];

    if (port_str && *port_str)
      port = atoi(port_str);
    else
      port = BONJOUR_DEFAULT_PORT;

    /* Create bonjour buddy and add to Purple list */
    BonjourBuddy *bb = bonjour_buddy_new(name, account);
    bb->port_p2pj = port;
    bb->ips = g_slist_append(NULL, g_strdup(ip));

    bonjour_buddy_add_to_purple(bb, NULL);

    PurpleBuddy *pb = purple_find_buddy(account, name);
    if (pb) {
      purple_prpl_got_user_status(account,
                                  purple_buddy_get_name(pb),
                                  BONJOUR_STATUS_ID_OFFLINE,
                                  NULL);
    }

    g_strfreev(parts);
  }

  g_strfreev(lines);
  g_free(contents);
  g_free(filename);
}

static void barev_save_contact(BonjourBuddy *bb)
{
  PurpleAccount *account = bb->account;
  gchar *filename = barev_contacts_filename(account);
  GString *out = g_string_new(NULL);
  char *contents = NULL;
  gsize len = 0;
  char **lines;
  guint i;
  gboolean replaced = FALSE;
  const char *name = bb->name;
  const char *ip = bb->ips ? (const char *)bb->ips->data : "";
  int port = bb->port_p2pj;

  /* Read existing file, rewrite in-memory, then overwrite */
  if (g_file_get_contents(filename, &contents, &len, NULL)) {
    lines = g_strsplit(contents, "\n", 0);

    for (i = 0; lines[i] != NULL; i++) {
      char *line = lines[i];
      char **parts;
      if (*line == '\0') {
        g_string_append_c(out, '\n');
        continue;
      }
      parts = g_strsplit(line, "\t", 3);
      if (parts[0] && g_strcmp0(parts[0], name) == 0) {
        /* replace this entry */
        g_string_append_printf(out, "%s\t%s\t%d\n", name, ip, port);
        replaced = TRUE;
      } else {
        g_string_append(out, line);
        g_string_append_c(out, '\n');
      }
      g_strfreev(parts);
    }

    g_strfreev(lines);
    g_free(contents);
  }

  if (!replaced) {
    g_string_append_printf(out, "%s\t%s\t%d\n", name, ip, port);
  }

  g_file_set_contents(filename, out->str, out->len, NULL);
  g_string_free(out, TRUE);
  g_free(filename);
}

static void barev_remove_contact(PurpleAccount *account, const char *name)
{
  gchar *filename = barev_contacts_filename(account);
  char *contents = NULL;
  gsize len = 0;
  GString *out;
  char **lines;
  guint i;

  if (!g_file_get_contents(filename, &contents, &len, NULL)) {
    g_free(filename);
    return;
  }

  out = g_string_new(NULL);
  lines = g_strsplit(contents, "\n", 0);

  for (i = 0; lines[i] != NULL; i++) {
    char *line = lines[i];
    char **parts;

    if (*line == '\0') {
      g_string_append_c(out, '\n');
      continue;
    }
    parts = g_strsplit(line, "\t", 3);
    if (parts[0] && g_strcmp0(parts[0], name) == 0) {
      /* skip this one (effectively deleting) */
      g_strfreev(parts);
      continue;
    }
    g_string_append(out, line);
    g_string_append_c(out, '\n');
    g_strfreev(parts);
  }

  g_strfreev(lines);
  g_free(contents);

  g_file_set_contents(filename, out->str, out->len, NULL);
  g_string_free(out, TRUE);
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

    /* Persist to barev-contacts-<account>.txt */
    barev_save_contact(bb);

    /* Do NOT mark them online here – we only do that when a stream is up */
    purple_prpl_got_user_status(gc->account,
                                full_buddy_name,
                                BONJOUR_STATUS_ID_OFFLINE,
                                NULL);

    g_free(info->nick);
    g_free(info->ipv6_address);
    g_free(info);
}


//static void barev_add_buddy_ok_cb(BarevAddBuddyData *data, PurpleRequestFields *fields)
//{
//  PurpleConnection *pc = data->pc;
//  PurpleBuddy *buddy = data->buddy;
//  PurpleAccount *account = purple_connection_get_account(pc);
//  BonjourBuddy *bb;
//  const char *name = purple_buddy_get_name(buddy);
//  PurpleRequestField *f;
//  const char *ip, *port_str;
//  int port;
//
//  f = purple_request_fields_get_field(fields, "ip");
//  ip = purple_request_field_string_get_value(f);
//  if (!ip || !*ip) {
//  purple_debug_error("bonjour", "No IP/hostname provided for buddy %s\n", name);
//  g_free(data);
//  return;
//}
//
//  f = purple_request_fields_get_field(fields, "port");
//  port_str = purple_request_field_string_get_value(f);
//  if (port_str && *port_str)
//    port = atoi(port_str);
//  else
//    port = purple_account_get_int(account, "port", BONJOUR_DEFAULT_PORT);
//
//  bb = bonjour_buddy_new(name, account);
//  bb->port_p2pj = port;
//  bb->ips = g_slist_append(NULL, g_strdup(ip));
//
//  bonjour_buddy_add_to_purple(bb, buddy);
//
//  barev_save_contact(bb);
//
//  g_free(data);
//}



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

  bd->jid = g_strdup_printf("%s@barev.local", accname);

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

  /* Minimal DNS-SD data (we don't use mDNS but some code expects this) */
  //bd->dns_sd_data = g_new0(BonjourDnsSd, 1);
  //bd->dns_sd_data->first   = g_strdup("");
  //bd->dns_sd_data->last    = g_strdup("");
  //bd->dns_sd_data->account = account;
  // no mdns
  bd->dns_sd_data = NULL;

  purple_connection_set_state(gc, PURPLE_CONNECTED);

  purple_debug_info("bonjour", "=== BAREV MODE READY ===\n");

  /* 1. Load saved contacts: barev-contacts-<account>.txt */
  barev_load_contacts(account);

  /* 2. For existing Purple buddies with no protocol_data yet, build bb from name */
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

  /* 3. Start auto-connect timer: keep streams up while reachable */
  bd->reconnect_timer = purple_timeout_add_seconds(30,
                                                   barev_auto_connect_timer,
                                                   gc);
  purple_debug_info("bonjour", "Auto-connect timer started (30s)\n");
}

static void
bonjour_login(PurpleAccount *account)
{
  PurpleConnection *gc;
  BonjourData *bd;
  PurpleStatus *status;
  PurplePresence *presence;
  const char *username;
  const char *protocol_id;
  GSList *buddies, *l;
  gboolean is_barev = FALSE;

  g_return_if_fail(account != NULL);

  gc = purple_account_get_connection(account);
  g_return_if_fail(gc != NULL);

  /* --- 1. Detect Barev via protocol id --- */
  protocol_id = purple_account_get_protocol_id(account);
  if (protocol_id && (strstr(protocol_id, "barev") || strstr(protocol_id, "prpl-barev"))) {
    purple_debug_info("bonjour", "Detected Barev mode from protocol id '%s'\n", protocol_id);
    bonjour_login_barev(account);
    return;
  }

  /* --- 2. Detect Barev via account username (nick@ipv6, etc.) --- */
  username = purple_account_get_username(account);
  if (username && strchr(username, '@')) {
    purple_debug_info("bonjour", "Detected Barev mode from account username '%s'\n", username);
    bonjour_login_barev(account);
    return;
  }

  /* --- 3. Detect Barev via any buddy name (nick@ipv6) --- */
  buddies = purple_find_buddies(account, NULL);
  for (l = buddies; l; l = l->next) {
    PurpleBuddy *buddy = l->data;
    const char *buddy_name = purple_buddy_get_name(buddy);

    if (buddy_name && strchr(buddy_name, '@')) {
      is_barev = TRUE;
      purple_debug_info("bonjour",
                        "Detected Barev mode from buddy name '%s'\n",
                        buddy_name);
      break;
    }
  }
  g_slist_free(buddies);

  if (is_barev) {
    bonjour_login_barev(account);
    return;
  }

  /* ===============================
   *   Normal Bonjour (mDNS) mode
   * =============================== */

#ifdef _WIN32
  if (!dns_sd_available()) {
    purple_connection_error_reason(gc,
                                   PURPLE_CONNECTION_ERROR_OTHER_ERROR,
                                   _("Unable to find Apple's \"Bonjour for Windows\" toolkit, see "
                                     "https://developer.pidgin.im/BonjourWindows for more information."));
    return;
  }
#endif /* _WIN32 */

  gc->flags |= PURPLE_CONNECTION_HTML;
  gc->proto_data = bd = g_new0(BonjourData, 1);

  /* Start waiting for jabber connections (iChat style) */
  bd->jabber_data = g_new0(BonjourJabber, 1);
  bd->jabber_data->socket = -1;
  bd->jabber_data->socket6 = -1;
  bd->jabber_data->port =
      purple_account_get_int(account, "port", BONJOUR_DEFAULT_PORT);
  bd->jabber_data->account = account;

  if (bonjour_jabber_start(bd->jabber_data) == -1) {
    purple_connection_error_reason(gc,
                                   PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                                   _("Unable to listen for incoming IM connections"));
    return;
  }

  /* Load Barev-style manual contacts even in normal Bonjour mode */
  barev_load_contacts(account);

  /* Start periodic reconnect attempts for Barev contacts */
  bd->reconnect_timer = purple_timeout_add_seconds(
      30,
      barev_reconnect_cb,
      gc);

  /* Connect to the mDNS daemon looking for buddies in the LAN */
  bd->dns_sd_data = bonjour_dns_sd_new();
  bd->dns_sd_data->first =
      g_strdup(purple_account_get_string(account, "first", default_firstname));
  bd->dns_sd_data->last =
      g_strdup(purple_account_get_string(account, "last", default_lastname));
  bd->dns_sd_data->port_p2pj = bd->jabber_data->port;
  /* Not engaged in AV conference */
  bd->dns_sd_data->vc = g_strdup("!");

  status = purple_account_get_active_status(account);
  presence = purple_account_get_presence(account);
  if (purple_presence_is_available(presence))
    bd->dns_sd_data->status = g_strdup("avail");
  else if (purple_presence_is_idle(presence))
    bd->dns_sd_data->status = g_strdup("away");
  else
    bd->dns_sd_data->status = g_strdup("dnd");

  bd->dns_sd_data->msg =
      g_strdup(purple_status_get_attr_string(status, "message"));

  bd->dns_sd_data->account = account;

  if (!bonjour_dns_sd_start(bd->dns_sd_data)) {
    purple_debug_warning("bonjour",
                         "mDNS start failed; continuing in manual-only mode.\n");
    g_clear_pointer(&bd->dns_sd_data, bonjour_dns_sd_free);
  } else {
    bonjour_dns_sd_update_buddy_icon(bd->dns_sd_data);
  }

  /* Show the buddy list by telling Purple we have already connected */
  purple_connection_set_state(gc, PURPLE_CONNECTED);
}

static void
bonjour_close(PurpleConnection *connection)
{
  PurpleGroup *bonjour_group;
  BonjourData *bd = connection->proto_data;

  bonjour_group = purple_find_group(BONJOUR_GROUP_NAME);

  /* Remove all the bonjour buddies */
  bonjour_removeallfromlocal(connection, bonjour_group);

  /* Stop looking for buddies in the LAN */
  if (bd != NULL && bd->dns_sd_data != NULL)
  {
    bonjour_dns_sd_stop(bd->dns_sd_data);
    bonjour_dns_sd_free(bd->dns_sd_data);
  }

  if (bd != NULL && bd->jabber_data != NULL)
  {
    /* Stop waiting for conversations */
    bonjour_jabber_stop(bd->jabber_data);
    g_free(bd->jabber_data);
  }

    if (bd != NULL && bd->reconnect_timer != 0) {
      purple_timeout_remove(bd->reconnect_timer);
      bd->reconnect_timer = 0;
  }


  /* Delete the bonjour group
   * (purple_blist_remove_group will bail out if the group isn't empty)
   */
  if (bonjour_group != NULL)
    purple_blist_remove_group(bonjour_group);

  /* Cancel any file transfers */
  while (bd != NULL && bd->xfer_lists) {
    purple_xfer_cancel_local(bd->xfer_lists->data);
  }

  if (bd != NULL)
    g_free(bd->jid);
  g_free(bd);
  connection->proto_data = NULL;
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

static void bonjour_set_status(PurpleAccount *account, PurpleStatus *status)
{
  PurpleConnection *gc;
  BonjourData *bd;
  PurplePresence *presence;
  const char *message, *bonjour_status;
  gchar *stripped;

  if (!account)
    return;

  gc = purple_account_get_connection(account);
  if (!gc)
    return;
  bd = gc->proto_data;
    if(!bd || !bd->dns_sd_data)
      return; // no mdns, nothing to broadcast

  presence = purple_account_get_presence(account);

  if (!bd || !bd->dns_sd_data)
   return; /* no mDNS, nothing to broadcast */

  message = purple_status_get_attr_string(status, "message");
  if (message == NULL)
    message = "";
  stripped = purple_markup_strip_html(message);

  /*
   * The three possible status for Bonjour are
   *   -available ("avail")
   *   -idle ("away")
   *   -away ("dnd")
   * Each of them can have an optional message.
   */
  if (purple_presence_is_available(presence))
    bonjour_status = "avail";
  else if (purple_presence_is_idle(presence))
    bonjour_status = "away";
  else
    bonjour_status = "dnd";

  bonjour_dns_sd_send_status(bd->dns_sd_data, bonjour_status, stripped);
  g_free(stripped);
}

/*
 * The add_buddy callback removes the buddy from the local list.
 * Bonjour manages buddies for you, and adding someone locally by
 * hand is stupid.  Perhaps we should change libpurple not to allow adding
 * if there is no add_buddy callback.
 */
//static void
//bonjour_fake_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group) {
//  purple_debug_error("bonjour", "Buddy '%s' manually added; removing.  "
//              "Bonjour buddies must be discovered and not manually added.\n",
//         purple_buddy_get_name(buddy));
//
//  /* I suppose we could alert the user here, but it seems unnecessary. */
//
//  /* If this causes problems, it can be moved to an idle callback */
//  purple_blist_remove_buddy(buddy);
//}

static void
bonjour_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
  const char *protocol_id = purple_account_get_protocol_id(gc->account);

  /* Check if this is Barev mode */
  if (protocol_id && (strstr(protocol_id, "barev") || strstr(protocol_id, "prpl-barev"))) {
    barev_add_buddy(gc, buddy, group);
    return;
  }

  /* Standard Bonjour mode */
  BonjourData *bd = purple_connection_get_protocol_data(gc);
  BonjourBuddy *bb;

  if (purple_buddy_get_protocol_data(buddy) != NULL) {
    return;
  }

  /* Check if we have dns_sd_data - in Barev mode we might not */
  if (!bd->dns_sd_data) {
    purple_debug_warning("bonjour", "No DNS-SD data available\n");
    return;
  }

  /* For standard Bonjour, we need different handling */
  /* Since bonjour_buddy_check expects a BonjourBuddy, not BonjourDnsSd,
   * we need to check if the buddy exists in discovery */

  /* Create a minimal BonjourBuddy for the check */
  bb = g_new0(BonjourBuddy, 1);
  bb->name = g_strdup(purple_buddy_get_name(buddy));

  /* Check if this buddy is valid for Bonjour */
  if (!bonjour_buddy_check(bb)) {
    purple_blist_remove_buddy(buddy);
    g_free(bb->name);
    g_free(bb);
    return;
  }

  /* Clean up temporary buddy */
  g_free(bb->name);
  g_free(bb);

  /* For standard Bonjour with mDNS, handle buddy list updates */
  /* Note: The bonjourdnsssd member may not exist in your version */
}



static void bonjour_remove_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group) {
  BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);
  if (bb) {
    barev_remove_contact(bb->account, bb->name);
    bonjour_buddy_delete(bb);
    purple_buddy_set_protocol_data(buddy, NULL);
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

static
void bonjour_set_buddy_icon(PurpleConnection *conn, PurpleStoredImage *img)
{
  BonjourData *bd = conn->proto_data;
  //bonjour_dns_sd_update_buddy_icon(bd->dns_sd_data);
  if (bd && bd->dns_sd_data)
   bonjour_dns_sd_update_buddy_icon(bd->dns_sd_data);
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
  NULL,                                                    /* send_typing */
  NULL,                                                    /* get_info */
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

PURPLE_INIT_PLUGIN(bonjour, init_plugin, info);
