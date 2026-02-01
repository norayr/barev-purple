/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301, USA.
 */

#include <glib.h>
#include <stdlib.h>

#include "internal.h"
#include "buddy.h"
#include "account.h"
#include "blist.h"
#include "bonjour.h"
#include "glibcompat.h"
#include "debug.h"

/**
 * Creates a new buddy.
 */
BonjourBuddy *
bonjour_buddy_new(const gchar *name, PurpleAccount* account)
{
  BonjourBuddy *buddy = g_new0(BonjourBuddy, 1);

  buddy->account = account;
  buddy->name = g_strdup(name);

  return buddy;
}

#define _B_CLR(x) g_free(x); x = NULL;

void clear_bonjour_buddy_values(BonjourBuddy *buddy) {

  _B_CLR(buddy->first)
  _B_CLR(buddy->email);
  _B_CLR(buddy->ext);
  _B_CLR(buddy->jid);
  _B_CLR(buddy->last);
  _B_CLR(buddy->msg);
  _B_CLR(buddy->nick);
  _B_CLR(buddy->node);
  _B_CLR(buddy->phsh);
  _B_CLR(buddy->status);
  _B_CLR(buddy->vc);
  _B_CLR(buddy->ver);
  _B_CLR(buddy->AIM);

}

void
set_bonjour_buddy_value(BonjourBuddy* buddy, const char *record_key, const char *value, guint32 len){
  gchar **fld = NULL;

  g_return_if_fail(record_key != NULL);

  if (purple_strequal(record_key, "1st"))
    fld = &buddy->first;
  else if(purple_strequal(record_key, "email"))
    fld = &buddy->email;
  else if(purple_strequal(record_key, "ext"))
    fld = &buddy->ext;
  else if(purple_strequal(record_key, "jid"))
    fld = &buddy->jid;
  else if(purple_strequal(record_key, "last"))
    fld = &buddy->last;
  else if(purple_strequal(record_key, "msg"))
    fld = &buddy->msg;
  else if(purple_strequal(record_key, "nick"))
    fld = &buddy->nick;
  else if(purple_strequal(record_key, "node"))
    fld = &buddy->node;
  else if(purple_strequal(record_key, "phsh"))
    fld = &buddy->phsh;
  else if(purple_strequal(record_key, "status"))
    fld = &buddy->status;
  else if(purple_strequal(record_key, "vc"))
    fld = &buddy->vc;
  else if(purple_strequal(record_key, "ver"))
    fld = &buddy->ver;
  else if(purple_strequal(record_key, "AIM"))
    fld = &buddy->AIM;

  if(fld == NULL)
    return;

  g_free(*fld);
  *fld = NULL;
  *fld = g_strndup(value, len);
}

/**
 * Check if all the compulsory buddy data is present.
 */
gboolean
bonjour_buddy_check(BonjourBuddy *buddy)
{
  if (buddy->account == NULL)
    return FALSE;

  if (buddy->name == NULL)
    return FALSE;

  return TRUE;
}

/**
 * If the buddy does not yet exist, then create it and add it to
 * our buddy list.  In either case we set the correct status for
 * the buddy.
 */
void
bonjour_buddy_add_to_purple(BonjourBuddy *bonjour_buddy, PurpleBuddy *buddy)
{
  PurpleGroup *group;
  PurpleAccount *account = bonjour_buddy->account;
  const char *status_id, *old_hash, *new_hash, *name;

  /* Translate between the Bonjour status and the Purple status */
  if (bonjour_buddy->status != NULL && g_ascii_strcasecmp("dnd", bonjour_buddy->status) == 0)
    status_id = BONJOUR_STATUS_ID_AWAY;
  else
    status_id = BONJOUR_STATUS_ID_AVAILABLE;

  /*
   * TODO: Figure out the idle time by getting the "away"
   * field from the DNS SD.
   */

  /* Make sure the Bonjour group exists in our buddy list */
  group = purple_find_group(BONJOUR_GROUP_NAME); /* Use the buddy's domain, instead? */
  if (group == NULL) {
    group = purple_group_new(BONJOUR_GROUP_NAME);
    purple_blist_add_group(group, NULL);
  }

  /* Make sure the buddy exists in our buddy list */
  if (buddy == NULL)
    buddy = purple_find_buddy(account, bonjour_buddy->name);

  if (buddy == NULL) {
    buddy = purple_buddy_new(account, bonjour_buddy->name, NULL);
    purple_blist_node_set_flags((PurpleBlistNode *)buddy, PURPLE_BLIST_NODE_FLAG_NO_SAVE);
    purple_blist_add_buddy(buddy, NULL, group, NULL);
  }

  name = purple_buddy_get_name(buddy);
  purple_buddy_set_protocol_data(buddy, bonjour_buddy);

  /* Create the alias for the buddy using the first and the last name */
  if (bonjour_buddy->nick && *bonjour_buddy->nick)
    serv_got_alias(purple_account_get_connection(account), name, bonjour_buddy->nick);
  else {
    gchar *alias = NULL;
    const char *first, *last;
    first = bonjour_buddy->first;
    last = bonjour_buddy->last;
    if ((first && *first) || (last && *last))
      alias = g_strdup_printf("%s%s%s",
            (first && *first ? first : ""),
            (first && *first && last && *last ? " " : ""),
            (last && *last ? last : ""));
    serv_got_alias(purple_account_get_connection(account), name, alias);
    g_free(alias);
  }

  /* Set the user's status */
  if (bonjour_buddy->msg != NULL)
    purple_prpl_got_user_status(account, name, status_id,
              "message", bonjour_buddy->msg, NULL);
  else
    purple_prpl_got_user_status(account, name, status_id, NULL);

  purple_prpl_got_user_idle(account, name, FALSE, 0);

  /* TODO: Because we don't save Bonjour buddies in blist.xml,
   * we will always have to look up the buddy icon at login time.
   * I think we should figure out a way to do something about this. */

  /* Deal with the buddy icon */
  old_hash = purple_buddy_icons_get_checksum_for_user(buddy);
     new_hash = (bonjour_buddy->phsh && *(bonjour_buddy->phsh)) ? bonjour_buddy->phsh : NULL;

     if (new_hash && !purple_strequal(old_hash, new_hash)) {
         purple_debug_info("bonjour",
                           "Barev: buddy icon hash changed for %s, ignoring (no mDNS)\n",
                           name);
         /* Optionally: clear or keep old icon; for now we just ignore. */
     } else if (!new_hash) {
         purple_buddy_icons_set_for_user(account, name, NULL, 0, NULL);
     }
}

/**
 * The buddy has signed off Bonjour.
 * If the buddy is being saved, mark as offline, otherwise delete
 */
void bonjour_buddy_signed_off(PurpleBuddy *pb) {
  if (PURPLE_BLIST_NODE_SHOULD_SAVE(pb)) {
    purple_prpl_got_user_status(purple_buddy_get_account(pb),
              purple_buddy_get_name(pb), "offline", NULL);
    bonjour_buddy_delete(purple_buddy_get_protocol_data(pb));
    purple_buddy_set_protocol_data(pb, NULL);
  } else {
    purple_account_remove_buddy(purple_buddy_get_account(pb), pb, NULL);
    purple_blist_remove_buddy(pb);
  }
}

/**
 * We got the buddy icon data; deal with it
 */
void bonjour_buddy_got_buddy_icon(BonjourBuddy *buddy, gconstpointer data, gsize len) {
  /* Recalculate the hash instead of using the current phsh to make sure it is accurate for the icon. */
  char *p, *hash;

  if (data == NULL || len == 0)
    return;

  /* Take advantage of the fact that we use a SHA-1 hash of the data as the filename. */
  hash = purple_util_get_image_filename(data, len);

  /* Get rid of the extension */
  if (!(p = strchr(hash, '.'))) {
    g_free(hash);
    return;
  }

  *p = '\0';

  purple_debug_info("bonjour", "Got buddy icon for %s icon hash='%s' phsh='%s'.\n", buddy->name,
        hash, buddy->phsh ? buddy->phsh : "(null)");

  purple_buddy_icons_set_for_user(buddy->account, buddy->name,
    g_memdup2(data, len), len, hash);

  g_free(hash);
}

/**
 * Mark a PurpleBuddy as a persistent contact.
 * Stores the IP and port as blist node settings and clears the NO_SAVE flag
 * so Purple will write this buddy into blist.xml.
 */
void
bonjour_buddy_save_to_blist(PurpleBuddy *pb, const char *ip, int port)
{
  PurpleBlistNode *node  = (PurpleBlistNode *)pb;
  PurpleBlistNodeFlags flags;

  /* Clear NO_SAVE so Purple persists this buddy */
  flags = purple_blist_node_get_flags(node);
  flags &= ~PURPLE_BLIST_NODE_FLAG_NO_SAVE;
  purple_blist_node_set_flags(node, flags);

  if (ip && *ip)
    purple_blist_node_set_string(node, "barev_ip", ip);
  purple_blist_node_set_int(node, "barev_port", port);
}

/**
 * Reconstruct BonjourBuddy protocol data for every buddy that belongs to
 * *account* and already has a "barev_ip" setting but no protocol_data.
 *
 * Purple parses blist.xml before login(), so saved buddies (and their
 * settings) are already in the tree.  We just attach the protocol_data and
 * mark the status offline until a real stream proves otherwise.
 *
 * Buddies that exist in the tree but do NOT have "barev_ip" are skipped;
 * the caller's fallback loop will handle them via barev_add_buddy().
 */
void
bonjour_buddies_load_from_blist(PurpleAccount *account)
{
  GSList *buddies, *iter;

  buddies = purple_find_buddies(account, NULL);

  for (iter = buddies; iter; iter = iter->next) {
    PurpleBuddy    *pb   = (PurpleBuddy *)iter->data;
    PurpleBlistNode*node = (PurpleBlistNode *)pb;
    const char     *name, *ip;
    int             port;
    BonjourBuddy   *bb;

    /* Already initialised (e.g. by the migration step) — skip */
    if (purple_buddy_get_protocol_data(pb) != NULL)
      continue;

    /* Only reconstruct buddies we have previously persisted */
    ip = purple_blist_node_get_string(node, "barev_ip");
    if (!ip || !*ip)
      continue;

    port = purple_blist_node_get_int(node, "barev_port");
    if (port <= 0)
      port = BONJOUR_DEFAULT_PORT;

    name = purple_buddy_get_name(pb);

    bb             = bonjour_buddy_new(name, account);
    bb->ips        = g_slist_append(NULL, g_strdup(ip));
    bb->port_p2pj  = port;

    purple_buddy_set_protocol_data(pb, bb);

    /* Mark offline until a stream is actually established */
    purple_prpl_got_user_status(account, name, BONJOUR_STATUS_ID_OFFLINE, NULL);

    purple_debug_info("bonjour",
        "Loaded saved contact from blist: %s ip=%s port=%d\n", name, ip, port);
  }

  g_slist_free(buddies);
}

/**
 * Deletes a buddy from memory.
 */
void
bonjour_buddy_delete(BonjourBuddy *buddy)
{
  g_free(buddy->name);
  while (buddy->ips != NULL) {
    g_free(buddy->ips->data);
    buddy->ips = g_slist_delete_link(buddy->ips, buddy->ips);
  }
  g_free(buddy->first);
  g_free(buddy->phsh);
  g_free(buddy->status);
  g_free(buddy->email);
  g_free(buddy->last);
  g_free(buddy->jid);
  g_free(buddy->AIM);
  g_free(buddy->vc);
  g_free(buddy->msg);
  g_free(buddy->ext);
  g_free(buddy->nick);
  g_free(buddy->node);
  g_free(buddy->ver);

  bonjour_jabber_close_conversation(buddy->conversation);
  buddy->conversation = NULL;

  g_free(buddy);
}
