/*
 * purple - Bonjour Jabber XML parser stuff
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
 *
 */
#include "internal.h"

#include <libxml/parser.h>

#include "connection.h"
#include "debug.h"
#include "jabber.h"
#include "parser.h"
#include "buddy.h"
#include "util.h"
#include "xmlnode.h"

/*
 * Return TRUE if the named buddy exists in roster AND has this IP
 * in its allowed IP list.
 */
static gboolean
buddy_name_allows_ip(PurpleAccount *account, const char *name, const char *ip)
{
  PurpleBuddy *pb;
  BonjourBuddy *bb;
  GSList *ip_iter;

  if (!account || !name || !ip)
    return FALSE;

  pb = purple_find_buddy(account, name);
  if (!pb)
    return FALSE;

  bb = purple_buddy_get_protocol_data(pb);
  if (!bb || !bb->ips)
    return FALSE;

  for (ip_iter = bb->ips; ip_iter; ip_iter = ip_iter->next) {
    if (g_strcmp0((const char *)ip_iter->data, ip) == 0)
      return TRUE;
  }

  return FALSE;
}

static gboolean
parse_from_attrib_and_find_buddy(BonjourJabberConversation *bconv, int nb_attributes, const xmlChar **attributes) {
  int i;

  /* If the "from" attribute is specified, attach it to the conversation. */
  for(i=0; i < nb_attributes * 5; i+=5) {
    if(!xmlStrcmp(attributes[i], (xmlChar*) "from")) {
      int len = attributes[i+4] - attributes[i+3];
      char *from_jid = g_strndup((char *)attributes[i+3], len);

      /* If we already have a buddy attached, check if the "from" matches */
      if (bconv->pb != NULL) {
          const char *current_buddy_name = purple_buddy_get_name(bconv->pb);

          if (g_strcmp0(current_buddy_name, from_jid) != 0) {
              /* "from" doesn't match current buddy. But check if current buddy's IP is correct first! */
              BonjourBuddy *bb = purple_buddy_get_protocol_data(bconv->pb);

              if (bb && bb->ips && bconv->ip) {
                  /* Check if connection IP matches current buddy's IP list */
                  GSList *ip_iter = bb->ips;
                  gboolean current_buddy_ip_matches = FALSE;

                  while (ip_iter) {
                      if (g_strcmp0(ip_iter->data, bconv->ip) == 0) {
                          current_buddy_ip_matches = TRUE;
                          break;
                      }
                      ip_iter = ip_iter->next;
                  }

                  if (current_buddy_ip_matches) {
                      /* Current buddy is correct by IP. Don't switch! Remote is lying about JID. */
                      //purple_debug_warning("bonjour",
                      //    "Stream 'from=%s' doesn't match connected buddy '%s', "
                      //    "but connection IP %s matches current buddy's IP list. "
                      //    "Keeping current buddy (remote JID claim rejected).\n",
                      //    from_jid, current_buddy_name, bconv->ip);
                      //g_free(from_jid);
                      //return TRUE;
                      /*
                       * Barev: multiple identities may legitimately share one IP.
                       * If the claimed JID is a known buddy AND that buddy allows this IP,
                       * prefer the claimed JID. Otherwise keep the current buddy as a spoofing guard.
                       */
                      if (!buddy_name_allows_ip(bconv->account, from_jid, bconv->ip)) {
                          purple_debug_warning("bonjour",
                              "Stream 'from=%s' doesn't match connected buddy '%s', "
                              "and connection IP %s matches current buddy's IP list. "
                              "Claimed JID is not a known buddy for this IP; keeping current buddy.\n",
                              from_jid, current_buddy_name, bconv->ip);
                          g_free(from_jid);
                          return TRUE;
                      }

                      purple_debug_info("bonjour",
                          "Stream 'from=%s' doesn't match connected buddy '%s', "
                          "but both buddies allow IP %s. Switching to claimed JID (Barev multi-identity).\n",
                          from_jid, current_buddy_name, bconv->ip);
                      /* fall through: clear old association and re-match by name */

                  }
              }

              purple_debug_warning("bonjour",
                  "Stream 'from=%s' doesn't match connected buddy '%s'. "
                  "Trying to find correct buddy.\n",
                  from_jid, current_buddy_name);

              /* Clear the old buddy association */
              if (bb && bb->conversation == bconv) {
                  bb->conversation = NULL;
              }
              bconv->pb = NULL;
          } else {
              /* "from" matches our current buddy, all good */
              purple_debug_info("bonjour",
                  "Stream 'from=%s' matches current buddy.\n", from_jid);
              g_free(from_jid);
              return TRUE;
          }
      }

      /* Set the buddy_name from the "from" attribute and try to match */
      g_free(bconv->buddy_name);
      bconv->buddy_name = from_jid;
      bonjour_jabber_conv_match_by_name(bconv);

      return (bconv->pb != NULL);
    }
  }

  return FALSE;
}

static void
bonjour_parser_element_start_libxml(void *user_data,
           const xmlChar *element_name, const xmlChar *prefix, const xmlChar *namespace,
           int nb_namespaces, const xmlChar **namespaces,
           int nb_attributes, int nb_defaulted, const xmlChar **attributes)
{
  BonjourJabberConversation *bconv = user_data;

  xmlnode *node;
  int i;

  g_return_if_fail(element_name != NULL);

  if(!xmlStrcmp(element_name, (xmlChar*) "stream")) {
    if(!bconv->recv_stream_start) {
      bconv->recv_stream_start = TRUE;

      /* Always parse and validate the "from" attribute, even if we already have a buddy */
      parse_from_attrib_and_find_buddy(bconv, nb_attributes, attributes);

      bonjour_jabber_stream_started(bconv);
    }
  } else {

    /* If we haven't yet attached a buddy and this isn't "<stream:features />",
     * try to get a "from" attribute as a last resort to match our buddy. */
    if(bconv->pb == NULL
        && !(prefix && !xmlStrcmp(prefix, (xmlChar*) "stream")
          && !xmlStrcmp(element_name, (xmlChar*) "features"))
        && !parse_from_attrib_and_find_buddy(bconv, nb_attributes, attributes))
      /* We've run out of options for finding who the conversation is from
         using explicitly specified stuff; see if we can make a good match
         by using the IP */
      bonjour_jabber_conv_match_by_ip(bconv);

    if(bconv->current)
      node = xmlnode_new_child(bconv->current, (const char*) element_name);
    else
      node = xmlnode_new((const char*) element_name);
    xmlnode_set_namespace(node, (const char*) namespace);

    for(i=0; i < nb_attributes * 5; i+=5) {
      const char *name = (const char *)attributes[i];
      const char *prefix = (const char *)attributes[i+1];
      const char *attrib_ns = (const char *)attributes[i+2];
      char *txt;
      int attrib_len = attributes[i+4] - attributes[i+3];
      char *attrib = g_malloc(attrib_len + 1);

      memcpy(attrib, attributes[i+3], attrib_len);
      attrib[attrib_len] = '\0';

      txt = attrib;
      attrib = purple_unescape_text(txt);
      g_free(txt);
      xmlnode_set_attrib_full(node, name, attrib_ns, prefix, attrib);
      g_free(attrib);
    }

    bconv->current = node;
  }
}

static void
bonjour_parser_element_end_libxml(void *user_data, const xmlChar *element_name,
         const xmlChar *prefix, const xmlChar *namespace)
{
  BonjourJabberConversation *bconv = user_data;

  if(!bconv->current) {
    /* We don't keep a reference to the start stream xmlnode,
     * so we have to check for it here to close the conversation */
    if(!xmlStrcmp(element_name, (xmlChar*) "stream"))
      /* Asynchronously close the conversation to prevent bonjour_parser_setup()
       * being called from within this context */
      async_bonjour_jabber_close_conversation(bconv);
    return;
  }

  if(bconv->current->parent) {
    if(!xmlStrcmp((xmlChar*) bconv->current->name, element_name))
      bconv->current = bconv->current->parent;
  } else {
    xmlnode *packet = bconv->current;
    bconv->current = NULL;
    bonjour_jabber_process_packet(bconv->pb, packet);
    xmlnode_free(packet);
  }
}

static void
bonjour_parser_element_text_libxml(void *user_data, const xmlChar *text, int text_len)
{
  BonjourJabberConversation *bconv = user_data;

  if(!bconv->current)
    return;

  if(!text || !text_len)
    return;

  xmlnode_insert_data(bconv->current, (const char*) text, text_len);
}

static void
bonjour_parser_structured_error_handler(void *user_data, const xmlError *error)
{
  BonjourJabberConversation *bconv = user_data;

  purple_debug_error("jabber", "XML parser error for BonjourJabberConversation %p: "
                               "Domain %i, code %i, level %i: %s",
                     bconv,
                     error->domain, error->code, error->level,
                     (error->message ? error->message : "(null)\n"));
}

static xmlSAXHandler bonjour_parser_libxml = {
  NULL,                  /*internalSubset*/
  NULL,                  /*isStandalone*/
  NULL,                  /*hasInternalSubset*/
  NULL,                  /*hasExternalSubset*/
  NULL,                  /*resolveEntity*/
  NULL,                  /*getEntity*/
  NULL,                  /*entityDecl*/
  NULL,                  /*notationDecl*/
  NULL,                  /*attributeDecl*/
  NULL,                  /*elementDecl*/
  NULL,                  /*unparsedEntityDecl*/
  NULL,                  /*setDocumentLocator*/
  NULL,                  /*startDocument*/
  NULL,                  /*endDocument*/
  NULL,                  /*startElement*/
  NULL,                  /*endElement*/
  NULL,                  /*reference*/
  bonjour_parser_element_text_libxml,    /*characters*/
  NULL,                  /*ignorableWhitespace*/
  NULL,                  /*processingInstruction*/
  NULL,                  /*comment*/
  NULL,                  /*warning*/
  NULL,                  /*error*/
  NULL,                  /*fatalError*/
  NULL,                  /*getParameterEntity*/
  NULL,                  /*cdataBlock*/
  NULL,                  /*externalSubset*/
  XML_SAX2_MAGIC,              /*initialized*/
  NULL,                  /*_private*/
  bonjour_parser_element_start_libxml,  /*startElementNs*/
  bonjour_parser_element_end_libxml,    /*endElementNs*/
  (xmlStructuredErrorFunc)bonjour_parser_structured_error_handler /*serror*/
};

void
bonjour_parser_setup(BonjourJabberConversation *bconv)
{

  /* This seems backwards, but it makes sense. The libxml code creates
   * the parser context when you try to use it (this way, it can figure
   * out the encoding at creation time. So, setting up the parser is
   * just a matter of destroying any current parser. */
  if (bconv->context) {
    xmlParseChunk(bconv->context, NULL,0,1);
    xmlFreeParserCtxt(bconv->context);
    bconv->context = NULL;
  }
}


void bonjour_parser_process(BonjourJabberConversation *bconv, const char *buf, int len)
{

  if (bconv->context == NULL) {
    /* libxml inconsistently starts parsing on creating the
     * parser, so do a ParseChunk right afterwards to force it. */
    bconv->context = xmlCreatePushParserCtxt(&bonjour_parser_libxml, bconv, buf, len, NULL);
    xmlParseChunk(bconv->context, "", 0, 0);
  } else if (xmlParseChunk(bconv->context, buf, len, 0) < 0)
    /* TODO: What should we do here - I assume we should display an error or something (maybe just print something to the conv?) */
    purple_debug_error("bonjour", "Error parsing xml.\n");

}
