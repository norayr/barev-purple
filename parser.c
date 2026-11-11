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
#include "address.h"
#include "debug.h"
#include "jabber.h"
#include "parser.h"
#include "util.h"
#include "xmlnode.h"

#define STREAM_NS "http://etherx.jabber.org/streams"
#define CLIENT_NS "jabber:client"
#define HEADER_LIMIT 4096
#define STANZA_LIMIT 524288

static guint64
parser_position(BonjourJabberConversation *bconv)
{
  xmlParserInput *input = bconv->context->input;
  return input->consumed + (guint64)(input->cur-input->base);
}

static void
parser_reject(BonjourJabberConversation *bconv, const char *reason)
{
  purple_debug_warning("barev", "Rejecting peer stream: %s\n", reason);
  async_bonjour_jabber_close_conversation(bconv);
}

/* SAX2 attribute values are length-delimited and can contain escaped entities. */
static char *
parser_attribute(int count, const xmlChar **attributes, const char *name)
{
  int i;
  for (i = 0; i < count * 5; i += 5) {
    if (!attributes[i+2] && !xmlStrcmp(attributes[i], (const xmlChar *)name)) {
      char *escaped = g_strndup((const char *)attributes[i+3], attributes[i+4]-attributes[i+3]);
      char *value = purple_unescape_text(escaped);
      g_free(escaped);
      return value;
    }
  }
  return NULL;
}

static gboolean
parser_address_matches(const char *value, const char *expected)
{
  char *canonical;
  gboolean matches;
  if (!value) return TRUE;
  canonical = barev_address_identity(value, FALSE);
  matches = canonical && expected && !strcmp(canonical, expected);
  g_free(canonical);
  return matches;
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

  if (!bconv || bconv->closing || bconv->close_timeout) return;
  if (!element_name || nb_attributes > 128 || nb_namespaces > 128) {
    parser_reject(bconv, "XML attribute limit");
    return;
  }

  if (!bconv->recv_stream_start) {
    char *from, *to, *version, *local;
    gboolean valid;
    if (bconv->current || bconv->header_last == '/' || xmlStrcmp(element_name, (const xmlChar *)"stream") ||
        (bconv->context->encoding && g_ascii_strcasecmp((const char *)bconv->context->encoding, "UTF-8")) ||
        (bconv->context->version && xmlStrcmp(bconv->context->version, (const xmlChar *)"1.0")) ||
        !namespace || xmlStrcmp(namespace, (const xmlChar *)STREAM_NS)) {
      parser_reject(bconv, "expected stream header");
      return;
    }
    from = parser_attribute(nb_attributes, attributes, "from");
    to = parser_attribute(nb_attributes, attributes, "to");
    version = parser_attribute(nb_attributes, attributes, "version");
    local = barev_address_identity(bonjour_jabber_get_local_jid(bconv), FALSE);
    valid = from && *from && local && parser_address_matches(to, local) &&
        (!version || !strcmp(version, "1.0"));
    g_free(local); g_free(to); g_free(version);
    if (!valid) {
      g_free(from);
      parser_reject(bconv, "invalid stream identity, recipient or version");
      return;
    }

    /* Keep the outgoing contact attached until the matcher checks its identity. */
    g_free(bconv->buddy_name);
    bconv->buddy_name = from;
    bonjour_jabber_conv_match_by_name(bconv);
    if (bconv->closing || bconv->close_timeout) return;
    if (!bconv->pb) {
      parser_reject(bconv, "unknown stream identity");
      return;
    }
    bconv->recv_stream_start = TRUE;
    /* SAX starts the root before consuming its final '>' byte. */
    bconv->frame_end = bconv->header_bytes;
    ++bconv->input_events;
    bconv->frame_started = g_get_monotonic_time();
    bonjour_jabber_stream_started(bconv);
    return;
  }

  if (!bconv->current) {
    char *from = parser_attribute(nb_attributes, attributes, "from");
    char *to = parser_attribute(nb_attributes, attributes, "to");
    char *local = barev_address_identity(bonjour_jabber_get_local_jid(bconv), FALSE);
    gboolean valid = bconv->pb && local &&
        parser_address_matches(from, bconv->buddy_name) && parser_address_matches(to, local);
    g_free(from); g_free(to); g_free(local);
    if (!valid) {
      parser_reject(bconv, "stanza identity mismatch");
      return;
    }
    if (namespace && !xmlStrcmp(namespace, (const xmlChar *)STREAM_NS) &&
        !xmlStrcmp(element_name, (const xmlChar *)"stream")) {
      parser_reject(bconv, "duplicate stream header");
      return;
    }
    bconv->stanza_depth = bconv->stanza_nodes = 0;
  }

  bconv->stanza_nodes += 1+nb_attributes;
  if (parser_position(bconv)-bconv->frame_end > STANZA_LIMIT ||
      ++bconv->stanza_depth > 24 || bconv->stanza_nodes > 512) {
    parser_reject(bconv, "XML stanza limit");
    return;
  }
  node = bconv->current ? xmlnode_new_child(bconv->current, (const char *)element_name) :
      xmlnode_new((const char *)element_name);
  xmlnode_set_namespace(node, (const char *)namespace);
  for (i = 0; i < nb_attributes * 5; i += 5) {
    char *escaped = g_strndup((const char *)attributes[i+3], attributes[i+4]-attributes[i+3]);
    char *value = purple_unescape_text(escaped);
    xmlnode_set_attrib_full(node, (const char *)attributes[i],
        (const char *)attributes[i+2], (const char *)attributes[i+1], value);
    g_free(value); g_free(escaped);
  }
  bconv->current = node;
}

static void
bonjour_parser_element_end_libxml(void *user_data, const xmlChar *element_name,
    const xmlChar *prefix, const xmlChar *namespace)
{
  BonjourJabberConversation *bconv = user_data;
  if (!bconv || bconv->closing || bconv->close_timeout) return;
  if (!bconv->current) {
    parser_reject(bconv, "stream closed");
    return;
  }
  if (bconv->current->parent) {
    --bconv->stanza_depth;
    bconv->current = bconv->current->parent;
  } else {
    xmlnode *packet = bconv->current;
    const char *ns = xmlnode_get_namespace(packet);
    guint64 end = parser_position(bconv);
    bconv->current = NULL;
    bconv->stanza_depth = bconv->stanza_nodes = 0;
    bconv->frame_started = g_get_monotonic_time();
    if (end-bconv->frame_end > STANZA_LIMIT || ++bconv->input_events > 64) {
      parser_reject(bconv, "XML frame or input work limit");
    } else if (ns && !strcmp(ns, STREAM_NS)) {
      if (!strcmp(packet->name, "error")) parser_reject(bconv, "peer stream error");
    } else if (ns && !strcmp(ns, CLIENT_NS)) {
      bonjour_jabber_process_packet(bconv->pb, packet);
      if (!bconv->closing && !bconv->close_timeout && !strcmp(packet->name, "presence") &&
          g_strcmp0(xmlnode_get_attrib(packet, "type"), "unavailable") == 0)
        parser_reject(bconv, "peer unavailable");
    }
    bconv->frame_end = end;
    xmlnode_free(packet);
  }
}

static void
bonjour_parser_element_text_libxml(void *user_data, const xmlChar *text, int length)
{
  BonjourJabberConversation *bconv = user_data;
  if (!bconv || bconv->closing || bconv->close_timeout || !text || !length) return;
  if (!bconv->current) {
    int i;
    for (i = 0; i < length; ++i) {
      if (text[i] != ' ' && text[i] != '\t' && text[i] != '\r' && text[i] != '\n') {
        parser_reject(bconv, "text outside stanza");
        break;
      }
    }
    return;
  }
  if (length < 0 || parser_position(bconv)-bconv->frame_end > STANZA_LIMIT ||
      ++bconv->stanza_nodes > 512) {
    parser_reject(bconv, "XML text limit");
    return;
  }
  xmlnode_insert_data(bconv->current, (const char *)text, length);
}

static void
bonjour_parser_subset(void *user_data, const xmlChar *name,
    const xmlChar *external_id, const xmlChar *system_id)
{
  parser_reject(user_data, "DOCTYPE is not allowed");
}

static void
bonjour_parser_structured_error_handler(void *user_data, const xmlError *error)
{
  BonjourJabberConversation *bconv = user_data;
  /* XEP-0054 uses the relative namespace vcard-temp. */
  if (!error || (error->code == XML_WAR_NS_URI_RELATIVE && error->message &&
      strstr(error->message, "vcard-temp"))) return;
  purple_debug_warning("barev", "XML parser: %s", error->message ? error->message : "invalid XML\n");
  if (bconv && error->level >= XML_ERR_ERROR)
    parser_reject(bconv, "invalid XML");
}

static xmlSAXHandler bonjour_parser_libxml = {
  .internalSubset = bonjour_parser_subset,
  .externalSubset = bonjour_parser_subset,
  .characters = bonjour_parser_element_text_libxml,
  .cdataBlock = bonjour_parser_element_text_libxml,
  .initialized = XML_SAX2_MAGIC,
  .startElementNs = bonjour_parser_element_start_libxml,
  .endElementNs = bonjour_parser_element_end_libxml,
  .serror = (xmlStructuredErrorFunc)bonjour_parser_structured_error_handler
};

void
bonjour_parser_setup(BonjourJabberConversation *bconv)
{
  bonjour_parser_destroy(bconv);
  bconv->recv_stream_start = FALSE;
  bconv->header_bytes = 0;
  bconv->header_last = 0;
  bconv->received_bytes = bconv->frame_end = 0;
  bconv->stanza_depth = bconv->stanza_nodes = 0;
}

void
bonjour_parser_destroy(BonjourJabberConversation *bconv)
{
  xmlnode *root;
  if (!bconv) return;
  if (bconv->context) {
    xmlFreeParserCtxt(bconv->context);
    bconv->context = NULL;
  }
  root = bconv->current;
  while (root && root->parent) root = root->parent;
  if (root) xmlnode_free(root);
  bconv->current = NULL;
}

void
bonjour_parser_process(BonjourJabberConversation *bconv, const char *buf, int len)
{
  int at = 0, result = 0, i;
  if (!bconv || bconv->closing || bconv->close_timeout) return;
  bconv->in_parser = TRUE;
  bconv->input_events = 0;
  if (!buf || len < 0 || len > 16384) {
    parser_reject(bconv, "input chunk limit");
  } else {
    for (i = 0; i < len; ++i) {
      if (!buf[i]) {
        parser_reject(bconv, "UTF-8 XML cannot contain NUL bytes");
        bconv->in_parser = FALSE;
        return;
      }
    }
    if (!bconv->context)
      bconv->context = xmlCreatePushParserCtxt(&bonjour_parser_libxml, bconv, NULL, 0, NULL);
    if (!bconv->context) {
      parser_reject(bconv, "cannot create XML parser");
    } else {
      /* Feed the bounded header separately so stanza bytes in the same read do
       * not count against its limit, and incomplete headers cannot grow forever. */
      while (at < len && !bconv->recv_stream_start && !bconv->close_timeout && !bconv->closing) {
        if (++bconv->header_bytes > HEADER_LIMIT) {
          parser_reject(bconv, "stream header limit");
          break;
        }
        result = xmlParseChunk(bconv->context, buf+at, 1, 0);
        ++bconv->received_bytes;
        bconv->header_last = buf[at++];
        if (result || !bconv->context->wellFormed) {
          parser_reject(bconv, "invalid XML");
          break;
        }
      }
      if (at < len && !bconv->close_timeout && !bconv->closing) {
        bconv->received_bytes += len-at;
        result = xmlParseChunk(bconv->context, buf+at, len-at, 0);
        if (result || !bconv->context->wellFormed) parser_reject(bconv, "invalid XML");
        if (bconv->received_bytes-bconv->frame_end > STANZA_LIMIT)
          parser_reject(bconv, "XML frame limit");
      }
    }
  }
  bconv->in_parser = FALSE;
}
