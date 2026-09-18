/*
 * Jingle signalling for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/jingle.h
 * JabberStream replaced with BonjourJabberConversation throughout.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef BAREV_JINGLE_H
#define BAREV_JINGLE_H

#include <glib.h>
#include <glib-object.h>

#include "../jabber.h"  /* BonjourJabberConversation */
#include "xmlnode.h"

G_BEGIN_DECLS

#ifdef __cplusplus
extern "C" {
#endif

#define JINGLE             "urn:xmpp:jingle:1"
#define JINGLE_ERROR       "urn:xmpp:jingle:errors:0"
#define JINGLE_APP_RTP     "urn:xmpp:jingle:apps:rtp:1"
#define JINGLE_APP_RTP_ERROR  "urn:xmpp:jingle:apps:rtp:errors:1"
#define JINGLE_APP_RTP_INFO   "urn:xmpp:jingle:apps:rtp:info:1"
#define JINGLE_APP_RTP_SUPPORT_AUDIO "urn:xmpp:jingle:apps:rtp:audio"
#define JINGLE_APP_RTP_SUPPORT_VIDEO "urn:xmpp:jingle:apps:rtp:video"
#define JINGLE_TRANSPORT_RAWUDP "urn:xmpp:jingle:transports:raw-udp:1"

typedef enum {
	JINGLE_UNKNOWN_TYPE,
	JINGLE_CONTENT_ACCEPT,
	JINGLE_CONTENT_ADD,
	JINGLE_CONTENT_MODIFY,
	JINGLE_CONTENT_REJECT,
	JINGLE_CONTENT_REMOVE,
	JINGLE_DESCRIPTION_INFO,
	JINGLE_SECURITY_INFO,
	JINGLE_SESSION_ACCEPT,
	JINGLE_SESSION_INFO,
	JINGLE_SESSION_INITIATE,
	JINGLE_SESSION_TERMINATE,
	JINGLE_TRANSPORT_ACCEPT,
	JINGLE_TRANSPORT_INFO,
	JINGLE_TRANSPORT_REJECT,
	JINGLE_TRANSPORT_REPLACE,
} JingleActionType;

const gchar *jingle_get_action_name(JingleActionType action);
JingleActionType jingle_get_action_type(const gchar *action);

GType jingle_get_type(const gchar *type);

void barev_jingle_parse(BonjourJabberConversation *bconv, const char *from,
                        const char *type, const char *id, xmlnode *child);

void barev_jingle_terminate_sessions(BonjourJabberConversation *bconv);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* BAREV_JINGLE_H */
