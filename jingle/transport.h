/*
 * Jingle transport base class for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/transport.h
 * No JabberStream dependency — copied verbatim with updated includes.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef BAREV_JINGLE_TRANSPORT_H
#define BAREV_JINGLE_TRANSPORT_H

#include <glib.h>
#include <glib-object.h>

#include "jingle.h"
#include "xmlnode.h"

G_BEGIN_DECLS

#define JINGLE_TYPE_TRANSPORT            (jingle_transport_get_type())
#define JINGLE_TRANSPORT(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_TRANSPORT, JingleTransport))
#define JINGLE_TRANSPORT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_TRANSPORT, JingleTransportClass))
#define JINGLE_IS_TRANSPORT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_TRANSPORT))
#define JINGLE_IS_TRANSPORT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_TRANSPORT))
#define JINGLE_TRANSPORT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_TRANSPORT, JingleTransportClass))

typedef struct _JingleTransport JingleTransport;
typedef struct _JingleTransportClass JingleTransportClass;
typedef struct _JingleTransportPrivate JingleTransportPrivate;

struct _JingleTransportClass
{
	GObjectClass parent_class;

	const gchar *transport_type;
	xmlnode *(*to_xml) (JingleTransport *transport, xmlnode *content, JingleActionType action);
	JingleTransport *(*parse) (xmlnode *transport);
};

struct _JingleTransport
{
	GObject parent;
	JingleTransportPrivate *priv;
};

#ifdef __cplusplus
extern "C" {
#endif

GType jingle_transport_get_type(void);

JingleTransport *jingle_transport_create(const gchar *type);
const gchar *jingle_transport_get_transport_type(JingleTransport *transport);

JingleTransport *jingle_transport_parse(xmlnode *transport);
xmlnode *jingle_transport_to_xml(JingleTransport *transport, xmlnode *content, JingleActionType action);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* BAREV_JINGLE_TRANSPORT_H */
