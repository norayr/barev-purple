/*
 * Raw UDP transport for barev-purple Jingle.
 * Adapted from libpurple/protocols/jabber/jingle/rawudp.h
 * No JabberStream dependency — copied verbatim with updated includes.
 */

#ifndef BAREV_JINGLE_RAWUDP_H
#define BAREV_JINGLE_RAWUDP_H

#include <glib.h>
#include <glib-object.h>

#include "transport.h"

G_BEGIN_DECLS

#define JINGLE_TYPE_RAWUDP            (jingle_rawudp_get_type())
#define JINGLE_TYPE_RAWUDP_CANDIDATE  (jingle_rawudp_candidate_get_type())
#define JINGLE_RAWUDP(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_RAWUDP, JingleRawUdp))
#define JINGLE_RAWUDP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_RAWUDP, JingleRawUdpClass))
#define JINGLE_IS_RAWUDP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_RAWUDP))
#define JINGLE_IS_RAWUDP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_RAWUDP))
#define JINGLE_RAWUDP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_RAWUDP, JingleRawUdpClass))

typedef struct _JingleRawUdp JingleRawUdp;
typedef struct _JingleRawUdpClass JingleRawUdpClass;
typedef struct _JingleRawUdpPrivate JingleRawUdpPrivate;
typedef struct _JingleRawUdpCandidate JingleRawUdpCandidate;

struct _JingleRawUdpClass
{
	JingleTransportClass parent_class;

	xmlnode *(*to_xml) (JingleTransport *transport, xmlnode *content, JingleActionType action);
	JingleTransport *(*parse) (xmlnode *transport);
};

struct _JingleRawUdp
{
	JingleTransport parent;
	JingleRawUdpPrivate *priv;
};

struct _JingleRawUdpCandidate
{
	guint generation;
	guint component;
	gchar *id;
	gchar *ip;
	guint port;
	gboolean rem_known;
};

#ifdef __cplusplus
extern "C" {
#endif

GType jingle_rawudp_candidate_get_type(void);
GType jingle_rawudp_get_type(void);

JingleRawUdpCandidate *jingle_rawudp_candidate_new(const gchar *id,
		guint generation, guint component, const gchar *ip, guint port);
void jingle_rawudp_add_local_candidate(JingleRawUdp *rawudp,
		JingleRawUdpCandidate *candidate);
GList *jingle_rawudp_get_remote_candidates(JingleRawUdp *rawudp);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* BAREV_JINGLE_RAWUDP_H */
