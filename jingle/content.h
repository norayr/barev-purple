/*
 * Jingle content for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/content.h
 * Removed jabber.h dependency (JabberStream not needed here).
 */

#ifndef BAREV_JINGLE_CONTENT_H
#define BAREV_JINGLE_CONTENT_H

#include "jingle.h"
#include "session.h"
#include "transport.h"

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define JINGLE_TYPE_CONTENT            (jingle_content_get_type())
#define JINGLE_CONTENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_CONTENT, JingleContent))
#define JINGLE_CONTENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_CONTENT, JingleContentClass))
#define JINGLE_IS_CONTENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_CONTENT))
#define JINGLE_IS_CONTENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_CONTENT))
#define JINGLE_CONTENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_CONTENT, JingleContentClass))

typedef struct _JingleContent JingleContent;
typedef struct _JingleContentClass JingleContentClass;
typedef struct _JingleContentPrivate JingleContentPrivate;

struct _JingleContentClass
{
	GObjectClass parent_class;

	xmlnode *(*to_xml) (JingleContent *content, xmlnode *jingle, JingleActionType action);
	JingleContent *(*parse) (xmlnode *content);
	void (*handle_action) (JingleContent *content, xmlnode *xmlcontent, JingleActionType action);
	const gchar *description_type;
};

struct _JingleContent
{
	GObject parent;
	JingleContentPrivate *priv;
};

#ifdef __cplusplus
extern "C" {
#endif

GType jingle_content_get_type(void);

JingleContent *jingle_content_create(const gchar *type, const gchar *creator,
		const gchar *disposition, const gchar *name,
		const gchar *senders, JingleTransport *transport);

JingleSession *jingle_content_get_session(JingleContent *content);
const gchar *jingle_content_get_description_type(JingleContent *content);
gchar *jingle_content_get_creator(JingleContent *content);
gchar *jingle_content_get_disposition(JingleContent *content);
gchar *jingle_content_get_name(JingleContent *content);
gchar *jingle_content_get_senders(JingleContent *content);
JingleTransport *jingle_content_get_transport(JingleContent *content);
JingleTransport *jingle_content_get_pending_transport(JingleContent *content);

void jingle_content_set_session(JingleContent *content, JingleSession *session);
void jingle_content_set_pending_transport(JingleContent *content, JingleTransport *transport);
void jingle_content_accept_transport(JingleContent *content);
void jingle_content_remove_pending_transport(JingleContent *content);
void jingle_content_modify(JingleContent *content, const gchar *senders);

#define jingle_content_create_content_accept(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_ACCEPT)
#define jingle_content_create_content_add(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_ADD)
#define jingle_content_create_content_modify(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_MODIFY)
#define jingle_content_create_content_remove(session) \
	jingle_session_to_packet(session, JINGLE_CONTENT_REMOVE)

JingleContent *jingle_content_parse(xmlnode *content);
xmlnode *jingle_content_to_xml(JingleContent *content, xmlnode *jingle, JingleActionType action);
void jingle_content_handle_action(JingleContent *content, xmlnode *xmlcontent, JingleActionType action);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* BAREV_JINGLE_CONTENT_H */
