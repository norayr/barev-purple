/*
 * Jingle session for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/session.h
 * JabberStream/JabberIq replaced with BonjourJabberConversation/xmlnode.
 */

#ifndef BAREV_JINGLE_SESSION_H
#define BAREV_JINGLE_SESSION_H

#include "../jabber.h"
#include "jingle.h"

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define JINGLE_TYPE_SESSION            (jingle_session_get_type())
#define JINGLE_SESSION(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_SESSION, JingleSession))
#define JINGLE_SESSION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_SESSION, JingleSessionClass))
#define JINGLE_IS_SESSION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_SESSION))
#define JINGLE_IS_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_SESSION))
#define JINGLE_SESSION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_SESSION, JingleSessionClass))

typedef struct _JingleSession JingleSession;
typedef struct _JingleSessionClass JingleSessionClass;
typedef struct _JingleSessionPrivate JingleSessionPrivate;

struct _JingleSessionClass
{
	GObjectClass parent_class;
};

struct _JingleSession
{
	GObject parent;
	JingleSessionPrivate *priv;
};

struct _JingleContent;

#ifdef __cplusplus
extern "C" {
#endif

GType jingle_session_get_type(void);

JingleSession *jingle_session_create(BonjourJabberConversation *bconv,
		const gchar *sid, const gchar *local_jid, const gchar *remote_jid,
		gboolean is_initiator);

BonjourJabberConversation *jingle_session_get_bconv(JingleSession *session);
gchar *jingle_session_get_sid(JingleSession *session);
gchar *jingle_session_get_local_jid(JingleSession *session);
gchar *jingle_session_get_remote_jid(JingleSession *session);
gboolean jingle_session_is_initiator(JingleSession *session);
gboolean jingle_session_get_state(JingleSession *session);

GList *jingle_session_get_contents(JingleSession *session);
GList *jingle_session_get_pending_contents(JingleSession *session);

JingleSession *jingle_session_find_by_sid(BonjourJabberConversation *bconv, const gchar *sid);
JingleSession *jingle_session_find_by_jid(BonjourJabberConversation *bconv, const gchar *jid);

/* Returns a new <iq type='result'> node (caller must xmlnode_free after sending) */
xmlnode *jingle_session_create_ack(JingleSession *session, const xmlnode *jingle);
xmlnode *jingle_session_to_xml(JingleSession *session, xmlnode *parent, JingleActionType action);
/* Returns a new <iq type='set'> node (caller must xmlnode_free after sending) */
xmlnode *jingle_session_to_packet(JingleSession *session, JingleActionType action);

void jingle_session_handle_action(JingleSession *session, xmlnode *jingle, JingleActionType action);

struct _JingleContent *jingle_session_find_content(JingleSession *session,
		const gchar *name, const gchar *creator);
struct _JingleContent *jingle_session_find_pending_content(JingleSession *session,
		const gchar *name, const gchar *creator);

void jingle_session_add_content(JingleSession *session, struct _JingleContent *content);
void jingle_session_remove_content(JingleSession *session, const gchar *name, const gchar *creator);
void jingle_session_add_pending_content(JingleSession *session, struct _JingleContent *content);
void jingle_session_remove_pending_content(JingleSession *session, const gchar *name, const gchar *creator);
void jingle_session_accept_content(JingleSession *session, const gchar *name, const gchar *creator);
void jingle_session_accept_session(JingleSession *session);

xmlnode *jingle_session_terminate_packet(JingleSession *session, const gchar *reason);
xmlnode *jingle_session_redirect_packet(JingleSession *session, const gchar *sid);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* BAREV_JINGLE_SESSION_H */
