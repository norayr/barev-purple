/*
 * Jingle session for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/session.c
 * JabberStream replaced with BonjourJabberConversation.
 * JabberIq replaced with xmlnode (bare <iq> element).
 */

#include "content.h"
#include "debug.h"
#include "session.h"
#include "jingle.h"
#include "../jabber.h"

#include <string.h>

struct _JingleSessionPrivate
{
	gchar *sid;
	BonjourJabberConversation *bconv;
	gchar *remote_jid;
	gchar *local_jid;
	gboolean is_initiator;
	gboolean state;
	GList *contents;
	GList *pending_contents;
};

#define JINGLE_SESSION_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE((obj), JINGLE_TYPE_SESSION, JingleSessionPrivate))

static void jingle_session_class_init(JingleSessionClass *klass);
static void jingle_session_init(JingleSession *session);
static void jingle_session_finalize(GObject *object);
static void jingle_session_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void jingle_session_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);

static GObjectClass *parent_class = NULL;

enum {
	PROP_0,
	PROP_SID,
	PROP_BCONV,
	PROP_REMOTE_JID,
	PROP_LOCAL_JID,
	PROP_IS_INITIATOR,
	PROP_STATE,
	PROP_CONTENTS,
	PROP_PENDING_CONTENTS,
};

GType
jingle_session_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(JingleSessionClass), NULL, NULL,
			(GClassInitFunc) jingle_session_class_init,
			NULL, NULL, sizeof(JingleSession), 0,
			(GInstanceInitFunc) jingle_session_init, NULL
		};
		type = g_type_register_static(G_TYPE_OBJECT, "JingleSession", &info, 0);
	}
	return type;
}

static void
jingle_session_class_init(JingleSessionClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->finalize = jingle_session_finalize;
	gobject_class->set_property = jingle_session_set_property;
	gobject_class->get_property = jingle_session_get_property;

	g_object_class_install_property(gobject_class, PROP_SID,
			g_param_spec_string("sid", "Session ID",
			"The unique session ID of the Jingle Session.", NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_BCONV,
			g_param_spec_pointer("bconv", "BonjourJabberConversation",
			"The conversation associated with this session.",
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_REMOTE_JID,
			g_param_spec_string("remote-jid", "Remote JID",
			"The JID of the remote participant.", NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_LOCAL_JID,
			g_param_spec_string("local-jid", "Local JID",
			"The JID of the local participant.", NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_IS_INITIATOR,
			g_param_spec_boolean("is-initiator", "Is Initiator",
			"Whether the local JID is the initiator.", FALSE,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_STATE,
			g_param_spec_boolean("state", "State",
			"Session state (PENDING=FALSE, ACTIVE=TRUE).", FALSE,
			G_PARAM_READABLE));
	g_object_class_install_property(gobject_class, PROP_CONTENTS,
			g_param_spec_pointer("contents", "Contents",
			"Active contents.", G_PARAM_READABLE));
	g_object_class_install_property(gobject_class, PROP_PENDING_CONTENTS,
			g_param_spec_pointer("pending-contents", "Pending contents",
			"Pending contents.", G_PARAM_READABLE));

	g_type_class_add_private(klass, sizeof(JingleSessionPrivate));
}

static void
jingle_session_init(JingleSession *session)
{
	session->priv = JINGLE_SESSION_GET_PRIVATE(session);
	memset(session->priv, 0, sizeof(*session->priv));
}

static void
jingle_session_finalize(GObject *session)
{
	JingleSessionPrivate *priv = JINGLE_SESSION_GET_PRIVATE(session);
	purple_debug_info("jingle", "jingle_session_finalize\n");

	if (priv->bconv && priv->bconv->jingle_sessions)
		g_hash_table_remove(priv->bconv->jingle_sessions, priv->sid);

	g_free(priv->sid);
	g_free(priv->remote_jid);
	g_free(priv->local_jid);

	for (; priv->contents;
			priv->contents = g_list_delete_link(priv->contents, priv->contents))
		g_object_unref(priv->contents->data);
	for (; priv->pending_contents;
			priv->pending_contents = g_list_delete_link(priv->pending_contents, priv->pending_contents))
		g_object_unref(priv->pending_contents->data);

	parent_class->finalize(session);
}

static void
jingle_session_set_property(GObject *object, guint prop_id,
		const GValue *value, GParamSpec *pspec)
{
	g_return_if_fail(JINGLE_IS_SESSION(object));
	JingleSession *session = JINGLE_SESSION(object);
	switch (prop_id) {
		case PROP_SID:
			g_free(session->priv->sid);
			session->priv->sid = g_value_dup_string(value);
			break;
		case PROP_BCONV:
			session->priv->bconv = g_value_get_pointer(value);
			break;
		case PROP_REMOTE_JID:
			g_free(session->priv->remote_jid);
			session->priv->remote_jid = g_value_dup_string(value);
			break;
		case PROP_LOCAL_JID:
			g_free(session->priv->local_jid);
			session->priv->local_jid = g_value_dup_string(value);
			break;
		case PROP_IS_INITIATOR:
			session->priv->is_initiator = g_value_get_boolean(value);
			break;
		case PROP_STATE:
			session->priv->state = g_value_get_boolean(value);
			break;
		case PROP_CONTENTS:
			session->priv->contents = g_value_get_pointer(value);
			break;
		case PROP_PENDING_CONTENTS:
			session->priv->pending_contents = g_value_get_pointer(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void
jingle_session_get_property(GObject *object, guint prop_id,
		GValue *value, GParamSpec *pspec)
{
	g_return_if_fail(JINGLE_IS_SESSION(object));
	JingleSession *session = JINGLE_SESSION(object);
	switch (prop_id) {
		case PROP_SID:
			g_value_set_string(value, session->priv->sid);
			break;
		case PROP_BCONV:
			g_value_set_pointer(value, session->priv->bconv);
			break;
		case PROP_REMOTE_JID:
			g_value_set_string(value, session->priv->remote_jid);
			break;
		case PROP_LOCAL_JID:
			g_value_set_string(value, session->priv->local_jid);
			break;
		case PROP_IS_INITIATOR:
			g_value_set_boolean(value, session->priv->is_initiator);
			break;
		case PROP_STATE:
			g_value_set_boolean(value, session->priv->state);
			break;
		case PROP_CONTENTS:
			g_value_set_pointer(value, session->priv->contents);
			break;
		case PROP_PENDING_CONTENTS:
			g_value_set_pointer(value, session->priv->pending_contents);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

JingleSession *
jingle_session_create(BonjourJabberConversation *bconv, const gchar *sid,
		const gchar *local_jid, const gchar *remote_jid,
		gboolean is_initiator)
{
	JingleSession *session = g_object_new(jingle_session_get_type(),
			"bconv", bconv,
			"sid", sid,
			"local-jid", local_jid,
			"remote-jid", remote_jid,
			"is-initiator", is_initiator,
			NULL);

	if (!bconv->jingle_sessions) {
		purple_debug_info("jingle", "Creating hash table for sessions\n");
		bconv->jingle_sessions = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, NULL);
	}
	purple_debug_info("jingle", "inserting session sid=%s\n", sid);
	g_hash_table_insert(bconv->jingle_sessions, g_strdup(sid), session);

	return session;
}

BonjourJabberConversation *
jingle_session_get_bconv(JingleSession *session)
{
	BonjourJabberConversation *bconv;
	g_object_get(session, "bconv", &bconv, NULL);
	return bconv;
}

gchar *
jingle_session_get_sid(JingleSession *session)
{
	gchar *sid;
	g_object_get(session, "sid", &sid, NULL);
	return sid;
}

gchar *
jingle_session_get_local_jid(JingleSession *session)
{
	gchar *local_jid;
	g_object_get(session, "local-jid", &local_jid, NULL);
	return local_jid;
}

gchar *
jingle_session_get_remote_jid(JingleSession *session)
{
	gchar *remote_jid;
	g_object_get(session, "remote-jid", &remote_jid, NULL);
	return remote_jid;
}

gboolean
jingle_session_is_initiator(JingleSession *session)
{
	gboolean is_initiator;
	g_object_get(session, "is-initiator", &is_initiator, NULL);
	return is_initiator;
}

gboolean
jingle_session_get_state(JingleSession *session)
{
	gboolean state;
	g_object_get(session, "state", &state, NULL);
	return state;
}

GList *
jingle_session_get_contents(JingleSession *session)
{
	GList *contents;
	g_object_get(session, "contents", &contents, NULL);
	return contents;
}

GList *
jingle_session_get_pending_contents(JingleSession *session)
{
	GList *pending_contents;
	g_object_get(session, "pending-contents", &pending_contents, NULL);
	return pending_contents;
}

JingleSession *
jingle_session_find_by_sid(BonjourJabberConversation *bconv, const gchar *sid)
{
	JingleSession *session = NULL;
	if (bconv->jingle_sessions)
		session = g_hash_table_lookup(bconv->jingle_sessions, sid);
	purple_debug_info("jingle", "find_by_sid %s: %p\n", sid, session);
	return session;
}

gboolean
jingle_session_is_registered(JingleSession *session)
{
	JingleSessionPrivate *priv = session->priv;
	return priv->bconv->jingle_sessions != NULL &&
			g_hash_table_lookup(priv->bconv->jingle_sessions, priv->sid) == session;
}

void
jingle_session_unregister(JingleSession *session)
{
	if (jingle_session_is_registered(session))
		g_hash_table_remove(session->priv->bconv->jingle_sessions,
				session->priv->sid);
}

static gboolean
find_by_jid_ghr(gpointer key, gpointer value, gpointer user_data)
{
	JingleSession *session = (JingleSession *)value;
	const gchar *jid = user_data;
	gchar *remote_jid = jingle_session_get_remote_jid(session);
	gboolean match = purple_strequal(jid, remote_jid);
	g_free(remote_jid);
	return match;
}

JingleSession *
jingle_session_find_by_jid(BonjourJabberConversation *bconv, const gchar *jid)
{
	return bconv->jingle_sessions ?
			g_hash_table_find(bconv->jingle_sessions, find_by_jid_ghr,
			(gpointer)jid) : NULL;
}

/* Build the <jingle> child of an IQ node */
static xmlnode *
jingle_add_jingle_packet(JingleSession *session, xmlnode *iq,
		JingleActionType action)
{
	xmlnode *jingle = xmlnode_new_child(iq, "jingle");
	gchar *local_jid = jingle_session_get_local_jid(session);
	gchar *remote_jid = jingle_session_get_remote_jid(session);
	gchar *sid = jingle_session_get_sid(session);

	xmlnode_set_namespace(jingle, JINGLE);
	xmlnode_set_attrib(jingle, "action", jingle_get_action_name(action));

	if (jingle_session_is_initiator(session)) {
		xmlnode_set_attrib(jingle, "initiator", local_jid);
		xmlnode_set_attrib(jingle, "responder", remote_jid);
	} else {
		xmlnode_set_attrib(jingle, "initiator", remote_jid);
		xmlnode_set_attrib(jingle, "responder", local_jid);
	}
	xmlnode_set_attrib(jingle, "sid", sid);

	g_free(local_jid);
	g_free(remote_jid);
	g_free(sid);
	return jingle;
}

xmlnode *
jingle_session_create_ack(JingleSession *session, const xmlnode *jingle)
{
	/* jingle's parent is the incoming <iq> */
	xmlnode *packet = xmlnode_get_parent((xmlnode *)jingle);
	const char *id   = xmlnode_get_attrib(packet, "id");
	const char *from = xmlnode_get_attrib(packet, "from");
	const char *to   = xmlnode_get_attrib(packet, "to");

	xmlnode *result = xmlnode_new("iq");
	xmlnode_set_attrib(result, "type", "result");
	if (id)   xmlnode_set_attrib(result, "id",   id);
	if (from) xmlnode_set_attrib(result, "to",   from);
	if (to)   xmlnode_set_attrib(result, "from", to);
	return result;
}

/* Build a new outgoing <iq type='set'> with a fresh ID */
static xmlnode *
jingle_create_outgoing_iq(JingleSession *session)
{
	gchar *from = jingle_session_get_local_jid(session);
	gchar *to   = jingle_session_get_remote_jid(session);
	gchar *id   = bonjour_jabber_next_id();

	xmlnode *iq = xmlnode_new("iq");
	xmlnode_set_attrib(iq, "type", "set");
	xmlnode_set_attrib(iq, "from", from);
	xmlnode_set_attrib(iq, "to",   to);
	xmlnode_set_attrib(iq, "id",   id);

	g_free(from);
	g_free(to);
	g_free(id);
	return iq;
}

xmlnode *
jingle_session_to_xml(JingleSession *session, xmlnode *jingle,
		JingleActionType action)
{
	if (action != JINGLE_SESSION_INFO && action != JINGLE_SESSION_TERMINATE) {
		GList *iter;
		if (action == JINGLE_CONTENT_ACCEPT ||
				action == JINGLE_CONTENT_ADD ||
				action == JINGLE_CONTENT_REMOVE)
			iter = jingle_session_get_pending_contents(session);
		else
			iter = jingle_session_get_contents(session);

		for (; iter; iter = g_list_next(iter))
			jingle_content_to_xml(iter->data, jingle, action);
	}
	return jingle;
}

xmlnode *
jingle_session_to_packet(JingleSession *session, JingleActionType action)
{
	xmlnode *iq = jingle_create_outgoing_iq(session);
	xmlnode *jingle = jingle_add_jingle_packet(session, iq, action);
	jingle_session_to_xml(session, jingle, action);
	return iq;
}

void
jingle_session_handle_action(JingleSession *session, xmlnode *jingle,
		JingleActionType action)
{
	GList *iter;
	if (action == JINGLE_CONTENT_ADD || action == JINGLE_CONTENT_REMOVE)
		iter = jingle_session_get_pending_contents(session);
	else
		iter = jingle_session_get_contents(session);

	for (; iter; iter = g_list_next(iter))
		jingle_content_handle_action(iter->data, jingle, action);
}

JingleContent *
jingle_session_find_content(JingleSession *session, const gchar *name,
		const gchar *creator)
{
	GList *iter;
	if (name == NULL)
		return NULL;

	iter = session->priv->contents;
	for (; iter; iter = g_list_next(iter)) {
		JingleContent *content = iter->data;
		gchar *cname = jingle_content_get_name(content);
		gboolean result = purple_strequal(name, cname);
		g_free(cname);
		if (creator != NULL) {
			gchar *ccreator = jingle_content_get_creator(content);
			result = (result && purple_strequal(creator, ccreator));
			g_free(ccreator);
		}
		if (result)
			return content;
	}
	return NULL;
}

JingleContent *
jingle_session_find_pending_content(JingleSession *session, const gchar *name,
		const gchar *creator)
{
	GList *iter;
	if (name == NULL)
		return NULL;

	iter = session->priv->pending_contents;
	for (; iter; iter = g_list_next(iter)) {
		JingleContent *content = iter->data;
		gchar *cname = jingle_content_get_name(content);
		gboolean result = purple_strequal(name, cname);
		g_free(cname);
		if (creator != NULL) {
			gchar *ccreator = jingle_content_get_creator(content);
			result = (result && purple_strequal(creator, ccreator));
			g_free(ccreator);
		}
		if (result)
			return content;
	}
	return NULL;
}

void
jingle_session_add_content(JingleSession *session, JingleContent *content)
{
	session->priv->contents = g_list_append(session->priv->contents, content);
	jingle_content_set_session(content, session);
}

void
jingle_session_remove_content(JingleSession *session, const gchar *name,
		const gchar *creator)
{
	JingleContent *content = jingle_session_find_content(session, name, creator);
	if (content) {
		session->priv->contents = g_list_remove(session->priv->contents, content);
		g_object_unref(content);
	}
}

void
jingle_session_add_pending_content(JingleSession *session, JingleContent *content)
{
	session->priv->pending_contents =
			g_list_append(session->priv->pending_contents, content);
	jingle_content_set_session(content, session);
}

void
jingle_session_remove_pending_content(JingleSession *session, const gchar *name,
		const gchar *creator)
{
	JingleContent *content =
			jingle_session_find_pending_content(session, name, creator);
	if (content) {
		session->priv->pending_contents =
				g_list_remove(session->priv->pending_contents, content);
		g_object_unref(content);
	}
}

void
jingle_session_accept_content(JingleSession *session, const gchar *name,
		const gchar *creator)
{
	JingleContent *content =
			jingle_session_find_pending_content(session, name, creator);
	if (content) {
		g_object_ref(content);
		jingle_session_remove_pending_content(session, name, creator);
		jingle_session_add_content(session, content);
	}
}

void
jingle_session_accept_session(JingleSession *session)
{
	session->priv->state = TRUE;
}

xmlnode *
jingle_session_terminate_packet(JingleSession *session, const gchar *reason)
{
	xmlnode *iq = jingle_session_to_packet(session, JINGLE_SESSION_TERMINATE);
	xmlnode *jingle = xmlnode_get_child(iq, "jingle");

	if (reason != NULL) {
		xmlnode *reason_node = xmlnode_new_child(jingle, "reason");
		xmlnode_new_child(reason_node, reason);
	}
	return iq;
}

xmlnode *
jingle_session_redirect_packet(JingleSession *session, const gchar *sid)
{
	xmlnode *iq = jingle_session_terminate_packet(session, "alternative-session");
	xmlnode *alt_session;

	if (sid == NULL)
		return iq;

	alt_session = xmlnode_get_child(iq, "jingle/reason/alternative-session");
	if (alt_session != NULL) {
		xmlnode *sid_node = xmlnode_new_child(alt_session, "sid");
		xmlnode_insert_data(sid_node, sid, -1);
	}
	return iq;
}
