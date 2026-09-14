/*
 * Jingle signalling for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/jingle.c
 * JabberStream replaced with BonjourJabberConversation.
 * jabber_iq_send() replaced with bonjour_jabber_send_xml().
 * ICE-UDP and STUN/TURN support removed.
 */

#include "content.h"
#include "debug.h"
#include "jingle.h"
#include "session.h"
#include "rawudp.h"
#include "rtp.h"
#include "../jabber.h"

#include <string.h>

GType
jingle_get_type(const gchar *type)
{
	GType result = G_TYPE_NONE;

	if (type == NULL) {
		purple_debug_info("jingle", "jingle_get_type(NULL) -> G_TYPE_NONE\n");
		return G_TYPE_NONE;
	}

	if (purple_strequal(type, JINGLE_TRANSPORT_RAWUDP)) {
		result = JINGLE_TYPE_RAWUDP;
		purple_debug_info("jingle", "jingle_get_type(%s) -> JINGLE_TYPE_RAWUDP=%lu\n",
		                  type, (unsigned long)result);
		return result;
	}
#ifdef USE_VV
	else if (purple_strequal(type, JINGLE_APP_RTP)) {
		result = JINGLE_TYPE_RTP;
		purple_debug_info("jingle", "jingle_get_type(%s) -> JINGLE_TYPE_RTP=%lu\n",
		                  type, (unsigned long)result);
		return result;
	}
#endif
	purple_debug_info("jingle", "jingle_get_type(%s) unknown -> G_TYPE_NONE\n", type);
	return G_TYPE_NONE;
}

/* Send an IQ xmlnode and free it */
static void
jingle_send_and_free(JingleSession *session, xmlnode *iq)
{
	BonjourJabberConversation *bconv = jingle_session_get_bconv(session);
	bonjour_jabber_send_xml(bconv, iq);
	xmlnode_free(iq);
}

static void
jingle_handle_unknown_type(JingleSession *session, xmlnode *jingle)
{
	(void)session; (void)jingle;
}

static void
jingle_handle_content_accept(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		jingle_session_accept_content(session, name, creator);
	}
}

static void
jingle_handle_content_add(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		JingleContent *pending_content = jingle_content_parse(content);
		if (pending_content == NULL) {
			purple_debug_error("jingle",
					"Error parsing \"content-add\" content.\n");
			jingle_send_and_free(session,
					jingle_session_terminate_packet(session,
					"unsupported-applications"));
		} else {
			jingle_session_add_pending_content(session, pending_content);
		}
	}
}

static void
jingle_handle_content_modify(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *local_content =
				jingle_session_find_content(session, name, creator);
		if (local_content != NULL) {
			const gchar *senders = xmlnode_get_attrib(content, "senders");
			gchar *local_senders = jingle_content_get_senders(local_content);
			if (!purple_strequal(senders, local_senders))
				jingle_content_modify(local_content, senders);
			g_free(local_senders);
		} else {
			purple_debug_error("jingle", "content_modify: unknown content\n");
			jingle_send_and_free(session,
					jingle_session_terminate_packet(session,
					"unknown-applications"));
		}
	}
}

static void
jingle_handle_content_reject(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		jingle_session_remove_pending_content(session, name, creator);
	}
}

static void
jingle_handle_content_remove(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		jingle_session_remove_content(session, name, creator);
	}
}

static void
jingle_handle_description_info(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	jingle_session_accept_session(session);

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *parsed_content =
				jingle_session_find_content(session, name, creator);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jingle_send_and_free(session,
					jingle_session_terminate_packet(session,
					"unsupported-applications"));
		} else {
			jingle_content_handle_action(parsed_content, content,
					JINGLE_DESCRIPTION_INFO);
		}
	}
}

static void
jingle_handle_security_info(JingleSession *session, xmlnode *jingle)
{
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
}

static void
jingle_handle_session_accept(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	jingle_session_accept_session(session);

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *parsed_content =
				jingle_session_find_content(session, name, creator);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jingle_send_and_free(session,
					jingle_session_terminate_packet(session,
					"unsupported-applications"));
		} else {
			jingle_content_handle_action(parsed_content, content,
					JINGLE_SESSION_ACCEPT);
		}
	}
}

static void
jingle_handle_session_info(JingleSession *session, xmlnode *jingle)
{
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
}

static void
jingle_handle_session_initiate(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	for (; content; content = xmlnode_get_next_twin(content)) {
		JingleContent *parsed_content = jingle_content_parse(content);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jingle_send_and_free(session,
					jingle_session_terminate_packet(session,
					"unsupported-applications"));
		} else {
			jingle_session_add_content(session, parsed_content);
			jingle_content_handle_action(parsed_content, content,
					JINGLE_SESSION_INITIATE);
		}
	}
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
}

static void
jingle_handle_session_terminate(JingleSession *session, xmlnode *jingle)
{
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	jingle_session_handle_action(session, jingle, JINGLE_SESSION_TERMINATE);
	g_object_unref(session);
}

static void
jingle_handle_transport_accept(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *c = jingle_session_find_content(session, name, creator);
		if (c) jingle_content_accept_transport(c);
	}
}

static void
jingle_handle_transport_info(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *parsed_content =
				jingle_session_find_content(session, name, creator);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jingle_send_and_free(session,
					jingle_session_terminate_packet(session,
					"unsupported-applications"));
		} else {
			jingle_content_handle_action(parsed_content, content,
					JINGLE_TRANSPORT_INFO);
		}
	}
}

static void
jingle_handle_transport_reject(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *c = jingle_session_find_content(session, name, creator);
		if (c) jingle_content_remove_pending_transport(c);
	}
}

static void
jingle_handle_transport_replace(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jingle_send_and_free(session, jingle_session_create_ack(session, jingle));
	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		xmlnode *xmltransport = xmlnode_get_child(content, "transport");
		JingleTransport *transport = jingle_transport_parse(xmltransport);
		JingleContent *c = jingle_session_find_content(session, name, creator);
		if (c && transport)
			jingle_content_set_pending_transport(c, transport);
	}
}

typedef struct {
	const char *name;
	void (*handler)(JingleSession *, xmlnode *);
} JingleAction;

static const JingleAction jingle_actions[] = {
	{"unknown-type",     jingle_handle_unknown_type},
	{"content-accept",   jingle_handle_content_accept},
	{"content-add",      jingle_handle_content_add},
	{"content-modify",   jingle_handle_content_modify},
	{"content-reject",   jingle_handle_content_reject},
	{"content-remove",   jingle_handle_content_remove},
	{"description-info", jingle_handle_description_info},
	{"security-info",    jingle_handle_security_info},
	{"session-accept",   jingle_handle_session_accept},
	{"session-info",     jingle_handle_session_info},
	{"session-initiate", jingle_handle_session_initiate},
	{"session-terminate",jingle_handle_session_terminate},
	{"transport-accept", jingle_handle_transport_accept},
	{"transport-info",   jingle_handle_transport_info},
	{"transport-reject", jingle_handle_transport_reject},
	{"transport-replace",jingle_handle_transport_replace},
};

const gchar *
jingle_get_action_name(JingleActionType action)
{
	return jingle_actions[action].name;
}

JingleActionType
jingle_get_action_type(const gchar *action)
{
	static const int num_actions =
			sizeof(jingle_actions) / sizeof(JingleAction);
	int i = 1; /* skip unknown-type */
	for (; i < num_actions; ++i) {
		if (purple_strequal(action, jingle_actions[i].name))
			return i;
	}
	return JINGLE_UNKNOWN_TYPE;
}

void
barev_jingle_parse(BonjourJabberConversation *bconv, const char *from,
                   const char *type, const char *id, xmlnode *jingle)
{
	const gchar *action;
	const gchar *sid;
	JingleActionType action_type;
	JingleSession *session;

	if (!type || !purple_strequal(type, "set"))
		return;

	if (!(action = xmlnode_get_attrib(jingle, "action")))
		return;

	action_type = jingle_get_action_type(action);
	purple_debug_info("barev", "Jingle action=%s from=%s\n", action,
			from ? from : "(null)");

	if (!(sid = xmlnode_get_attrib(jingle, "sid")))
		return;

	session = jingle_session_find_by_sid(bconv, sid);

	if (!session && !purple_strequal(action, "session-initiate")) {
		purple_debug_error("jingle",
				"barev_jingle_parse: session not found for sid=%s\n", sid);
		return;
	}

	if (action_type == JINGLE_SESSION_INITIATE) {
		if (session) {
			purple_debug_error("jingle",
					"Jingle session sid=%s already exists\n", sid);
			return;
		}
		/* own_jid = our username */
		gchar *own_jid =
				g_strdup(purple_account_get_username(bconv->account));
		session = jingle_session_create(bconv, sid, own_jid,
				from ? from : "", FALSE);
		g_free(own_jid);
	}

	jingle_actions[action_type].handler(session, jingle);
}

static void
jingle_terminate_sessions_gh(gpointer key, gpointer value, gpointer user_data)
{
	(void)key; (void)user_data;
	g_object_unref((JingleSession *)value);
}

void
barev_jingle_terminate_sessions(BonjourJabberConversation *bconv)
{
	if (bconv->jingle_sessions) {
		g_hash_table_foreach(bconv->jingle_sessions,
				jingle_terminate_sessions_gh, NULL);
		/* finalize callbacks remove entries; destroy the table afterwards */
		g_hash_table_destroy(bconv->jingle_sessions);
		bconv->jingle_sessions = NULL;
	}
}
