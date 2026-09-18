/*
 * Jingle RTP content for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/rtp.c
 * JabberStream replaced with BonjourJabberConversation.
 * ICE-UDP / STUN / TURN support removed; Raw UDP only.
 * jabber_iq_send() replaced with bonjour_jabber_send_xml().
 */

#ifdef USE_VV

#include "../jabber.h"
#include "jingle.h"
#include "media.h"
#include "media/backend-iface.h"
#include "media-gst.h"
#include "mediamanager.h"
#include "rawudp.h"
#include "rtp.h"
#include "session.h"
#include "debug.h"

#include <farstream/fs-candidate.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define BAREV_SRTP_KEY_LEN 30
#define BAREV_SRTP_CIPHER "aes-128-icm"
#define BAREV_SRTP_AUTH "hmac-sha1-80"
#define BAREV_SRTP_SUITE "AES_CM_128_HMAC_SHA1_80"

struct _JingleRtpPrivate
{
	gchar *media_type;
	gchar *ssrc;
	guint8 local_key[BAREV_SRTP_KEY_LEN];
	gboolean has_local_key;
	gboolean crypto_supported;
	gboolean crypto_negotiated;
	gboolean held_for_crypto;
	gboolean use_crypto;
	gchar *crypto_tag;
};

#define JINGLE_RTP_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE((obj), JINGLE_TYPE_RTP, JingleRtpPrivate))

static void jingle_rtp_class_init(JingleRtpClass *klass);
static void jingle_rtp_init(JingleRtp *rtp);
static void jingle_rtp_finalize(GObject *object);
static void jingle_rtp_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void jingle_rtp_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);
static JingleContent *jingle_rtp_parse_internal(xmlnode *rtp);
static xmlnode *jingle_rtp_to_xml_internal(JingleContent *rtp, xmlnode *content, JingleActionType action);
static void jingle_rtp_handle_action_internal(JingleContent *content, xmlnode *jingle, JingleActionType action);

static PurpleMedia *jingle_rtp_get_media(JingleSession *session);

static JingleContentClass *parent_class = NULL;

enum {
	PROP_0,
	PROP_MEDIA_TYPE,
	PROP_SSRC,
};

GType
jingle_rtp_get_type()
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(JingleRtpClass), NULL, NULL,
			(GClassInitFunc) jingle_rtp_class_init,
			NULL, NULL, sizeof(JingleRtp), 0,
			(GInstanceInitFunc) jingle_rtp_init, NULL
		};
		type = g_type_register_static(JINGLE_TYPE_CONTENT, "JingleRtp", &info, 0);
	}
	return type;
}

static void
jingle_rtp_class_init(JingleRtpClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->finalize = jingle_rtp_finalize;
	gobject_class->set_property = jingle_rtp_set_property;
	gobject_class->get_property = jingle_rtp_get_property;
	klass->parent_class.to_xml = jingle_rtp_to_xml_internal;
	klass->parent_class.parse = jingle_rtp_parse_internal;
	klass->parent_class.description_type = JINGLE_APP_RTP;
	klass->parent_class.handle_action = jingle_rtp_handle_action_internal;

	g_object_class_install_property(gobject_class, PROP_MEDIA_TYPE,
			g_param_spec_string("media-type", "Media Type",
			"The media type (\"audio\" or \"video\") for this rtp session.",
			NULL, G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_SSRC,
			g_param_spec_string("ssrc", "ssrc",
			"The ssrc for this rtp session.",
			NULL, G_PARAM_READWRITE));

	g_type_class_add_private(klass, sizeof(JingleRtpPrivate));
}

static void
jingle_rtp_init(JingleRtp *rtp)
{
	rtp->priv = JINGLE_RTP_GET_PRIVATE(rtp);
	memset(rtp->priv, 0, sizeof(*rtp->priv));
}

static void
jingle_rtp_finalize(GObject *rtp)
{
	JingleRtpPrivate *priv = JINGLE_RTP_GET_PRIVATE(rtp);
	purple_debug_info("jingle-rtp", "jingle_rtp_finalize\n");
	g_free(priv->media_type);
	g_free(priv->ssrc);
	g_free(priv->crypto_tag);
	memset(priv->local_key, 0, sizeof(priv->local_key));
	G_OBJECT_CLASS(parent_class)->finalize(rtp);
}

static void
jingle_rtp_set_property(GObject *object, guint prop_id,
		const GValue *value, GParamSpec *pspec)
{
	g_return_if_fail(JINGLE_IS_RTP(object));
	JingleRtp *rtp = JINGLE_RTP(object);
	switch (prop_id) {
		case PROP_MEDIA_TYPE:
			g_free(rtp->priv->media_type);
			rtp->priv->media_type = g_value_dup_string(value);
			break;
		case PROP_SSRC:
			g_free(rtp->priv->ssrc);
			rtp->priv->ssrc = g_value_dup_string(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void
jingle_rtp_get_property(GObject *object, guint prop_id,
		GValue *value, GParamSpec *pspec)
{
	g_return_if_fail(JINGLE_IS_RTP(object));
	JingleRtp *rtp = JINGLE_RTP(object);
	switch (prop_id) {
		case PROP_MEDIA_TYPE:
			g_value_set_string(value, rtp->priv->media_type);
			break;
		case PROP_SSRC:
			g_value_set_string(value, rtp->priv->ssrc);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

gchar *
jingle_rtp_get_media_type(JingleContent *content)
{
	gchar *media_type;
	g_object_get(content, "media-type", &media_type, NULL);
	return media_type;
}

gchar *
jingle_rtp_get_ssrc(JingleContent *content)
{
	gchar *ssrc;
	g_object_get(content, "ssrc", &ssrc, NULL);
	return ssrc;
}

static PurpleMedia *
jingle_rtp_get_media(JingleSession *session)
{
	BonjourJabberConversation *bconv = jingle_session_get_bconv(session);
	PurpleMedia *media = NULL;
	GList *iter = purple_media_manager_get_media_by_account(
			purple_media_manager_get(), bconv->account);

	for (; iter; iter = g_list_delete_link(iter, iter)) {
		JingleSession *media_session = purple_media_get_prpl_data(iter->data);
		if (media_session == session) {
			media = iter->data;
			break;
		}
	}
	if (iter != NULL)
		g_list_free(iter);
	return media;
}

static JingleRawUdpCandidate *
jingle_rtp_candidate_to_rawudp(guint generation, PurpleMediaCandidate *candidate)
{
	gchar *id = bonjour_jabber_next_id();
	gchar *ip = purple_media_candidate_get_ip(candidate);
	JingleRawUdpCandidate *rawudp_candidate = jingle_rawudp_candidate_new(
			id, generation,
			purple_media_candidate_get_component_id(candidate),
			ip, purple_media_candidate_get_port(candidate));
	g_free(ip);
	g_free(id);
	return rawudp_candidate;
}

static gboolean
jingle_rtp_random_bytes(guint8 *buffer, gsize length)
{
	gsize offset = 0;
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0) {
		purple_debug_error("jingle-rtp", "cannot open /dev/urandom: %s\n",
				g_strerror(errno));
		return FALSE;
	}

	while (offset < length) {
		ssize_t count = read(fd, buffer + offset, length - offset);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0) {
			purple_debug_error("jingle-rtp", "cannot read /dev/urandom: %s\n",
					count < 0 ? g_strerror(errno) : "unexpected EOF");
			close(fd);
			return FALSE;
		}
		offset += count;
	}

	close(fd);
	return TRUE;
}

static JingleTransport *
jingle_rtp_candidates_to_transport(guint generation, GList *candidates)
{
	JingleTransport *transport = jingle_transport_create(JINGLE_TRANSPORT_RAWUDP);
	for (; candidates; candidates = g_list_next(candidates)) {
		PurpleMediaCandidate *candidate = candidates->data;
		if (purple_media_candidate_get_protocol(candidate) ==
				PURPLE_MEDIA_NETWORK_PROTOCOL_UDP) {
			jingle_rawudp_add_local_candidate(JINGLE_RAWUDP(transport),
					jingle_rtp_candidate_to_rawudp(generation, candidate));
		}
	}
	return transport;
}

static GList *
jingle_rtp_transport_to_candidates(JingleTransport *transport)
{
	GList *ret = NULL;
	GList *candidates = jingle_rawudp_get_remote_candidates(
			JINGLE_RAWUDP(transport));
	for (; candidates; candidates = g_list_delete_link(candidates, candidates)) {
		JingleRawUdpCandidate *candidate = candidates->data;
		ret = g_list_append(ret, purple_media_candidate_new(
				"", candidate->component,
				PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
				PURPLE_MEDIA_NETWORK_PROTOCOL_UDP,
				candidate->ip, candidate->port));
	}
	return ret;
}

static void jingle_rtp_ready(JingleSession *session);

static void
jingle_rtp_candidates_prepared_cb(PurpleMedia *media, gchar *sid, gchar *name,
		JingleSession *session)
{
	JingleContent *content = jingle_session_find_content(session, sid, NULL);
	JingleTransport *oldtransport, *transport;
	GList *candidates;

	purple_debug_info("jingle-rtp", "jingle_rtp_candidates_prepared_cb\n");

	if (content == NULL) {
		purple_debug_error("jingle-rtp",
				"candidates_prepared_cb: can't find session %s\n", sid);
		return;
	}

	oldtransport = jingle_content_get_transport(content);
	candidates = purple_media_get_local_candidates(media, sid, name);
	transport = jingle_rtp_candidates_to_transport(0, candidates);

	purple_media_candidate_list_free(candidates);
	g_object_unref(oldtransport);

	jingle_content_set_pending_transport(content, transport);
	jingle_content_accept_transport(content);

	jingle_rtp_ready(session);
}

static void
jingle_rtp_codecs_changed_cb(PurpleMedia *media, gchar *sid,
		JingleSession *session)
{
	purple_debug_info("jingle-rtp",
			"jingle_rtp_codecs_changed_cb: sid=%s session=%p\n",
			sid, session);
	jingle_rtp_ready(session);
}

static void
jingle_rtp_new_candidate_cb(PurpleMedia *media, gchar *sid, gchar *name,
		PurpleMediaCandidate *candidate, JingleSession *session)
{
	JingleContent *content = jingle_session_find_content(session, sid, NULL);
	JingleTransport *transport;

	purple_debug_info("jingle-rtp", "jingle_rtp_new_candidate_cb\n");

	if (content == NULL) {
		purple_debug_error("jingle-rtp",
				"new_candidate_cb: can't find session %s\n", sid);
		return;
	}

	transport = jingle_content_get_transport(content);

	if (JINGLE_IS_RAWUDP(transport))
		jingle_rawudp_add_local_candidate(JINGLE_RAWUDP(transport),
				jingle_rtp_candidate_to_rawudp(1, candidate));

	g_object_unref(transport);

	{
		BonjourJabberConversation *bconv = jingle_session_get_bconv(session);
		xmlnode *iq = jingle_session_to_packet(session, JINGLE_TRANSPORT_INFO);
		bonjour_jabber_send_xml(bconv, iq);
		xmlnode_free(iq);
	}
}

static void
jingle_rtp_state_changed_cb(PurpleMedia *media, PurpleMediaState state,
		gchar *sid, gchar *name, JingleSession *session)
{
	purple_debug_info("jingle-rtp",
			"state-changed: state=%d sid=%s name=%s\n",
			state, sid ? sid : "(null)", name ? name : "(null)");
}

static void
jingle_rtp_stream_info_cb(PurpleMedia *media, PurpleMediaInfoType type,
		gchar *sid, gchar *name, gboolean local, JingleSession *session)
{
	purple_debug_info("jingle-rtp",
			"stream-info: type=%d sid=%s name=%s\n",
			type, sid ? sid : "(null)", name ? name : "(null)");

	g_return_if_fail(JINGLE_IS_SESSION(session));

	if (type == PURPLE_MEDIA_INFO_HANGUP || type == PURPLE_MEDIA_INFO_REJECT) {
		BonjourJabberConversation *bconv = jingle_session_get_bconv(session);
		xmlnode *iq = jingle_session_terminate_packet(session,
				type == PURPLE_MEDIA_INFO_HANGUP ? "success" : "decline");
		bonjour_jabber_send_xml(bconv, iq);
		xmlnode_free(iq);

		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_state_changed_cb), session);
		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_stream_info_cb), session);
		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_new_candidate_cb), session);

		g_object_unref(session);
	} else if (type == PURPLE_MEDIA_INFO_ACCEPT && sid && name &&
			jingle_session_is_initiator(session) == FALSE) {
		jingle_rtp_ready(session);
	}
}

static void
jingle_rtp_ready(JingleSession *session)
{
	PurpleMedia *media = jingle_rtp_get_media(session);

	if (purple_media_candidates_prepared(media, NULL, NULL) &&
			purple_media_codecs_ready(media, NULL) &&
			(jingle_session_is_initiator(session) == TRUE ||
			purple_media_accepted(media, NULL, NULL))) {

		BonjourJabberConversation *bconv = jingle_session_get_bconv(session);

		if (jingle_session_is_initiator(session)) {
			xmlnode *iq = jingle_session_to_packet(session,
					JINGLE_SESSION_INITIATE);
			bonjour_jabber_send_xml(bconv, iq);
			xmlnode_free(iq);
		} else {
			xmlnode *iq = jingle_session_to_packet(session,
					JINGLE_SESSION_ACCEPT);
			bonjour_jabber_send_xml(bconv, iq);
			xmlnode_free(iq);
		}

		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_candidates_prepared_cb), session);
		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_codecs_changed_cb), session);
		g_signal_connect(G_OBJECT(media), "new-candidate",
				G_CALLBACK(jingle_rtp_new_candidate_cb), session);
	}
}

static PurpleMedia *
jingle_rtp_create_media(JingleContent *content)
{
	JingleSession *session = jingle_content_get_session(content);
	BonjourJabberConversation *bconv = jingle_session_get_bconv(session);
	gchar *remote_jid = jingle_session_get_remote_jid(session);

	PurpleMedia *media = purple_media_manager_create_media(
			purple_media_manager_get(),
			bconv->account,
			"fsrtpconference", remote_jid,
			jingle_session_is_initiator(session));
	g_free(remote_jid);

	if (!media) {
		purple_debug_error("jingle-rtp", "Couldn't create media session\n");
		g_object_unref(session);
		return NULL;
	}

	purple_media_set_prpl_data(media, session);

	g_signal_connect(G_OBJECT(media), "candidates-prepared",
			G_CALLBACK(jingle_rtp_candidates_prepared_cb), session);
	g_signal_connect(G_OBJECT(media), "codecs-changed",
			G_CALLBACK(jingle_rtp_codecs_changed_cb), session);
	g_signal_connect(G_OBJECT(media), "state-changed",
			G_CALLBACK(jingle_rtp_state_changed_cb), session);
	g_signal_connect_object(G_OBJECT(media), "stream-info",
			G_CALLBACK(jingle_rtp_stream_info_cb), session, 0);

	g_object_unref(session);
	return media;
}

static gboolean
jingle_rtp_prepare_local_crypto(JingleContent *content, PurpleMedia *media,
		const gchar *name, const gchar *remote_jid)
{
	JingleRtpPrivate *priv = JINGLE_RTP(content)->priv;
	JingleSession *session;
	GObject *backend = NULL;
	PurpleMediaBackendIface *iface;

	g_object_get(media, "backend", &backend, NULL);
	if (backend == NULL || !PURPLE_IS_MEDIA_BACKEND(backend)) {
		purple_debug_error("jingle-rtp",
				"media backend is unavailable or invalid\n");
		if (backend != NULL)
			g_object_unref(backend);
		return FALSE;
	}

	iface = PURPLE_MEDIA_BACKEND_GET_INTERFACE(backend);
	priv->crypto_supported = iface->set_encryption_parameters != NULL &&
			iface->set_decryption_parameters != NULL &&
			iface->set_require_encryption != NULL;
	if (!priv->crypto_supported) {
		purple_debug_info("jingle-rtp",
				"media backend %s has no SRTP API; using RTP over Yggdrasil\n",
				G_OBJECT_TYPE_NAME(backend));
		g_object_unref(backend);
		return TRUE;
	}
	g_object_unref(backend);

	if (!priv->has_local_key) {
		if (!jingle_rtp_random_bytes(priv->local_key,
					sizeof(priv->local_key)))
			return FALSE;
		priv->has_local_key = TRUE;
	}
	if (priv->crypto_tag == NULL)
		priv->crypto_tag = g_strdup("1");
	if (!purple_media_set_require_encryption(media, name, remote_jid, TRUE))
		return FALSE;

	session = jingle_content_get_session(content);
	if (jingle_session_is_initiator(session)) {
		/* Do not send plaintext while the responder chooses SRTP or fallback. */
		priv->held_for_crypto = TRUE;
		purple_media_stream_info(media, PURPLE_MEDIA_INFO_HOLD,
				name, remote_jid, TRUE);
		purple_media_stream_info(media, PURPLE_MEDIA_INFO_PAUSE,
				name, remote_jid, TRUE);
	}
	g_object_unref(session);
	return TRUE;
}

static gboolean
jingle_rtp_complete_crypto_negotiation(JingleContent *content,
		gboolean use_crypto)
{
	JingleRtpPrivate *priv = JINGLE_RTP(content)->priv;

	priv->crypto_negotiated = TRUE;
	priv->use_crypto = use_crypto;
	return TRUE;
}

static gboolean
jingle_rtp_apply_crypto_negotiation(JingleContent *content, PurpleMedia *media,
		const gchar *name, const gchar *remote_jid)
{
	JingleRtpPrivate *priv = JINGLE_RTP(content)->priv;

	if (!priv->crypto_negotiated)
		return FALSE;
	if (!priv->use_crypto && priv->crypto_supported &&
			!purple_media_set_require_encryption(media, name,
					remote_jid, FALSE)) {
		purple_debug_error("jingle-rtp",
				"could not disable SRTP requirement for fallback\n");
		return FALSE;
	}
	return TRUE;
}

static void
jingle_rtp_release_crypto_hold(JingleContent *content, PurpleMedia *media,
		const gchar *name, const gchar *remote_jid)
{
	JingleRtpPrivate *priv = JINGLE_RTP(content)->priv;

	if (!priv->held_for_crypto)
		return;
	priv->held_for_crypto = FALSE;
	purple_media_stream_info(media, PURPLE_MEDIA_INFO_UNHOLD,
			name, remote_jid, TRUE);
	purple_media_stream_info(media, PURPLE_MEDIA_INFO_UNPAUSE,
			name, remote_jid, TRUE);
}

static gboolean
jingle_rtp_enable_local_crypto(JingleContent *content, PurpleMedia *media,
		const gchar *name, const gchar *remote_jid)
{
	JingleRtpPrivate *priv = JINGLE_RTP(content)->priv;
	gboolean encrypted, required;

	if (!priv->crypto_supported || !priv->has_local_key)
		return FALSE;

	encrypted = purple_media_set_encryption_parameters(media, name,
			BAREV_SRTP_CIPHER, BAREV_SRTP_AUTH,
			(const gchar *)priv->local_key, sizeof(priv->local_key));
	required = purple_media_set_require_encryption(media, name, remote_jid, TRUE);
	purple_debug_info("jingle-rtp",
			"local SRTP parameters: encryption=%d required=%d\n",
			encrypted, required);
	return encrypted && required;
}

static gboolean
jingle_rtp_set_remote_crypto(JingleContent *content, xmlnode *description)
{
	xmlnode *encryption, *crypto;
	const gchar *suite = NULL, *key_params = NULL, *tag = NULL;
	const gchar *required_attr;
	const gchar *encoded;
	gchar *encoded_key;
	guchar *key;
	gsize encoded_len, key_len;
	JingleSession *session;
	JingleRtpPrivate *priv = JINGLE_RTP(content)->priv;
	PurpleMedia *media;
	gchar *name, *remote_jid;
	gboolean required, result;

	if (description == NULL)
		return FALSE;
	if (priv->crypto_negotiated) {
		purple_debug_error("jingle-rtp",
				"peer attempted to renegotiate media encryption\n");
		return FALSE;
	}

	encryption = xmlnode_get_child(description, "encryption");
	if (encryption == NULL) {
		purple_debug_info("jingle-rtp",
				"peer selected RTP over Yggdrasil without SRTP\n");
		return jingle_rtp_complete_crypto_negotiation(content, FALSE);
	}

	required_attr = xmlnode_get_attrib(encryption, "required");
	if (required_attr == NULL || purple_strequal(required_attr, "0") ||
			g_ascii_strcasecmp(required_attr, "false") == 0) {
		required = FALSE;
	} else if (purple_strequal(required_attr, "1") ||
			g_ascii_strcasecmp(required_attr, "true") == 0) {
		required = TRUE;
	} else {
		purple_debug_error("jingle-rtp",
				"peer sent invalid SRTP required value %s\n", required_attr);
		return FALSE;
	}
	if (!priv->crypto_supported) {
		if (required) {
			purple_debug_error("jingle-rtp",
					"peer requires SRTP but the local media backend does not support it\n");
			return FALSE;
		}
		purple_debug_info("jingle-rtp",
				"declining optional SRTP; using RTP over Yggdrasil\n");
		return jingle_rtp_complete_crypto_negotiation(content, FALSE);
	}

	for (crypto = xmlnode_get_child(encryption, "crypto"); crypto;
			crypto = xmlnode_get_next_twin(crypto)) {
		suite = xmlnode_get_attrib(crypto, "crypto-suite");
		key_params = xmlnode_get_attrib(crypto, "key-params");
		tag = xmlnode_get_attrib(crypto, "tag");
		if (suite != NULL &&
				g_ascii_strcasecmp(suite, BAREV_SRTP_SUITE) == 0 &&
				key_params != NULL && g_str_has_prefix(key_params, "inline:") &&
				tag != NULL && *tag != '\0')
			break;
	}

	if (crypto == NULL) {
		if (required) {
			purple_debug_error("jingle-rtp",
					"peer requires unsupported SRTP parameters\n");
			return FALSE;
		}
		purple_debug_info("jingle-rtp",
				"ignoring unsupported optional SRTP parameters\n");
		return jingle_rtp_complete_crypto_negotiation(content, FALSE);
	}

	session = jingle_content_get_session(content);
	if (jingle_session_is_initiator(session)) {
		if (!purple_strequal(tag, priv->crypto_tag)) {
			purple_debug_error("jingle-rtp",
					"peer selected unexpected SRTP tag %s\n", tag);
			g_object_unref(session);
			return FALSE;
		}
	} else {
		g_free(priv->crypto_tag);
		priv->crypto_tag = g_strdup(tag);
	}

	encoded = key_params + strlen("inline:");
	if (strchr(encoded, '|') != NULL) {
		purple_debug_error("jingle-rtp",
				"SRTP lifetime and MKI parameters are not supported\n");
		g_object_unref(session);
		return FALSE;
	}
	encoded_len = strcspn(encoded, "|");
	encoded_key = g_strndup(encoded, encoded_len);
	key = g_base64_decode(encoded_key, &key_len);
	g_free(encoded_key);
	if (key_len != BAREV_SRTP_KEY_LEN) {
		purple_debug_error("jingle-rtp", "peer SRTP key has invalid length %lu\n",
				(unsigned long)key_len);
		g_free(key);
		g_object_unref(session);
		return FALSE;
	}

	media = jingle_rtp_get_media(session);
	name = jingle_content_get_name(content);
	remote_jid = jingle_session_get_remote_jid(session);
	result = jingle_rtp_enable_local_crypto(content, media, name, remote_jid) &&
			purple_media_set_decryption_parameters(media, name, remote_jid,
					BAREV_SRTP_CIPHER, BAREV_SRTP_AUTH,
					(const gchar *)key, key_len);
	if (result)
		result = jingle_rtp_complete_crypto_negotiation(content, TRUE);
	purple_debug_info("jingle-rtp", "remote SRTP parameters: decryption=%d\n",
			result);

	memset(key, 0, key_len);
	g_free(key);
	g_free(remote_jid);
	g_free(name);
	g_object_unref(session);
	return result;
}

static gboolean
jingle_rtp_init_media(JingleContent *content)
{
	JingleSession *session = jingle_content_get_session(content);
	BonjourJabberConversation *bconv = jingle_session_get_bconv(session);
	PurpleMedia *media = jingle_rtp_get_media(session);
	gchar *creator, *media_type, *remote_jid, *senders, *name;
	const gchar *transmitter;
	gboolean is_audio, is_creator;
	PurpleMediaSessionType type;
	JingleTransport *transport;
	GParameter param = { 0 };
	GList *preferred_candidates = NULL;
	guint num_params = 0;
	gboolean stream_added;

	if (bconv->local_ip == NULL || *bconv->local_ip == '\0') {
		purple_debug_error("jingle-rtp",
				"cannot start media without a local Yggdrasil address\n");
		g_object_unref(session);
		return FALSE;
	}

	if (media == NULL) {
		media = jingle_rtp_create_media(content);
		if (media == NULL) {
			g_object_unref(session);
			return FALSE;
		}
	}

	name       = jingle_content_get_name(content);
	media_type = jingle_rtp_get_media_type(content);
	remote_jid = jingle_session_get_remote_jid(session);
	senders    = jingle_content_get_senders(content);
	transport  = jingle_content_get_transport(content);

	if (media_type == NULL) {
		g_free(name); g_free(remote_jid); g_free(senders);
		g_object_unref(transport); g_object_unref(session);
		return FALSE;
	}

	/* Raw UDP only */
	transmitter = JINGLE_IS_RAWUDP(transport) ? "rawudp" : "notransmitter";
	g_object_unref(transport);

	is_audio = purple_strequal(media_type, "audio");

	if (purple_strequal(senders, "both"))
		type = is_audio ? PURPLE_MEDIA_AUDIO : PURPLE_MEDIA_VIDEO;
	else if (purple_strequal(senders, "initiator") ==
			jingle_session_is_initiator(session))
		type = is_audio ? PURPLE_MEDIA_SEND_AUDIO : PURPLE_MEDIA_SEND_VIDEO;
	else
		type = is_audio ? PURPLE_MEDIA_RECV_AUDIO : PURPLE_MEDIA_RECV_VIDEO;

	creator = jingle_content_get_creator(content);
	if (creator == NULL) {
		g_free(name); g_free(media_type); g_free(remote_jid);
		g_free(senders); g_object_unref(session);
		return FALSE;
	}

	is_creator = purple_strequal(creator, "initiator") ?
			jingle_session_is_initiator(session) :
			!jingle_session_is_initiator(session);
	g_free(creator);

	preferred_candidates = g_list_append(preferred_candidates,
			fs_candidate_new("", FS_COMPONENT_RTP, FS_CANDIDATE_TYPE_HOST,
					FS_NETWORK_PROTOCOL_UDP, bconv->local_ip, 0));
	preferred_candidates = g_list_append(preferred_candidates,
			fs_candidate_new("", FS_COMPONENT_RTCP, FS_CANDIDATE_TYPE_HOST,
					FS_NETWORK_PROTOCOL_UDP, bconv->local_ip, 0));
	param.name = "preferred-local-candidates";
	g_value_init(&param.value, FS_TYPE_CANDIDATE_LIST);
	g_value_set_static_boxed(&param.value, preferred_candidates);
	num_params = 1;
	purple_debug_info("jingle-rtp", "binding media to Yggdrasil address %s\n",
			bconv->local_ip);

	stream_added = purple_media_add_stream(media, name, remote_jid,
			type, is_creator, transmitter, num_params, &param);
	g_value_unset(&param.value);
	fs_candidate_list_destroy(preferred_candidates);
	if (!stream_added) {
		purple_media_end(media, NULL, NULL);
		g_free(name); g_free(media_type); g_free(remote_jid);
		g_free(senders); g_object_unref(session);
		return FALSE;
	}

	if (!jingle_rtp_prepare_local_crypto(content, media, name, remote_jid)) {
		purple_debug_error("jingle-rtp", "could not prepare local SRTP\n");
		purple_media_end(media, NULL, NULL);
		g_free(name); g_free(media_type); g_free(remote_jid);
		g_free(senders); g_object_unref(session);
		return FALSE;
	}

	g_free(name);
	g_free(media_type);
	g_free(remote_jid);
	g_free(senders);
	g_object_unref(session);
	return TRUE;
}

static GList *
jingle_rtp_parse_codecs(xmlnode *description)
{
	GList *codecs = NULL;
	xmlnode *codec_element = NULL;
	const char *encoding_name, *id, *clock_rate;
	PurpleMediaCodec *codec;
	const gchar *media = xmlnode_get_attrib(description, "media");
	PurpleMediaSessionType type;

	if (media == NULL) {
		purple_debug_warning("jingle-rtp", "missing media type\n");
		return NULL;
	}

	if (purple_strequal(media, "video"))
		type = PURPLE_MEDIA_VIDEO;
	else if (purple_strequal(media, "audio"))
		type = PURPLE_MEDIA_AUDIO;
	else {
		purple_debug_warning("jingle-rtp", "unknown media type: %s\n", media);
		return NULL;
	}

	for (codec_element = xmlnode_get_child(description, "payload-type");
			codec_element;
			codec_element = xmlnode_get_next_twin(codec_element)) {
		xmlnode *param;
		gchar *codec_str;
		encoding_name = xmlnode_get_attrib(codec_element, "name");
		id = xmlnode_get_attrib(codec_element, "id");
		clock_rate = xmlnode_get_attrib(codec_element, "clockrate");

		codec = purple_media_codec_new(atoi(id), encoding_name, type,
				clock_rate ? atoi(clock_rate) : 0);

		for (param = xmlnode_get_child(codec_element, "parameter");
				param; param = xmlnode_get_next_twin(param)) {
			purple_media_codec_add_optional_parameter(codec,
					xmlnode_get_attrib(param, "name"),
					xmlnode_get_attrib(param, "value"));
		}

		codec_str = purple_media_codec_to_string(codec);
		purple_debug_info("jingle-rtp", "received codec: %s\n", codec_str);
		g_free(codec_str);

		codecs = g_list_append(codecs, codec);
	}
	return codecs;
}

static JingleContent *
jingle_rtp_parse_internal(xmlnode *rtp)
{
	JingleContent *content = parent_class->parse(rtp);
	xmlnode *description = xmlnode_get_child(rtp, "description");
	const gchar *media_type = xmlnode_get_attrib(description, "media");
	const gchar *ssrc = xmlnode_get_attrib(description, "ssrc");
	purple_debug_info("jingle-rtp", "rtp parse\n");
	g_object_set(content, "media-type", media_type, NULL);
	if (ssrc != NULL)
		g_object_set(content, "ssrc", ssrc, NULL);
	return content;
}

static void
jingle_rtp_add_payloads(xmlnode *description, GList *codecs)
{
	for (; codecs; codecs = codecs->next) {
		PurpleMediaCodec *codec = (PurpleMediaCodec*)codecs->data;
		GList *iter = purple_media_codec_get_optional_parameters(codec);
		gchar *id, *name, *clockrate, *channels;
		gchar *codec_str;
		xmlnode *payload = xmlnode_new_child(description, "payload-type");

		id       = g_strdup_printf("%d", purple_media_codec_get_id(codec));
		name     = purple_media_codec_get_encoding_name(codec);
		clockrate= g_strdup_printf("%d", purple_media_codec_get_clock_rate(codec));
		channels = g_strdup_printf("%d", purple_media_codec_get_channels(codec));

		xmlnode_set_attrib(payload, "name",      name);
		xmlnode_set_attrib(payload, "id",        id);
		xmlnode_set_attrib(payload, "clockrate", clockrate);
		xmlnode_set_attrib(payload, "channels",  channels);

		g_free(channels); g_free(clockrate); g_free(name); g_free(id);

		for (; iter; iter = g_list_next(iter)) {
			PurpleKeyValuePair *mparam = iter->data;
			xmlnode *param = xmlnode_new_child(payload, "parameter");
			xmlnode_set_attrib(param, "name",  mparam->key);
			xmlnode_set_attrib(param, "value", mparam->value);
		}

		codec_str = purple_media_codec_to_string(codec);
		purple_debug_info("jingle", "adding codec: %s\n", codec_str);
		g_free(codec_str);
	}
}

static xmlnode *
jingle_rtp_to_xml_internal(JingleContent *rtp, xmlnode *content,
		JingleActionType action)
{
	xmlnode *node = parent_class->to_xml(rtp, content, action);
	xmlnode *description = xmlnode_get_child(node, "description");
	if (description != NULL) {
		JingleSession *session = jingle_content_get_session(rtp);
		PurpleMedia *media = jingle_rtp_get_media(session);
		gchar *media_type = jingle_rtp_get_media_type(rtp);
		gchar *ssrc = jingle_rtp_get_ssrc(rtp);
		gchar *name = jingle_content_get_name(rtp);
		GList *codecs = purple_media_get_codecs(media, name);

		xmlnode_set_attrib(description, "media", media_type);
		if (ssrc != NULL)
			xmlnode_set_attrib(description, "ssrc", ssrc);

		g_free(media_type);
		g_free(name);
		g_object_unref(session);

		jingle_rtp_add_payloads(description, codecs);
		if (((action == JINGLE_SESSION_INITIATE &&
				JINGLE_RTP(rtp)->priv->crypto_supported) ||
				(action == JINGLE_SESSION_ACCEPT &&
				 JINGLE_RTP(rtp)->priv->use_crypto)) &&
				JINGLE_RTP(rtp)->priv->has_local_key) {
			gchar *key = g_base64_encode(JINGLE_RTP(rtp)->priv->local_key,
					BAREV_SRTP_KEY_LEN);
			gchar *key_params = g_strdup_printf("inline:%s", key);
			xmlnode *encryption = xmlnode_new_child(description, "encryption");
			xmlnode *crypto = xmlnode_new_child(encryption, "crypto");

			xmlnode_set_attrib(encryption, "required",
					action == JINGLE_SESSION_INITIATE ? "0" : "1");
			xmlnode_set_attrib(crypto, "crypto-suite", BAREV_SRTP_SUITE);
			xmlnode_set_attrib(crypto, "key-params", key_params);
			xmlnode_set_attrib(crypto, "tag",
					JINGLE_RTP(rtp)->priv->crypto_tag);
			g_free(key_params);
			g_free(key);
		}
		purple_media_codec_list_free(codecs);
	}
	return node;
}

static void
jingle_rtp_handle_action_internal(JingleContent *content, xmlnode *xmlcontent,
		JingleActionType action)
{
	switch (action) {
		case JINGLE_SESSION_ACCEPT:
		case JINGLE_SESSION_INITIATE: {
			JingleSession *session;
			JingleTransport *transport;
			xmlnode *description;
			GList *candidates, *codecs;
			gchar *name, *remote_jid;
			PurpleMedia *media;

			session = jingle_content_get_session(content);

			if (action == JINGLE_SESSION_INITIATE &&
					!jingle_rtp_init_media(content)) {
				BonjourJabberConversation *bconv =
						jingle_session_get_bconv(session);
				xmlnode *iq = jingle_session_terminate_packet(
						session, "general-error");
				bonjour_jabber_send_xml(bconv, iq);
				xmlnode_free(iq);
				jingle_session_unregister(session);
				g_object_unref(session);
				break;
			}

			transport = jingle_transport_parse(
					xmlnode_get_child(xmlcontent, "transport"));
			description = xmlnode_get_child(xmlcontent, "description");
			candidates = jingle_rtp_transport_to_candidates(transport);
			codecs = jingle_rtp_parse_codecs(description);
			name = jingle_content_get_name(content);
			remote_jid = jingle_session_get_remote_jid(session);

			media = jingle_rtp_get_media(session);
			if (!jingle_rtp_set_remote_crypto(content, description)) {
				BonjourJabberConversation *bconv =
						jingle_session_get_bconv(session);
				xmlnode *iq = jingle_session_terminate_packet(
						session, "security-error");
				bonjour_jabber_send_xml(bconv, iq);
				xmlnode_free(iq);
				purple_media_end(media, NULL, NULL);
				jingle_session_unregister(session);
				g_free(remote_jid);
				g_free(name);
				g_object_unref(session);
				g_object_unref(transport);
				purple_media_codec_list_free(codecs);
				purple_media_candidate_list_free(candidates);
				break;
			}

			if (!purple_media_set_remote_codecs(media, name,
					remote_jid, codecs)) {
				BonjourJabberConversation *bconv =
						jingle_session_get_bconv(session);
				xmlnode *iq = jingle_session_terminate_packet(
						session, "failed-application");
				purple_debug_error("jingle-rtp",
						"could not set remote codecs for %s\n", name);
				bonjour_jabber_send_xml(bconv, iq);
				xmlnode_free(iq);
				purple_media_end(media, NULL, NULL);
				jingle_session_unregister(session);
				g_free(remote_jid);
				g_free(name);
				g_object_unref(session);
				g_object_unref(transport);
				purple_media_codec_list_free(codecs);
				purple_media_candidate_list_free(candidates);
				break;
			}
			if (!jingle_rtp_apply_crypto_negotiation(content, media,
					name, remote_jid)) {
				BonjourJabberConversation *bconv =
						jingle_session_get_bconv(session);
				xmlnode *iq = jingle_session_terminate_packet(
						session, "security-error");
				bonjour_jabber_send_xml(bconv, iq);
				xmlnode_free(iq);
				purple_media_end(media, NULL, NULL);
				jingle_session_unregister(session);
				g_free(remote_jid);
				g_free(name);
				g_object_unref(session);
				g_object_unref(transport);
				purple_media_codec_list_free(codecs);
				purple_media_candidate_list_free(candidates);
				break;
			}
			purple_media_add_remote_candidates(media, name, remote_jid,
					candidates);

			if (action == JINGLE_SESSION_ACCEPT) {
				jingle_rtp_release_crypto_hold(content, media,
						name, remote_jid);
				purple_media_stream_info(media, PURPLE_MEDIA_INFO_ACCEPT,
						name, remote_jid, FALSE);
			}

			g_free(remote_jid);
			g_free(name);
			g_object_unref(session);
			g_object_unref(transport);
			purple_media_codec_list_free(codecs);
			purple_media_candidate_list_free(candidates);
			break;
		}
		case JINGLE_SESSION_TERMINATE: {
			JingleSession *session = jingle_content_get_session(content);
			PurpleMedia *media = jingle_rtp_get_media(session);
			if (media != NULL)
				purple_media_end(media, NULL, NULL);
			g_object_unref(session);
			break;
		}
		case JINGLE_TRANSPORT_INFO: {
			JingleSession *session = jingle_content_get_session(content);
			JingleTransport *transport = jingle_transport_parse(
					xmlnode_get_child(xmlcontent, "transport"));
			GList *candidates = jingle_rtp_transport_to_candidates(transport);
			gchar *name = jingle_content_get_name(content);
			gchar *remote_jid = jingle_session_get_remote_jid(session);

			purple_media_add_remote_candidates(
					jingle_rtp_get_media(session),
					name, remote_jid, candidates);

			g_free(remote_jid);
			g_free(name);
			g_object_unref(session);
			g_object_unref(transport);
			purple_media_candidate_list_free(candidates);
			break;
		}
		case JINGLE_DESCRIPTION_INFO: {
			JingleSession *session = jingle_content_get_session(content);
			xmlnode *description = xmlnode_get_child(xmlcontent, "description");
			GList *codecs, *iter, *iter2;
			GList *remote_codecs = jingle_rtp_parse_codecs(description);
			gchar *name = jingle_content_get_name(content);
			gchar *remote_jid = jingle_session_get_remote_jid(session);
			PurpleMedia *media = jingle_rtp_get_media(session);

			codecs = purple_media_get_codecs(media, name);
			for (iter = codecs; iter; iter = g_list_next(iter)) {
				guint id = purple_media_codec_get_id(iter->data);
				for (iter2 = remote_codecs; iter2;
						iter2 = g_list_next(iter2)) {
					if (purple_media_codec_get_id(iter2->data) != id)
						continue;
					g_object_unref(iter->data);
					iter->data = iter2->data;
					remote_codecs = g_list_delete_link(
							remote_codecs, iter2);
					break;
				}
			}
			codecs = g_list_concat(codecs, remote_codecs);
			purple_media_set_remote_codecs(media, name, remote_jid, codecs);

			purple_media_codec_list_free(codecs);
			g_free(remote_jid);
			g_free(name);
			g_object_unref(session);
			break;
		}
		default:
			break;
	}
}

gboolean
jingle_rtp_initiate_media(BonjourJabberConversation *bconv, const gchar *who,
		PurpleMediaSessionType type)
{
	JingleSession *session;
	JingleContent *content;
	JingleTransport *transport;
	gboolean ret = FALSE;
	gchar *me = NULL, *sid = NULL;

	me = g_strdup(bonjour_jabber_get_local_jid(bconv));
	sid = bonjour_jabber_next_id();

	session = jingle_session_create(bconv, sid, me, who, TRUE);

	if (type & PURPLE_MEDIA_AUDIO) {
		transport = jingle_transport_create(JINGLE_TRANSPORT_RAWUDP);
		content = jingle_content_create(JINGLE_APP_RTP, "initiator",
				"session", "audio-session", "both", transport);
		jingle_session_add_content(session, content);
		JINGLE_RTP(content)->priv->media_type = g_strdup("audio");
		if (!jingle_rtp_init_media(content))
			goto out;
	}
	if (type & PURPLE_MEDIA_VIDEO) {
		transport = jingle_transport_create(JINGLE_TRANSPORT_RAWUDP);
		content = jingle_content_create(JINGLE_APP_RTP, "initiator",
				"session", "video-session", "both", transport);
		jingle_session_add_content(session, content);
		JINGLE_RTP(content)->priv->media_type = g_strdup("video");
		if (!jingle_rtp_init_media(content)) {
			PurpleMedia *media = jingle_rtp_get_media(session);
			if (media != NULL)
				purple_media_end(media, NULL, NULL);
			goto out;
		}
	}

	if (jingle_rtp_get_media(session) == NULL)
		goto out;

	ret = TRUE;
out:
	if (!ret)
		g_object_unref(session);
	g_free(me);
	g_free(sid);
	return ret;
}

void
jingle_rtp_terminate_session(BonjourJabberConversation *bconv, const gchar *who)
{
	JingleSession *session = jingle_session_find_by_jid(bconv, who);
	if (session) {
		PurpleMedia *media = jingle_rtp_get_media(session);
		if (media) {
			purple_debug_info("jingle-rtp", "hanging up media\n");
			purple_media_stream_info(media, PURPLE_MEDIA_INFO_HANGUP,
					NULL, NULL, TRUE);
		}
	}
}

#endif /* USE_VV */
