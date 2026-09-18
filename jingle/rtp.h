/*
 * Jingle RTP content for barev-purple.
 * Adapted from libpurple/protocols/jabber/jingle/rtp.h
 * JabberStream replaced with BonjourJabberConversation.
 */

#ifndef BAREV_JINGLE_RTP_H
#define BAREV_JINGLE_RTP_H

#ifdef USE_VV

#include <glib.h>
#include <glib-object.h>

#include "content.h"
#include "media.h"
#include "xmlnode.h"

G_BEGIN_DECLS

#define JINGLE_TYPE_RTP            (jingle_rtp_get_type())
#define JINGLE_RTP(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), JINGLE_TYPE_RTP, JingleRtp))
#define JINGLE_RTP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), JINGLE_TYPE_RTP, JingleRtpClass))
#define JINGLE_IS_RTP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), JINGLE_TYPE_RTP))
#define JINGLE_IS_RTP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), JINGLE_TYPE_RTP))
#define JINGLE_RTP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), JINGLE_TYPE_RTP, JingleRtpClass))

typedef struct _JingleRtp JingleRtp;
typedef struct _JingleRtpClass JingleRtpClass;
typedef struct _JingleRtpPrivate JingleRtpPrivate;

struct _JingleRtpClass
{
	JingleContentClass parent_class;
};

struct _JingleRtp
{
	JingleContent parent;
	JingleRtpPrivate *priv;
};

#ifdef __cplusplus
extern "C" {
#endif

GType jingle_rtp_get_type(void);

gchar *jingle_rtp_get_media_type(JingleContent *content);
gchar *jingle_rtp_get_ssrc(JingleContent *content);

gboolean jingle_rtp_initiate_media(BonjourJabberConversation *bconv,
		const gchar *who, PurpleMediaSessionType type);
void jingle_rtp_terminate_session(BonjourJabberConversation *bconv,
		const gchar *who);

#ifdef __cplusplus
}
#endif

G_END_DECLS

#endif /* USE_VV */

#endif /* BAREV_JINGLE_RTP_H */
