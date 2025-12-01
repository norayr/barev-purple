#ifndef _PURPLE_INTERNAL_H_
#define _PURPLE_INTERNAL_H_

/* Public libpurple API */
#include <purple.h>

/* Glib for gboolean */
#include <glib.h>

/* POSIX / networking stuff */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>

/* ----- Things bonjour/jabber expect from internal.h ----- */

/* Buffer sizes (matches upstream semantics well enough) */
#define MSG_LEN 2048
#define BUF_LEN MSG_LEN
#define BUF_LONG (BUF_LEN * 2)

/* Shared sockaddr union used in various core/protocol files */
typedef union
{
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr_storage storage;
} common_sockaddr_t;

/* i18n helpers – make them no-ops if not already defined */
#ifndef _
#  define _(String) ((const char *)(String))
#endif

#ifndef N_
#  define N_(String) (String)
#endif

/* Website macro from upstream internal.h */
#ifndef PURPLE_WEBSITE
#  define PURPLE_WEBSITE "https://pidgin.im/"
#endif

/* Version string used in the plugin info struct.
 * Upstream takes this from config.h as DISPLAY_VERSION;
 * for an out-of-tree plugin, any descriptive string is fine.
 */
#ifndef DISPLAY_VERSION
#  define DISPLAY_VERSION "bonjour-out-of-tree"
#endif

#ifndef VERSION
/* Use the same string as DISPLAY_VERSION for the TXT "ver" field. */
#  define VERSION DISPLAY_VERSION
#endif


/* Inline clone of libpurple's _purple_network_set_common_socket_flags()
 * so we don't depend on a private symbol from libpurple.
 */
static inline gboolean
_purple_network_set_common_socket_flags(int fd)
{
    int flags;

    /* Make socket non-blocking */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return FALSE;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return FALSE;

    /* Set close-on-exec */
    flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1)
        return FALSE;
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
        return FALSE;

    return TRUE;
}

#endif /* _PURPLE_INTERNAL_H_ */
