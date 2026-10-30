#ifndef _PURPLE_INTERNAL_H_
#define _PURPLE_INTERNAL_H_

/* Public libpurple API */
#if !defined(RC_INVOKED)
#include <purple.h>
#endif

/* Glib for gboolean */
#if !defined(RC_INVOKED)
#include <glib.h>
#endif

/* POSIX / networking stuff */
#include <sys/types.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
/* -- Win32-specfic declarations: some stuff is explicitly missing from Windows Sockets, so we should put 'em too -- */
#define MSG_NOSIGNAL 0
#define MSG_DONTWAIT 0
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <fcntl.h>
#endif
#include <unistd.h>

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

	#if defined(_WIN32)
	/* Win32 API doesn't have `fcntl`. So we are gonna use the alternatives */
	u_long nonblock = 1;

    /* Make socket non-blocking */
	if (ioctlsocket((SOCKET)fd, FIONBIO, &nonblock) != 0)
		return FALSE;

    /* Set close-on-exec */
	if (!SetHandleInformation((HANDLE)(SOCKET)fd, HANDLE_FLAG_INHERIT, 0))
		return FALSE;

	#else
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
	#endif

    return TRUE;
}

/**
 * @brief Error handlers.
 * These are intended to properly catch all errors on all platforms, because Windows Sockets
 * give different stack of errors in contrary of Linux standard `errno`.
 */
static inline int barev_sock_transient()
{
#if defined(_WIN32)
    int w = WSAGetLastError();
    return w == WSAEWOULDBLOCK || w == WSAEINPROGRESS || w == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EINTR;
#endif
}

static inline int barev_connect_pending()
{
#if defined(_WIN32)
    int w = WSAGetLastError();
    return w == WSAEWOULDBLOCK || w == WSAEINPROGRESS || w == WSAEALREADY;
#else
    return errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK;
#endif
}

#endif /* _PURPLE_INTERNAL_H_ */
