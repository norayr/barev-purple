/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "tls.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <errno.h>
#include <sys/socket.h>
#endif

#define TLS_PLAIN_LIMIT 16384

struct BarevTLS {
    SSL_CTX *context;
    SSL *ssl;
    BIO_METHOD *method;
    int fd;
    unsigned char pin[32], writing[TLS_PLAIN_LIMIT];
    size_t writing_length;
    gboolean server, ready, failed, closed, verified, peer_certificate, sent_certificate, requested;
    gboolean handshake_write, read_write, write_write;
    char error[BAREV_TLS_ERROR_BYTES];
};

static int socket_write(BIO *bio, const char *bytes, int length)
{
    BarevTLS *tls = BIO_get_data(bio);
    int result;
    BIO_clear_retry_flags(bio);
#ifdef _WIN32
    result = send(tls->fd, bytes, length, 0);
    if (result < 0 && (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR)) BIO_set_retry_write(bio);
#else
    result = send(tls->fd, bytes, length,
#ifdef MSG_NOSIGNAL
        MSG_NOSIGNAL
#else
        0
#endif
    );
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_write(bio);
#endif
    return result;
}

static int socket_read(BIO *bio, char *bytes, int length)
{
    BarevTLS *tls = BIO_get_data(bio);
    int result;
    BIO_clear_retry_flags(bio); result = recv(tls->fd, bytes, length, 0);
#ifdef _WIN32
    if (result < 0 && (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR)) BIO_set_retry_read(bio);
#else
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_read(bio);
#endif
    return result;
}

static long socket_control(BIO *bio, int command, long value, void *output)
{
    (void)value;
    if (command == BIO_CTRL_FLUSH) return 1;
    if (command == BIO_C_GET_FD) {
        BarevTLS *tls = BIO_get_data(bio);
        if (output) *(int *)output = tls->fd;
        return tls->fd;
    }
    return 0;
}

static int fail(BarevTLS *tls, const char *reason)
{
    if (!tls->failed) g_strlcpy(tls->error, reason, sizeof(tls->error));
    tls->failed = TRUE; tls->ready = FALSE;
    return -1;
}

static int ssl_failure(BarevTLS *tls)
{
    unsigned long error = ERR_get_error();
    char text[BAREV_TLS_ERROR_BYTES];
    if (error) ERR_error_string_n(error, text, sizeof(text));
    else g_strlcpy(text, "TLS connection failed or ended without close_notify", sizeof(text));
    return fail(tls, text);
}

static unsigned be16(const unsigned char *p) { return (unsigned)p[0]*256+p[1]; }
static size_t be24(const unsigned char *p) { return (size_t)p[0]*65536+(size_t)p[1]*256+p[2]; }

static gboolean certificate_message(const unsigned char *p, size_t n)
{
    size_t length;
    if (n < 13 || n > 32768 || p[0] != 11 || be24(p+1) != n-4 || p[4] || be24(p+5) != n-8)
        return FALSE;
    length = be24(p+8);
    return length > 0 && length == n-13 && be16(p+11+length) == 0;
}

static gboolean certificate_request(const unsigned char *p, size_t n)
{
    unsigned char seen[8192] = {0};
    size_t at = 7, end;
    unsigned type, length;
    gboolean ed25519 = FALSE;
    if (n < 7 || n > 32768 || be24(p+1) != n-4 || p[4] || be16(p+5) != n-7) return FALSE;
    while (at < n) {
        if (n-at < 4) return FALSE;
        type = be16(p+at); length = be16(p+at+2); at += 4;
        if (length > n-at || (seen[type/8] & (1u << (type%8)))) return FALSE;
        seen[type/8] |= 1u << (type%8); end = at+length;
        if (type == 13 || type == 50) {
            if (length < 4 || length%2 || be16(p+at) != length-2) return FALSE;
            if (type == 13) {
                at += 2;
                while (at < end) { if (be16(p+at) == 0x0807) ed25519 = TRUE; at += 2; }
            }
        }
        at = end;
    }
    return ed25519;
}

static void message(int sent, int version, int type, const void *bytes, size_t length, SSL *ssl, void *data)
{
    BarevTLS *tls = data;
    const unsigned char *p = bytes;
    (void)version; (void)ssl;
    if (type != SSL3_RT_HANDSHAKE || length < 4 || tls->failed) return;
    if (p[0] == 11) {
        if (!certificate_message(p, length)) { fail(tls, "expected one initial-handshake certificate"); return; }
        if (sent) tls->sent_certificate = TRUE;
        else tls->peer_certificate = TRUE;
    } else if (p[0] == 13 && !sent && !tls->server) {
        if (tls->requested || !certificate_request(p, length)) {
            fail(tls, "the peer did not request initial Ed25519 client authentication"); return;
        }
        tls->requested = TRUE;
    }
}

static gboolean ed25519_algorithm(const X509_ALGOR *algorithm)
{
    const ASN1_OBJECT *oid;
    const void *value;
    int type;
    if (!algorithm) return FALSE;
    X509_ALGOR_get0(&oid, &type, &value, algorithm);
    return OBJ_obj2nid(oid) == NID_ED25519 && type == V_ASN1_UNDEF;
}

static gboolean usages(X509 *certificate, gboolean server)
{
    ASN1_BIT_STRING *usage;
    EXTENDED_KEY_USAGE *extended;
    int critical = -1, i, nid;
    gboolean allowed = FALSE;
    for (i = 0; i < X509_get_ext_count(certificate); ++i) {
        X509_EXTENSION *extension = X509_get_ext(certificate, i);
        nid = OBJ_obj2nid(X509_EXTENSION_get_object(extension));
        if (X509_get_ext_by_OBJ(certificate, X509_EXTENSION_get_object(extension), i) >= 0) return FALSE;
        if (X509_EXTENSION_get_critical(extension) && nid != NID_basic_constraints && nid != NID_key_usage &&
            nid != NID_ext_key_usage && nid != NID_subject_alt_name && nid != NID_name_constraints) return FALSE;
    }
    usage = X509_get_ext_d2i(certificate, NID_key_usage, &critical, NULL);
    if (!usage && critical != -1) return FALSE;
    if (usage) { allowed = ASN1_BIT_STRING_get_bit(usage, 0) == 1; ASN1_BIT_STRING_free(usage); if (!allowed) return FALSE; }
    critical = -1; extended = X509_get_ext_d2i(certificate, NID_ext_key_usage, &critical, NULL);
    if (!extended) return critical == -1;
    allowed = FALSE;
    for (i = 0; i < sk_ASN1_OBJECT_num(extended); ++i) {
        nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(extended, i));
        if (nid == NID_anyExtendedKeyUsage || nid == (server ? NID_server_auth : NID_client_auth)) allowed = TRUE;
    }
    EXTENDED_KEY_USAGE_free(extended); return allowed;
}

static int verify(X509_STORE_CTX *store, void *data)
{
    BarevTLS *tls = data;
    X509 *certificate = X509_STORE_CTX_get0_cert(store);
    EVP_PKEY *key = NULL;
    X509_ALGOR *public_algorithm = NULL;
    const X509_ALGOR *signature_algorithm;
    unsigned char public_key[32];
    size_t length = sizeof(public_key);
    gboolean okay = FALSE;
    if (tls->failed || !tls->peer_certificate || !certificate) goto done;
    X509_get0_signature(NULL, &signature_algorithm, certificate);
    if (!ed25519_algorithm(signature_algorithm) || !ed25519_algorithm(X509_get0_tbs_sigalg(certificate)) ||
        X509_ALGOR_cmp(signature_algorithm, X509_get0_tbs_sigalg(certificate)) ||
        !X509_PUBKEY_get0_param(NULL, NULL, NULL, &public_algorithm, X509_get_X509_PUBKEY(certificate)) ||
        !ed25519_algorithm(public_algorithm)) goto done;
    key = X509_get_pubkey(certificate);
    if (!key || EVP_PKEY_id(key) != EVP_PKEY_ED25519 ||
        EVP_PKEY_get_raw_public_key(key, public_key, &length) != 1 || length != 32 ||
        CRYPTO_memcmp(public_key, tls->pin, 32) || X509_NAME_cmp(X509_get_issuer_name(certificate), X509_get_subject_name(certificate)) ||
        X509_verify(certificate, key) != 1 || X509_cmp_current_time(X509_get0_notBefore(certificate)) >= 0 ||
        X509_cmp_current_time(X509_get0_notAfter(certificate)) <= 0 || !usages(certificate, !tls->server)) goto done;
    okay = TRUE;
done:
    EVP_PKEY_free(key);
    tls->verified = okay;
    X509_STORE_CTX_set_error(store, okay ? X509_V_OK : X509_V_ERR_CERT_REJECTED);
    if (!okay) fail(tls, "the peer does not match the pinned Ed25519 identity");
    return okay ? 1 : 0;
}

static X509 *self_signed(EVP_PKEY *key)
{
    X509 *certificate = X509_new();
    X509_NAME *name;
    unsigned char serial[16];
    BIGNUM *number = NULL;
    if (!certificate || RAND_bytes(serial, sizeof(serial)) != 1) goto failed;
    serial[0] = (serial[0] & 0x3f)+1;
    number = BN_bin2bn(serial, sizeof(serial), NULL);
    if (!number || !BN_to_ASN1_INTEGER(number, X509_get_serialNumber(certificate)) ||
        X509_set_version(certificate, 2) != 1 || !X509_gmtime_adj(X509_getm_notBefore(certificate), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L) || X509_set_pubkey(certificate, key) != 1) goto failed;
    name = X509_get_subject_name(certificate);
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"barev", -1, -1, 0) != 1 ||
        X509_set_issuer_name(certificate, name) != 1 || X509_sign(certificate, key, NULL) <= 0) goto failed;
    BN_free(number); return certificate;
failed:
    BN_free(number); X509_free(certificate); return NULL;
}

BarevTLS *barev_tls_new(const BarevIdentity *identity, const unsigned char *pin,
    size_t pin_length, int fd, gboolean server, char error[BAREV_TLS_ERROR_BYTES])
{
    BarevTLS *tls = g_new0(BarevTLS, 1);
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    BIO *bio = NULL;
    unsigned char public_key[32];
    size_t length = sizeof(public_key);
    if (error) error[0] = 0;
    ERR_clear_error();
    if (!identity || !identity->active || !pin || pin_length != 32 || fd < 0) {
        fail(tls, "a local identity, peer key pin and connected descriptor are required"); goto failed;
    }
    tls->server = server; tls->fd = fd; memcpy(tls->pin, pin, 32);
#if !defined(_WIN32) && defined(SO_NOSIGPIPE)
    {
        int enabled = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
            fail(tls, "cannot suppress socket SIGPIPE"); goto failed;
        }
    }
#endif
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, identity->seed, 32);
    if (!key || EVP_PKEY_get_raw_public_key(key, public_key, &length) != 1 || length != 32 ||
        CRYPTO_memcmp(public_key, identity->public_key, 32)) { fail(tls, "invalid local Ed25519 identity"); goto failed; }
    certificate = self_signed(key); tls->context = SSL_CTX_new(TLS_method());
    if (!certificate || !tls->context || SSL_CTX_set_min_proto_version(tls->context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(tls->context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(tls->context, "TLS_AES_128_GCM_SHA256") != 1 ||
        SSL_CTX_set1_groups_list(tls->context, "X25519:P-256") != 1 ||
        SSL_CTX_set1_sigalgs_list(tls->context, "ed25519") != 1 ||
        SSL_CTX_use_certificate(tls->context, certificate) != 1 || SSL_CTX_use_PrivateKey(tls->context, key) != 1 ||
        SSL_CTX_check_private_key(tls->context) != 1 || SSL_CTX_set_num_tickets(tls->context, 0) != 1 ||
        SSL_CTX_set_max_early_data(tls->context, 0) != 1) goto failed;
    SSL_CTX_set_session_cache_mode(tls->context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_max_cert_list(tls->context, 32768);
    SSL_CTX_set_verify(tls->context, SSL_VERIFY_PEER | (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);
    SSL_CTX_set_cert_verify_callback(tls->context, verify, tls);
    tls->ssl = SSL_new(tls->context);
    tls->method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "Barev socket");
    if (!tls->ssl || !tls->method || BIO_socket_nbio(fd, 1) != 1 ||
        BIO_meth_set_read(tls->method, socket_read) != 1 || BIO_meth_set_write(tls->method, socket_write) != 1 ||
        BIO_meth_set_ctrl(tls->method, socket_control) != 1) goto failed;
    bio = BIO_new(tls->method);
    if (!bio) goto failed;
    BIO_set_data(bio, tls); BIO_set_init(bio, 1); SSL_set_bio(tls->ssl, bio, bio);
    SSL_set_msg_callback(tls->ssl, message); SSL_set_msg_callback_arg(tls->ssl, tls);
    if (server) SSL_set_accept_state(tls->ssl); else SSL_set_connect_state(tls->ssl);
    X509_free(certificate); EVP_PKEY_free(key); return tls;
failed:
    if (!tls->failed) ssl_failure(tls);
    if (error) g_strlcpy(error, tls->error, BAREV_TLS_ERROR_BYTES);
    X509_free(certificate); EVP_PKEY_free(key); barev_tls_free(tls); return NULL;
}

void barev_tls_free(BarevTLS *tls)
{
    if (!tls) return;
    SSL_free(tls->ssl); BIO_meth_free(tls->method); SSL_CTX_free(tls->context);
    OPENSSL_cleanse(tls, sizeof(*tls)); g_free(tls);
}

int barev_tls_handshake(BarevTLS *tls)
{
    int result, error;
    if (!tls || tls->failed || tls->closed) return -1;
    if (tls->ready) return 1;
    ERR_clear_error(); result = SSL_do_handshake(tls->ssl);
    error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(tls->ssl, result);
    if (tls->failed) return -1;
    if (result == 1) {
        if (!tls->verified || !tls->peer_certificate || !tls->sent_certificate || (!tls->server && !tls->requested) ||
            SSL_version(tls->ssl) != TLS1_3_VERSION) return fail(tls, "mutual Ed25519 authentication did not complete");
        tls->ready = TRUE; tls->handshake_write = FALSE; return 1;
    }
    tls->handshake_write = error == SSL_ERROR_WANT_WRITE;
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return 0;
    return ssl_failure(tls);
}

gboolean barev_tls_authenticated(const BarevTLS *tls) { return tls && tls->ready && !tls->failed && !tls->closed; }
gboolean barev_tls_wants_write(const BarevTLS *tls) { return tls && !tls->failed && !tls->closed && (tls->handshake_write || tls->read_write || tls->write_write); }
gboolean barev_tls_pending(const BarevTLS *tls) { return barev_tls_authenticated(tls) && SSL_pending(tls->ssl) > 0; }
size_t barev_tls_certificate(const BarevTLS *tls, unsigned char *bytes, size_t capacity)
{
    X509 *certificate;
    int length;
    unsigned char *at = bytes;
    if (!tls || !tls->ssl || !bytes) return 0;
    certificate = SSL_get_certificate(tls->ssl); length = certificate ? i2d_X509(certificate, NULL) : 0;
    if (length <= 0 || (size_t)length > capacity) return 0;
    return i2d_X509(certificate, &at) == length ? (size_t)length : 0;
}
const char *barev_tls_error(const BarevTLS *tls) { return tls ? tls->error : "TLS initialization failed"; }

int barev_tls_read(BarevTLS *tls, void *bytes, size_t length)
{
    size_t received = 0;
    int result, error;
    if (!tls || !tls->ready || tls->failed || !bytes || !length || length > TLS_PLAIN_LIMIT) return -1;
    if (tls->closed) return 0;
    ERR_clear_error(); result = SSL_read_ex(tls->ssl, bytes, length, &received);
    error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(tls->ssl, result);
    tls->read_write = error == SSL_ERROR_WANT_WRITE;
    if (tls->failed) return -1;
    if (result == 1) return (int)received;
    if (error == SSL_ERROR_ZERO_RETURN) { tls->closed = TRUE; return 0; }
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return BAREV_TLS_WOULD_BLOCK;
    return ssl_failure(tls);
}

int barev_tls_write(BarevTLS *tls, const void *bytes, size_t length)
{
    size_t sent = 0;
    int result, error;
    if (!barev_tls_authenticated(tls) || !bytes || !length) return -1;
    if (!tls->writing_length) {
        tls->writing_length = MIN(length, sizeof(tls->writing)); memcpy(tls->writing, bytes, tls->writing_length);
    } else if (length < tls->writing_length || memcmp(tls->writing, bytes, tls->writing_length)) {
        return fail(tls, "TLS write retry changed its unconsumed prefix");
    }
    ERR_clear_error(); result = SSL_write_ex(tls->ssl, tls->writing, tls->writing_length, &sent);
    error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(tls->ssl, result);
    tls->write_write = error == SSL_ERROR_WANT_WRITE;
    if (tls->failed) return -1;
    if (result == 1) {
        if (sent != tls->writing_length) return fail(tls, "incomplete TLS record write");
        OPENSSL_cleanse(tls->writing, tls->writing_length); tls->writing_length = 0; return (int)sent;
    }
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return BAREV_TLS_WOULD_BLOCK;
    return ssl_failure(tls);
}
