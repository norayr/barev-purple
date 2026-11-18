/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "tls.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

static unsigned checks;
#define CHECK(condition) do { ++checks; if (!(condition)) { fprintf(stderr, "FAIL TLS check %u, line %d\n", checks, __LINE__); exit(1); } } while (0)

static gboolean public_key(BarevIdentity *identity)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, identity->seed, 32);
    size_t length = 32;
    gboolean okay = key && EVP_PKEY_get_raw_public_key(key, identity->public_key, &length) == 1 && length == 32;
    EVP_PKEY_free(key); identity->active = okay; return okay;
}

static size_t hex(const char *text, unsigned char bytes[32])
{
    size_t at, n = strlen(text);
    CHECK(n <= 64 && n%2 == 0);
    for (at = 0; at < n; at += 2) {
        int high = g_ascii_xdigit_value(text[at]), low = g_ascii_xdigit_value(text[at+1]);
        CHECK(high >= 0 && low >= 0); bytes[at/2] = high*16+low;
    }
    return n/2;
}

static void deadline(gint64 started) { CHECK(g_get_monotonic_time()-started < 15000000); }

static int selftest(void)
{
    BarevIdentity keys[2], original;
    BarevTLS *tls[2];
    int sockets[2], result[2] = {0}, small = 1024, j, n;
    char error[BAREV_TLS_ERROR_BYTES];
    unsigned char bytes[16384], moved[16384], received[16384];
    size_t sent = 0, got = 0, i, wanted = 65537;
    gint64 started = g_get_monotonic_time();
    memset(keys, 0, sizeof(keys));
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    for (j = 0; j < 2; ++j) { for (i = 0; i < 32; ++i) keys[j].seed[i] = i+j; CHECK(public_key(&keys[j])); }
    original = keys[0];
    tls[0] = barev_tls_new(&keys[0], keys[1].public_key, 32, sockets[0], FALSE, error); CHECK(tls[0]);
    tls[1] = barev_tls_new(&keys[1], keys[0].public_key, 32, sockets[1], TRUE, error); CHECK(tls[1]);
    CHECK(!memcmp(&original, &keys[0], sizeof(original)));
    CHECK(barev_tls_write(tls[0], "hello", 5) == -1 && barev_tls_read(tls[0], received, sizeof(received)) == -1);
    while (result[0] != 1 || result[1] != 1) {
        for (j = 0; j < 2; ++j) { result[j] = barev_tls_handshake(tls[j]); CHECK(result[j] >= 0); }
        deadline(started);
    }
    CHECK(barev_tls_authenticated(tls[0]) && barev_tls_authenticated(tls[1]));
    while (got < wanted) {
        if (sent < wanted) {
            size_t length = MIN(sizeof(bytes), wanted-sent);
            for (i = 0; i < length; ++i) bytes[i] = (sent+i)*7;
            memcpy(moved, bytes, length);
            n = barev_tls_write(tls[0], sent%2 ? moved : bytes, length);
            CHECK(n > 0 || n == BAREV_TLS_WOULD_BLOCK);
            if (n > 0) sent += n;
        }
        n = barev_tls_read(tls[1], received, sizeof(received));
        CHECK(n > 0 || n == BAREV_TLS_WOULD_BLOCK);
        if (n > 0) { for (i = 0; i < (size_t)n; ++i) CHECK(received[i] == (unsigned char)((got+i)*7)); got += n; }
        deadline(started);
    }
    CHECK(sent == wanted);
    memset(bytes, 17, sizeof(bytes));
    do { n = barev_tls_write(tls[0], bytes, sizeof(bytes)); deadline(started); } while (n > 0);
    CHECK(n == BAREV_TLS_WOULD_BLOCK && barev_tls_wants_write(tls[0]));
    bytes[0] ^= 1; CHECK(barev_tls_write(tls[0], bytes, sizeof(bytes)) == -1);
    CHECK(!barev_tls_authenticated(tls[0]) && barev_tls_handshake(tls[0]) == -1);
    CHECK(barev_tls_read(tls[0], received, sizeof(received)) == -1);
    for (j = 0; j < 2; ++j) { barev_tls_free(tls[j]); CHECK(fcntl(sockets[j], F_GETFD) >= 0); close(sockets[j]); }
    printf("TLS transport: %u checks passed\n", checks); return 0;
}

int main(int argc, char **argv)
{
    BarevIdentity identity = {0}, original;
    BarevTLS *tls;
    unsigned char pin[32], bytes[32], certificate[4096];
    char error[BAREV_TLS_ERROR_BYTES];
    gboolean server;
    size_t pin_length, at;
    gint64 started = g_get_monotonic_time();
    int fd, result;
    if (argc == 2 && !strcmp(argv[1], "selftest")) return selftest();
    if (argc != 6) return 2;
    CHECK(hex(argv[1], identity.seed) == 32 && public_key(&identity));
    pin_length = hex(argv[2], pin); fd = atoi(argv[3]); server = !strcmp(argv[4], "server");
    original = identity; tls = barev_tls_new(&identity, pin, pin_length, fd, server, error);
    CHECK(!memcmp(&identity, &original, sizeof(identity)));
    if (!strcmp(argv[5], "begin-reject")) { CHECK(!tls && *error); close(fd); return 0; }
    CHECK(tls);
    at = barev_tls_certificate(tls, certificate, sizeof(certificate)); CHECK(at > 0);
    printf("CERT "); for (pin_length = 0; pin_length < at; ++pin_length) printf("%02x", certificate[pin_length]); putchar('\n'); fflush(stdout);
    CHECK(barev_tls_write(tls, "hello", 5) == -1 && barev_tls_read(tls, bytes, sizeof(bytes)) == -1);
    do { result = barev_tls_handshake(tls); g_usleep(1000); deadline(started); } while (!result);
    if (!strcmp(argv[5], "reject")) {
        CHECK(result == -1 && !barev_tls_authenticated(tls) && *barev_tls_error(tls));
        CHECK(barev_tls_write(tls, "hello", 5) == -1 && barev_tls_read(tls, bytes, sizeof(bytes)) == -1);
        puts(barev_tls_error(tls)); barev_tls_free(tls); close(fd); return 0;
    }
    if (result != 1) fprintf(stderr, "%s\n", barev_tls_error(tls));
    CHECK(result == 1 && barev_tls_authenticated(tls));
    if (!server) {
        do { result = barev_tls_write(tls, "hello", 5); g_usleep(1000); deadline(started); } while (result == BAREV_TLS_WOULD_BLOCK);
        CHECK(result == 5);
    }
    for (at = 0; at < 5;) {
        result = barev_tls_read(tls, bytes+at, 5-at); deadline(started); g_usleep(1000);
        CHECK(result > 0 || result == BAREV_TLS_WOULD_BLOCK); if (result > 0) at += result;
    }
    CHECK(!memcmp(bytes, server ? "hello" : "world", 5));
    if (server) {
        do { result = barev_tls_write(tls, "world", 5); g_usleep(1000); deadline(started); } while (result == BAREV_TLS_WOULD_BLOCK);
        CHECK(result == 5);
    }
    barev_tls_free(tls); close(fd); puts("PASS authenticated TLS transport"); return 0;
}
