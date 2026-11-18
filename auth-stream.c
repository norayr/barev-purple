/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "auth-stream.h"
#include <string.h>

#define STREAMS_URI "http://etherx.jabber.org/streams"
#define TLS_URI "urn:ietf:params:xml:ns:xmpp-tls"
#define SASL_URI "urn:ietf:params:xml:ns:xmpp-sasl"

enum {
    INITIAL, WANT_TLS_FEATURES, WANT_STARTTLS, WANT_PROCEED, SENDING_PROCEED,
    HANDSHAKE, TLS_HEADERS, WANT_EXTERNAL_FEATURES, WANT_EXTERNAL, WANT_SUCCESS,
    SENDING_SUCCESS, FINAL_HEADERS, WANT_FINAL_FEATURES, SENDING_FINAL_FEATURES,
    AUTHENTICATED, DEAD
};

void barev_auth_init(BarevAuth *s, gboolean server)
{ s->phase = INITIAL; s->output = BAREV_AUTH_NONE; s->server = server; }

int barev_auth_fail(BarevAuth *s)
{ s->phase = DEAD; s->output = BAREV_AUTH_NONE; return BAREV_AUTH_FAILED; }

static int output(BarevAuth *s, int action, unsigned phase)
{ s->phase = phase; s->output = action; return action; }

int barev_auth_opened(BarevAuth *s)
{
    if (s->output) return barev_auth_fail(s);
    switch (s->phase) {
    case INITIAL:
        if (s->server) return output(s, BAREV_AUTH_TLS_FEATURES, WANT_STARTTLS);
        s->phase = WANT_TLS_FEATURES; break;
    case TLS_HEADERS:
        if (s->server) return output(s, BAREV_AUTH_EXTERNAL_FEATURES, WANT_EXTERNAL);
        s->phase = WANT_EXTERNAL_FEATURES; break;
    case FINAL_HEADERS:
        if (s->server) return output(s, BAREV_AUTH_FINAL_FEATURES, SENDING_FINAL_FEATURES);
        s->phase = WANT_FINAL_FEATURES; break;
    default: return barev_auth_fail(s);
    }
    return BAREV_AUTH_NONE;
}

int barev_auth_sent(BarevAuth *s)
{
    if (!s->output) return barev_auth_fail(s);
    s->output = BAREV_AUTH_NONE;
    switch (s->phase) {
    case SENDING_PROCEED: s->phase = HANDSHAKE; return BAREV_AUTH_BEGIN_TLS;
    case SENDING_SUCCESS: s->phase = FINAL_HEADERS; return BAREV_AUTH_RESTART_SASL;
    case SENDING_FINAL_FEATURES: s->phase = AUTHENTICATED; return BAREV_AUTH_READY;
    default: return BAREV_AUTH_NONE;
    }
}

int barev_auth_secured(BarevAuth *s, gboolean verified)
{
    if (s->phase != HANDSHAKE || !verified) return barev_auth_fail(s);
    s->phase = TLS_HEADERS; return BAREV_AUTH_RESTART_TLS;
}

static gboolean is(const xmlnode *item, const char *uri, const char *name)
{
    return item && item->type == XMLNODE_TYPE_TAG && !g_strcmp0(item->name, name) &&
        !g_strcmp0(xmlnode_get_namespace((xmlnode *)item), uri);
}

static gboolean text(const xmlnode *item, const char *expected)
{
    const xmlnode *part;
    size_t at = 0, length = strlen(expected);
    if (!item) return FALSE;
    for (part = item->child; part; part = part->next) {
        if (part->type == XMLNODE_TYPE_TAG) return FALSE;
        if (part->type == XMLNODE_TYPE_DATA) {
            if (part->data_sz > length-at || memcmp(expected+at, part->data, part->data_sz)) return FALSE;
            at += part->data_sz;
        }
    }
    return at == length;
}

static gboolean attributes(const xmlnode *item)
{
    const xmlnode *part;
    if (!item) return TRUE;
    for (part = item->child; part; part = part->next)
        if (part->type == XMLNODE_TYPE_ATTRIB) return TRUE;
    return FALSE;
}

static gboolean empty(const xmlnode *item)
{ return item && !attributes(item) && text(item, ""); }

static const xmlnode *only_child(const xmlnode *item)
{
    const xmlnode *part, *found = NULL;
    size_t i;
    if (!item || attributes(item)) return NULL;
    for (part = item->child; part; part = part->next) {
        if (part->type == XMLNODE_TYPE_TAG) {
            if (found) return NULL;
            found = part;
        } else if (part->type == XMLNODE_TYPE_DATA) {
            for (i = 0; i < part->data_sz; ++i)
                if (part->data[i] != ' ' && part->data[i] != '\t' && part->data[i] != '\r' && part->data[i] != '\n') return NULL;
        }
    }
    return found;
}

int barev_auth_receive(BarevAuth *s, const xmlnode *item)
{
    const xmlnode *child, *leaf, *part;
    unsigned count;
    if (s->output || !item) return barev_auth_fail(s);
    switch (s->phase) {
    case WANT_TLS_FEATURES:
        child = only_child(item); leaf = only_child(child);
        if (is(item, STREAMS_URI, "features") && is(child, TLS_URI, "starttls") && is(leaf, TLS_URI, "required") && empty(leaf))
            return output(s, BAREV_AUTH_STARTTLS, WANT_PROCEED);
        break;
    case WANT_STARTTLS:
        if (is(item, TLS_URI, "starttls") && empty(item)) return output(s, BAREV_AUTH_PROCEED, SENDING_PROCEED);
        break;
    case WANT_PROCEED:
        if (is(item, TLS_URI, "proceed") && empty(item)) { s->phase = HANDSHAKE; return BAREV_AUTH_BEGIN_TLS; }
        break;
    case WANT_EXTERNAL_FEATURES:
        child = only_child(item); leaf = only_child(child);
        if (is(item, STREAMS_URI, "features") && is(child, SASL_URI, "mechanisms") && is(leaf, SASL_URI, "mechanism") &&
            !attributes(leaf) && text(leaf, "EXTERNAL")) return output(s, BAREV_AUTH_EXTERNAL, WANT_SUCCESS);
        break;
    case WANT_EXTERNAL:
        count = 0;
        for (part = item->child; part; part = part->next) {
            if (part->type == XMLNODE_TYPE_ATTRIB) {
                if (g_strcmp0(part->name, "mechanism") || (part->xmlns && *part->xmlns) || g_strcmp0(part->data, "EXTERNAL"))
                    return barev_auth_fail(s);
                ++count;
            }
        }
        if (is(item, SASL_URI, "auth") && count == 1 && text(item, "=")) return output(s, BAREV_AUTH_SUCCESS, SENDING_SUCCESS);
        break;
    case WANT_SUCCESS:
        if (is(item, SASL_URI, "success") && empty(item)) { s->phase = FINAL_HEADERS; return BAREV_AUTH_RESTART_SASL; }
        break;
    case WANT_FINAL_FEATURES:
        if (is(item, STREAMS_URI, "features") && empty(item)) { s->phase = AUTHENTICATED; return BAREV_AUTH_READY; }
        break;
    default: break;
    }
    return barev_auth_fail(s);
}

const char *barev_auth_output(const BarevAuth *s)
{
    switch (s->output) {
    case BAREV_AUTH_TLS_FEATURES: return "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>";
    case BAREV_AUTH_STARTTLS: return "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
    case BAREV_AUTH_PROCEED: return "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
    case BAREV_AUTH_EXTERNAL_FEATURES: return "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
    case BAREV_AUTH_EXTERNAL: return "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>";
    case BAREV_AUTH_SUCCESS: return "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
    case BAREV_AUTH_FINAL_FEATURES: return "<stream:features/>";
    default: return "";
    }
}

gboolean barev_auth_ready(const BarevAuth *s) { return s->phase == AUTHENTICATED; }
gboolean barev_auth_handshaking(const BarevAuth *s) { return s->phase == HANDSHAKE; }
gboolean barev_auth_writing(const BarevAuth *s) { return s->output != BAREV_AUTH_NONE; }
