/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "image-wire.h"
#include <string.h>

static unsigned checks;
#define CHECK(value) do { ++checks; if (!(value)) g_error("image wire check %u failed", checks); } while (0)

static gboolean deliver(BarevImageWire *from, BarevImageWire *to)
{
    xmlnode *p = barev_image_wire_packet(from);
    if (!p) return FALSE;
    CHECK(barev_image_wire_receive(to, p)); xmlnode_free(p); return TRUE;
}
static void pump(BarevImageWire *a, BarevImageWire *b)
{
    unsigned count = 0;
    gboolean work;
    do { work = deliver(a, b); work = deliver(b, a) || work; CHECK(++count < 1024); } while (work);
}
static void discard(BarevImageWire *wire)
{
    BarevImageEvent *e;
    while ((e = barev_image_wire_event(wire))) barev_image_event_free(e);
}
static void packet(BarevImageWire *wire, const char *text)
{
    xmlnode *p = xmlnode_from_str(text, -1);
    CHECK(p != NULL); CHECK(barev_image_wire_receive(wire, p)); xmlnode_free(p);
}

int main(void)
{
    BarevImageWire *a, *b, *limits[5];
    BarevImageEvent *e;
    gsize size;
    guchar *raw = g_base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGMQVDL+DwACFAFmBODefwAAAABJRU5ErkJggg==", &size);
    guchar *padded = g_malloc0(size+20012);
    int token, receiver;
    unsigned i;
    a = barev_image_wire_new(262144, 65536); b = barev_image_wire_new(262144, 65536);
    CHECK(barev_image_wire_send(a, raw, size, "pixel.png") > 0); pump(a, b);
    e = barev_image_wire_event(b); CHECK(e && e->kind == 2 && e->size == size && !memcmp(e->data, raw, size));
    barev_image_event_free(e);
    CHECK(barev_image_wire_send(a, raw, size, "pixel.png") > 0); CHECK(deliver(a, b));
    CHECK(barev_image_wire_packet(b) == NULL); discard(b);
    CHECK(barev_image_wire_send(a, raw, size, "../pixel.png") == 0);
    barev_image_wire_free(a); barev_image_wire_free(b); CHECK(barev_image_wire_memory() == 0);

    memcpy(padded, raw, size-12); padded[size-10] = 20000/256; padded[size-9] = 20000%256;
    memcpy(padded+size-8, "tEXt", 4); memcpy(padded+size+20000, raw+size-12, 12); size += 20012;
    a = barev_image_wire_new(262144, 1024); b = barev_image_wire_new(0, 1024);
    token = barev_image_wire_send(a, padded, size, "original.png"); CHECK(token > 0); CHECK(deliver(a, b));
    e = barev_image_wire_event(b); CHECK(e && e->kind == 1); receiver = e->token; barev_image_event_free(e); discard(a);
    CHECK(barev_image_wire_accept(b, receiver, TRUE)); pump(a, b);
    e = barev_image_wire_event(b); CHECK(e && e->kind == 2 && e->size == size && !memcmp(e->data, padded, size)); barev_image_event_free(e);
    e = barev_image_wire_event(a); CHECK(e && e->kind == 3); barev_image_event_free(e);
    CHECK(barev_image_wire_progress(a, token) == -1);
    barev_image_wire_free(a); barev_image_wire_free(b); CHECK(barev_image_wire_memory() == 0);

    a = barev_image_wire_new(262144, 1024); b = barev_image_wire_new(262144, 1024);
    CHECK(barev_image_wire_send(a, padded, size, "original.png") > 0);
    CHECK(deliver(a, b)); CHECK(deliver(b, a)); CHECK(deliver(a, b)); discard(a);
    barev_image_wire_cancel(a, -1);
    barev_image_wire_disconnect(b); discard(b);
    barev_image_wire_disconnect(a); discard(a);
    CHECK(barev_image_wire_send(a, padded, size, "original.png") > 0); discard(a);
    for (i = 0; i < 121; ++i) barev_image_wire_tick(a);
    e = barev_image_wire_event(a); CHECK(e && e->kind == 4); barev_image_event_free(e);
    barev_image_wire_free(a); barev_image_wire_free(b); CHECK(barev_image_wire_memory() == 0);

    for (i = 0; i < 5; ++i) {
        limits[i] = barev_image_wire_new(16*1024*1024, 1024);
        packet(limits[i], "<iq type='set' id='offer'><si xmlns='http://jabber.org/protocol/si' id='large' "
            "profile='http://jabber.org/protocol/si/profile/file-transfer' mime-type='image/png'>"
            "<file xmlns='http://jabber.org/protocol/si/profile/file-transfer' name='large.png' size='16777216'/>"
            "<feature xmlns='http://jabber.org/protocol/feature-neg'><x xmlns='jabber:x:data' type='form'>"
            "<field var='stream-method'><option><value>http://jabber.org/protocol/ibb</value></option>"
            "</field></x></feature></si></iq>");
        CHECK(barev_image_wire_memory() == MIN(i+1, 4u)*16777216u);
    }
    for (i = 0; i < 5; ++i) barev_image_wire_free(limits[i]);
    CHECK(barev_image_wire_memory() == 0);
    g_free(raw); g_free(padded);
    g_print("Barev C image wire checks passed: %u\n", checks);
    return 0;
}
