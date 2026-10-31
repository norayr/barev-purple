/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_IMAGE_WIRE_H
#define BAREV_IMAGE_WIRE_H
#include <glib.h>
#include <libpurple/xmlnode.h>
#define BAREV_IMAGE_MAX (16u*1024*1024)
#define BAREV_BOB_MAX (256u*1024)
typedef struct BarevImageWire BarevImageWire;
typedef struct {
    int token, kind;
    size_t size;
    char *name, *caption;
    const guchar *data;
    gpointer private_blob;
} BarevImageEvent;
BarevImageWire *barev_image_wire_new(int automatic, int bob);
void barev_image_wire_free(BarevImageWire *);
void barev_image_wire_disconnect(BarevImageWire *);
void barev_image_wire_tick(BarevImageWire *);
int barev_image_wire_send(BarevImageWire *, const guchar *, size_t, const char *);
gboolean barev_image_wire_receive(BarevImageWire *, xmlnode *);
xmlnode *barev_image_wire_packet(BarevImageWire *);
BarevImageEvent *barev_image_wire_event(BarevImageWire *);
void barev_image_event_free(BarevImageEvent *);
gboolean barev_image_wire_accept(BarevImageWire *, int, gboolean);
void barev_image_wire_cancel(BarevImageWire *, int);
int barev_image_wire_progress(BarevImageWire *, int);
size_t barev_image_wire_memory(void);
#endif
