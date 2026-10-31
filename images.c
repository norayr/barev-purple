/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "internal.h"
#include "barev.h"
#include "buddy.h"
#include "images.h"
#include "image-wire.h"
#include "image-ui.h"
#include "address.h"
#include <libpurple/eventloop.h>
#include <string.h>

typedef struct { char *who; BarevImageWire *wire; unsigned refs; gboolean retired; } ImagePeer;
struct BarevImages { PurpleAccount *account; BarevImageUI *ui; GHashTable *peers;
    guint timer; unsigned refs; gboolean closed; };
static void ref(BarevImages *c) { ++c->refs; }
static void unref(BarevImages *c) { if (!--c->refs) g_free(c); }
static ImagePeer *peer_ref(ImagePeer *p) { ++p->refs; return p; }
static void peer_unref(gpointer data)
{
    ImagePeer *p=data;
    if (!--p->refs) { barev_image_wire_free(p->wire); g_free(p->who); g_free(p); }
}
static BarevImages *context(PurpleAccount *account)
{
    PurpleConnection *gc=purple_account_get_connection(account);
    BonjourData *bd=gc?purple_connection_get_protocol_data(gc):NULL;
    return bd?bd->images:NULL;
}
static ImagePeer *peer(BarevImages *c,const char *who,gboolean create)
{
    PurpleBuddy *pb; ImagePeer *p; char *key;
    if (!c || c->closed || !(pb=purple_find_buddy(c->account,who))) return NULL;
    key=g_strdup(purple_normalize(c->account,purple_buddy_get_name(pb)));
    p=g_hash_table_lookup(c->peers,key);
    if (!p && create && g_hash_table_size(c->peers)<256) {
        p=g_new0(ImagePeer,1); p->refs=1; p->who=g_strdup(purple_buddy_get_name(pb));
        p->wire=barev_image_wire_new(CLAMP(purple_account_get_int(c->account,"image_auto_kib",256),0,16384)*1024,
                                   CLAMP(purple_account_get_int(c->account,"image_bob_kib",64),1,256)*1024);
        g_hash_table_insert(c->peers,key,p); key=NULL;
    }
    g_free(key); return p && !p->retired ? p : NULL;
}
static BonjourJabberConversation *connection(BarevImages *c,ImagePeer *p)
{
    PurpleBuddy *pb; BonjourBuddy *bb;
    if (c->closed || p->retired || !(pb=purple_find_buddy(c->account,p->who)) || !(bb=purple_buddy_get_protocol_data(pb)) ||
        !bb->conversation || bb->conversation->closing || bb->conversation->close_timeout ||
        !bb->conversation->recv_stream_start || bb->conversation->sent_stream_start!=STREAM_FULLY_SENT) return NULL;
    return bb->conversation;
}
static void pump(BarevImages *c,ImagePeer *p)
{
    unsigned budget=8;
    BarevImageEvent *e;
    ref(c); peer_ref(p);
    while (!c->closed && budget--) {
        BonjourJabberConversation *conv=connection(c,p);
        xmlnode *packet;
        if (!conv || (conv->tx_buf && conv->tx_buf->bufused>=32768)) break;
        packet=barev_image_wire_packet(p->wire); if (!packet) break;
        xmlnode_set_attrib(packet,"from",bonjour_jabber_get_local_jid(conv)); xmlnode_set_attrib(packet,"to",p->who);
        if (bonjour_jabber_send_xml(conv,packet)<0) barev_image_wire_disconnect(p->wire);
        xmlnode_free(packet);
    }
    budget=16;
    while (!c->closed && budget-- && (e=barev_image_wire_event(p->wire))) {
        BarevImageUI_Event(c->ui,p->who,e->token,e->kind,e->size,e->name,e->caption,e->data,e->kind==2?e->size:0);
        barev_image_event_free(e);
    }
    peer_unref(p); unref(c);
}
static int send_image(gpointer data,const char *who,const guchar *bytes,size_t length,const char *name)
{
    BarevImages *c=data; ImagePeer *p=peer(c,who,TRUE); int token=0;
    if (p && connection(c,p)) { token=barev_image_wire_send(p->wire,bytes,length,name); if (token) pump(c,p); }
    return token;
}
static gboolean accept_image(gpointer data,const char *who,int token,gboolean accepted)
{
    BarevImages *c=data; ImagePeer *p=peer(c,who,FALSE); gboolean okay=FALSE;
    if (p) { okay=barev_image_wire_accept(p->wire,token,accepted); pump(c,p); } return okay;
}
static void cancel_image(gpointer data,const char *who,int token)
{
    BarevImages *c=data; ImagePeer *p=peer(c,who,FALSE);
    if (p) { barev_image_wire_cancel(p->wire,token); pump(c,p); }
}
static int progress(gpointer data,const char *who,int token)
{ ImagePeer *p=peer(data,who,FALSE); return p?barev_image_wire_progress(p->wire,token):-1; }
static gboolean tick(gpointer data)
{
    BarevImages *c=data; GList *values,*it;
    ref(c); values=g_hash_table_get_values(c->peers);
    for (it=values;it;it=it->next) peer_ref(it->data);
    for (it=values;it;it=it->next) {
        ImagePeer *p=it->data;
        if (!c->closed) {
            barev_image_wire_tick(p->wire); pump(c,p);
            if (!c->closed && p->retired) {
                char *key=g_strdup(purple_normalize(c->account,p->who));
                BarevImageUI_Forget(c->ui,p->who);
                if (!c->closed) g_hash_table_remove(c->peers,key);
                g_free(key);
            }
        }
        peer_unref(p);
    }
    g_list_free(values);
    if (!c->closed) BarevImageUI_Update(c->ui);
    { gboolean keep=!c->closed; unref(c); return keep; }
}
BarevImages *barev_images_new(PurpleAccount *account)
{
    BarevImages *c=g_new0(BarevImages,1);
    BarevImageBackend backend={c,send_image,accept_image,cancel_image,progress};
    c->refs=1; c->account=account; c->peers=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,peer_unref);
    c->ui=BarevImageUI_New(account,&backend); c->timer=purple_timeout_add_seconds(1,tick,c); return c;
}
void barev_images_close(BarevImages *c)
{
    if (!c || c->closed) return;
    c->closed=TRUE; if (c->timer) purple_timeout_remove(c->timer);
    BarevImageUI_Close(c->ui); c->ui=NULL; g_hash_table_destroy(c->peers); c->peers=NULL; unref(c);
}
int barev_images_send(BarevImages *c,const char *who,const char *markup,char **stripped)
{ return c?BarevImageUI_Send(c->ui,who,markup,stripped):0; }
static gboolean same(const char *left,const char *right)
{
    char *a=barev_address_identity(left,FALSE),*b=barev_address_identity(right,FALSE);
    gboolean equal=a && b && !strcmp(a,b); g_free(a); g_free(b); return equal;
}
gboolean barev_images_receive(PurpleBuddy *pb,xmlnode *packet)
{
    BarevImages *c=context(purple_buddy_get_account(pb)); ImagePeer *p;
    BonjourBuddy *bb=purple_buddy_get_protocol_data(pb);
    const char *from=xmlnode_get_attrib(packet,"from"),*to=xmlnode_get_attrib(packet,"to");
    gboolean handled;
    if (!c || !bb || !bb->conversation) return FALSE;
    /* Image replies and IBB chunks are always scoped to the validated stream. */
    if ((from && !same(from,bb->conversation->buddy_name?bb->conversation->buddy_name:purple_buddy_get_name(pb))) ||
        (to && !same(to,bonjour_jabber_get_local_jid(bb->conversation)))) return TRUE;
    p=peer(c,purple_buddy_get_name(pb),TRUE); if (!p) return FALSE;
    handled=barev_image_wire_receive(p->wire,packet); if (handled) pump(c,p); return handled;
}
void barev_images_lost(PurpleBuddy *pb)
{
    BarevImages *c=context(purple_buddy_get_account(pb)); ImagePeer *p=peer(c,purple_buddy_get_name(pb),FALSE);
    if (p) barev_image_wire_disconnect(p->wire);
}
void barev_images_forget(PurpleBuddy *pb)
{
    BarevImages *c=context(purple_buddy_get_account(pb)); ImagePeer *p;
    if (!c || c->closed) return;
    p=peer(c,purple_buddy_get_name(pb),FALSE);
    if (p) { barev_image_wire_disconnect(p->wire); p->retired=TRUE; }
}

void barev_images_file_completed(PurpleXfer *xfer)
{
    BarevImages *c=context(purple_xfer_get_account(xfer));
    if (c && !c->closed) { ref(c); BarevImageUI_FileCompleted(c->ui,xfer); unref(c); }
}
