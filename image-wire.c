/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bounded peer-scoped BoB objects and SI/IBB image transfers. */
#include "image-wire.h"
#include <string.h>
#include <libpurple/util.h>

#define BOB "urn:xmpp:bob"
#define IBB "http://jabber.org/protocol/ibb"
#define SI "http://jabber.org/protocol/si"
#define FILE_NS "http://jabber.org/protocol/si/profile/file-transfer"
#define FEATURE "http://jabber.org/protocol/feature-neg"
#define FORM "jabber:x:data"
#define XHTML "http://www.w3.org/1999/xhtml"
#define XHTML_IM "http://jabber.org/protocol/xhtml-im"
#define DISCO "http://jabber.org/protocol/disco#info"
#define MEMORY_MAX (64u*1024*1024)
#define BLOCK 4096
enum { WAIT_OFFER=1, WAIT_OPEN, WAIT_DATA, WAIT_CLOSE, CONSENT, RECEIVING };
typedef struct { unsigned refs; guchar *data; size_t size; char *mime, *cid; } Blob;
typedef struct { int token, age; char *cid, *id, *caption; } Pending;
typedef struct { int token, phase, age; size_t size, done, count; unsigned seq, block;
    char *sid, *id, *name, *mime; Blob *blob; } Transfer;
struct BarevImageWire { Blob *cache[8]; unsigned oldest, budget, image_budget; int automatic, bob;
    Pending *pending[4]; Transfer *tx, *rx; GQueue packets, events; };
static int serial;
static size_t memory;
static int next_token(void) { return serial == G_MAXINT ? 0 : ++serial; }
static char *identifier(const char *prefix, int token) { return g_strdup_printf("%s%d", prefix, token); }
static Blob *retain(Blob *b) { if (b) ++b->refs; return b; }
static void release(Blob *b)
{
    if (b && !--b->refs) { memory -= b->size; g_free(b->data); g_free(b->mime); g_free(b->cid); g_free(b); }
}
static Blob *allocate(size_t size)
{
    Blob *b;
    if (!size || size > BAREV_IMAGE_MAX || size > MEMORY_MAX-memory) return NULL;
    b = g_new0(Blob, 1); b->data = g_malloc(size); b->size = size; b->refs = 1; memory += size; return b;
}

static unsigned be16(const guchar *p) { return p[0]*256u+p[1]; }
static const char *image_type(const guchar *p, size_t n)
{
    size_t at;
    unsigned width=0, height=0;
    gboolean frame=FALSE, data=FALSE;
    if (n >= 33 && !memcmp(p, "\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR", 16)) {
        if (p[16] || p[17] || p[20] || p[21]) return NULL;
        width=be16(p+18); height=be16(p+22);
        if (!width || !height || width>8192 || height>8192 || width>16777216u/height) return NULL;
        for (at=33; at+12<=n;) {
            size_t count;
            if (p[at]) return NULL;
            count=p[at+1]*65536u+p[at+2]*256u+p[at+3];
            if (count>n-at-12) return NULL;
            if (!memcmp(p+at+4,"acTL",4) || !memcmp(p+at+4,"IHDR",4)) return NULL;
            if (!memcmp(p+at+4,"IDAT",4)) data=TRUE;
            if (!memcmp(p+at+4,"IEND",4)) return data && !count && at+12==n ? "image/png" : NULL;
            at+=count+12;
        }
        return NULL;
    }
    if (n<4 || p[0]!=255 || p[1]!=216) return NULL;
    at=2;
    while (at+2<=n) {
        unsigned marker, count;
        if (p[at]!=255) return NULL;
        while (at<n && p[at]==255) ++at;
        if (at==n) return NULL;
        marker=p[at++];
        if (marker==217) return frame && data && at==n ? "image/jpeg" : NULL;
        if (marker==216 || marker==220 || at+2>n) return NULL;
        count=be16(p+at); if (count<2 || count>n-at) return NULL;
        if (marker>=192 && marker<=194) {
            unsigned components;
            if (frame || count<8 || p[at+2]!=8) return NULL;
            height=be16(p+at+3); width=be16(p+at+5); components=p[at+7];
            if (!width || !height || width>8192 || height>8192 || width>16777216u/height ||
                (components!=1 && components!=3) || count!=8+3*components) return NULL;
            frame=TRUE;
        } else if (marker>=195 && marker<=207 && marker!=196 && marker!=204) return NULL;
        at+=count;
        if (marker==218) {
            if (!frame) return NULL;
            data=TRUE;
            while (at<n) {
                size_t start;
                if (p[at]!=255) { ++at; continue; }
                start=at; while (at<n && p[at]==255) ++at;
                if (at==n) return NULL;
                if (!p[at] || (p[at]>=208 && p[at]<=215)) ++at;
                else { at=start; break; }
            }
        }
    }
    return NULL;
}
static gboolean identify(Blob *b)
{
    const char *mime=image_type(b->data,b->size);
    char *hash;
    if (!mime) return FALSE;
    hash=g_compute_checksum_for_data(G_CHECKSUM_SHA1,b->data,b->size);
    g_free(b->mime); g_free(b->cid); b->mime=g_strdup(mime); b->cid=g_strdup_printf("sha1+%s@bob.xmpp.org",hash);
    g_free(hash); return TRUE;
}
static gboolean cid_valid(const char *s)
{
    unsigned i;
    if (!s || strlen(s)!=58 || strncmp(s,"sha1+",5) || strcmp(s+45,"@bob.xmpp.org")) return FALSE;
    for (i=5;i<45;++i) if (!(s[i]>='0' && s[i]<='9') && !(s[i]>='a' && s[i]<='f')) return FALSE;
    return TRUE;
}
static Blob *cached(BarevImageWire *c,const char *cid)
{
    unsigned i;
    for (i=0;cid && i<8;++i) if (c->cache[i] && !strcmp(c->cache[i]->cid,cid)) return c->cache[i];
    return NULL;
}
static void cache(BarevImageWire *c,Blob *b)
{
    if (cached(c,b->cid)) return;
    release(c->cache[c->oldest]); c->cache[c->oldest]=retain(b); c->oldest=(c->oldest+1)%8;
}
static gboolean queue(BarevImageWire *c,xmlnode *item)
{
    if (!item) return FALSE;
    if (c->packets.length>=8) { xmlnode_free(item); return FALSE; }
    g_queue_push_tail(&c->packets,item); return TRUE;
}
static gboolean notify(BarevImageWire *c,int token,int kind,size_t size,const char *name,const char *caption,Blob *b)
{
    BarevImageEvent *e;
    if (c->events.length>=16) return FALSE;
    e=g_new0(BarevImageEvent,1); e->token=token; e->kind=kind; e->size=size;
    e->name=g_strdup(name); e->caption=g_strdup(caption); e->private_blob=retain(b); e->data=b?b->data:NULL;
    g_queue_push_tail(&c->events,e); return TRUE;
}
void barev_image_event_free(BarevImageEvent *e)
{ if (e) { release(e->private_blob); g_free(e->name); g_free(e->caption); g_free(e); } }
static xmlnode *child(xmlnode *p,const char *ns,const char *name)
{ xmlnode *n=xmlnode_new_child(p,name); xmlnode_set_namespace(n,ns); return n; }
static xmlnode *unique(xmlnode *p,const char *ns,const char *name)
{
    xmlnode *n,*found=NULL;
    for (n=p?p->child:NULL;n;n=n->next)
        if (n->type==XMLNODE_TYPE_TAG && !g_strcmp0(n->name,name) && !g_strcmp0(xmlnode_get_namespace(n),ns)) {
            if (found) return NULL;
            found=n;
        }
    return found;
}
static const char *attr(xmlnode *p,const char *key) { return p?xmlnode_get_attrib(p,key):NULL; }
static xmlnode *packet(const char *id,const char *type)
{ xmlnode *p=xmlnode_new("iq"); xmlnode_set_attrib(p,"type",type); xmlnode_set_attrib(p,"id",id); return p; }
static gboolean valid_id(const char *s) { return s && *s && strlen(s)<=128 && g_utf8_validate(s,-1,NULL); }
static gboolean number(const char *s,size_t *out)
{
    size_t v=0;
    if (!s || !*s || strlen(s)>10) return FALSE;
    for (;*s;++s) { if (*s<'0' || *s>'9' || v>((size_t)G_MAXINT-(*s-'0'))/10) return FALSE; v=v*10+*s-'0'; }
    *out=v; return TRUE;
}
static gboolean filename(const char *s)
{
    const unsigned char *p=(const unsigned char *)s;
    if (!s || !*s || strlen(s)>255 || !g_utf8_validate(s,-1,NULL) || !strcmp(s,".") || !strcmp(s,"..")) return FALSE;
    for (;*p;++p) if (*p<32 || *p==127 || *p=='/' || *p=='\\' || *p==':') return FALSE;
    return TRUE;
}
static char *text(xmlnode *p,size_t maximum)
{
    xmlnode *n; char *s;
    if (!p) return NULL;
    for (n=p->child;n;n=n->next) if (n->type==XMLNODE_TYPE_TAG) return NULL;
    s=xmlnode_get_data(p); if (!s) s=g_strdup("");
    if (strlen(s)>maximum) { g_free(s); return NULL; } return s;
}
static void reject(BarevImageWire *c,const char *id,const char *condition)
{
    xmlnode *p,*e;
    if (!valid_id(id)) return;
    p=packet(id,"error"); e=xmlnode_new_child(p,"error"); xmlnode_set_attrib(e,"type","cancel");
    child(e,"urn:ietf:params:xml:ns:xmpp-stanzas",condition); queue(c,p);
}
static void result(BarevImageWire *c,const char *id) { queue(c,packet(id,"result")); }
static guchar *decode(const char *s,size_t maximum,size_t *length)
{
    GString *clean; guchar *raw; char *again; gboolean okay; const char *p;
    if (!s || strlen(s)>350552) return NULL;
    clean=g_string_new(NULL);
    for (p=s;*p;++p) if (*p!=' ' && *p!='\r' && *p!='\n' && *p!='\t') g_string_append_c(clean,*p);
    if (!clean->len || clean->len%4 || clean->len>4*((maximum+2)/3)) { g_string_free(clean,TRUE); return NULL; }
    raw=g_base64_decode(clean->str,length); again=g_base64_encode(raw,*length);
    okay=*length<=maximum && !strcmp(again,clean->str); g_free(again); g_string_free(clean,TRUE);
    if (!okay) { g_free(raw); return NULL; } return raw;
}
static void selection(xmlnode *si,gboolean offer)
{
    xmlnode *form=child(child(si,FEATURE,"feature"),FORM,"x"),*field,*value;
    xmlnode_set_attrib(form,"type",offer?"form":"submit"); field=child(form,FORM,"field");
    xmlnode_set_attrib(field,"var","stream-method");
    if (offer) { xmlnode_set_attrib(field,"type","list-single"); field=child(field,FORM,"option"); }
    value=child(field,FORM,"value"); xmlnode_insert_data(value,IBB,-1);
}
static gboolean method(xmlnode *p,gboolean offer)
{
    xmlnode *si=unique(p,SI,"si"),*form=unique(unique(si,FEATURE,"feature"),FORM,"x"),*field,*n;
    if (g_strcmp0(attr(form,"type"),offer?"form":"submit")) return FALSE;
    field=unique(form,FORM,"field"); if (g_strcmp0(attr(field,"var"),"stream-method")) return FALSE;
    if (!offer) { char *s=text(unique(field,FORM,"value"),128); gboolean yes=!g_strcmp0(s,IBB); g_free(s); return yes; }
    for (n=field->child;n;n=n->next) if (n->type==XMLNODE_TYPE_TAG && !g_strcmp0(n->name,"option") && !g_strcmp0(xmlnode_get_namespace(n),FORM)) {
        char *s=text(unique(n,FORM,"value"),128); gboolean yes=!g_strcmp0(s,IBB); g_free(s); if (yes) return TRUE;
    }
    return FALSE;
}
static xmlnode *si_packet(Transfer *t,gboolean accept)
{
    xmlnode *p=packet(t->id,accept?"result":"set"),*si=child(p,SI,"si"),*file;
    if (!accept) {
        char *size=g_strdup_printf("%zu",t->size);
        xmlnode_set_attrib(si,"id",t->sid); xmlnode_set_attrib(si,"profile",FILE_NS); xmlnode_set_attrib(si,"mime-type",t->mime);
        file=child(si,FILE_NS,"file"); xmlnode_set_attrib(file,"name",t->name); xmlnode_set_attrib(file,"size",size); g_free(size);
    }
    selection(si,!accept); return p;
}
static void transfer_free(Transfer *t)
{ if (t) { release(t->blob); g_free(t->sid); g_free(t->id); g_free(t->name); g_free(t->mime); g_free(t); } }
static void fail(BarevImageWire *c,Transfer **t)
{ if (*t) { notify(c,(*t)->token,4,(*t)->size,(*t)->name,"Image transfer failed or was declined.",NULL); transfer_free(*t); *t=NULL; } }
static void pending_free(Pending *p)
{ if (p) { g_free(p->cid); g_free(p->id); g_free(p->caption); g_free(p); } }
static gboolean request(BarevImageWire *c,Pending *p)
{
    xmlnode *iq,*data; g_free(p->id); p->id=identifier("bib",p->token); p->age=0;
    iq=packet(p->id,"get"); data=child(iq,BOB,"data"); xmlnode_set_attrib(data,"cid",p->cid); return queue(c,iq);
}
static void send_block(BarevImageWire *c)
{
    Transfer *t=c->tx; xmlnode *p,*data;
    g_free(t->id); t->id=identifier("bid",next_token()); p=packet(t->id,"set");
    if (t->done==t->size) { data=child(p,IBB,"close"); t->phase=WAIT_CLOSE; }
    else {
        char *encoded,*seq=g_strdup_printf("%u",t->seq);
        t->count=MIN((size_t)BLOCK,t->size-t->done); encoded=g_base64_encode(t->blob->data+t->done,t->count);
        data=child(p,IBB,"data"); xmlnode_set_attrib(data,"seq",seq); xmlnode_insert_data(data,encoded,-1);
        g_free(encoded); g_free(seq); t->phase=WAIT_DATA;
    }
    xmlnode_set_attrib(data,"sid",t->sid); if (!queue(c,p)) t->phase=0;
}

BarevImageWire *barev_image_wire_new(int automatic,int bob)
{ BarevImageWire *c=g_new0(BarevImageWire,1); c->automatic=CLAMP(automatic,0,(int)BAREV_IMAGE_MAX); c->bob=CLAMP(bob,1024,(int)BAREV_BOB_MAX); c->budget=c->image_budget=8; return c; }
int barev_image_wire_send(BarevImageWire *c,const guchar *bytes,size_t size,const char *name)
{
    Blob *b; int token;
    if (!c || c->tx || !bytes || !filename(name)) return 0;
    b=allocate(size); if (!b) return 0; memcpy(b->data,bytes,size);
    if (!identify(b) || !(token=next_token())) { release(b); return 0; }
    if (size<=(size_t)c->bob) {
        xmlnode *p=xmlnode_new("message"),*body,*img;
        char *src=g_strdup_printf("cid:%s",b->cid);
        xmlnode_set_attrib(p,"type","chat"); body=child(p,"jabber:client","body"); xmlnode_insert_data(body,"[Image]",-1);
        body=child(child(p,XHTML_IM,"html"),XHTML,"body"); img=child(body,XHTML,"img");
        xmlnode_set_attrib(img,"src",src); xmlnode_set_attrib(img,"alt","Image"); g_free(src);
        if (!queue(c,p)) { release(b); return 0; } cache(c,b); release(b); return token;
    }
    c->tx=g_new0(Transfer,1); c->tx->token=token; c->tx->blob=b; c->tx->size=size; c->tx->mime=g_strdup(b->mime);
    c->tx->name=g_strdup(name); c->tx->sid=identifier("bis",token); c->tx->id=identifier("bio",token); c->tx->phase=WAIT_OFFER;
    if (!queue(c,si_packet(c->tx,FALSE))) { transfer_free(c->tx); c->tx=NULL; return 0; }
    notify(c,token,5,size,name,"Sending original image over the messaging connection",NULL); return token;
}
gboolean barev_image_wire_accept(BarevImageWire *c,int token,gboolean yes)
{
    unsigned i;
    if (!c) return FALSE;
    if (c->rx && c->rx->token==token) {
        if (!yes) { reject(c,c->rx->id,"forbidden"); fail(c,&c->rx); return TRUE; }
        if (c->rx->phase!=CONSENT) return FALSE;
        c->rx->blob=allocate(c->rx->size);
        if (!c->rx->blob || !queue(c,si_packet(c->rx,TRUE))) { reject(c,c->rx->id,"resource-constraint"); fail(c,&c->rx); return FALSE; }
        c->rx->phase=WAIT_OPEN; c->rx->age=0; return TRUE;
    }
    for (i=0;i<4;++i) if (c->pending[i] && c->pending[i]->token==token) {
        Pending *p=c->pending[i]; Blob *b=cached(c,p->cid);
        if (!yes) { pending_free(p); c->pending[i]=NULL; return TRUE; }
        if (b) {
            if (!notify(c,token,2,b->size,"image",p->caption,b)) return FALSE;
            pending_free(p); c->pending[i]=NULL; return TRUE;
        }
        return request(c,p);
    }
    return FALSE;
}
static void find_images(BarevImageWire *c,xmlnode *node,const char *caption,unsigned depth,unsigned *found)
{
    xmlnode *n; const char *src; unsigned i;
    if (!node || depth>16 || *found>=4 || g_strcmp0(xmlnode_get_namespace(node),XHTML)) return;
    if (!strcmp(node->name,"img")) {
        Pending *p; Blob *b;
        src=attr(node,"src"); if (!src || strncmp(src,"cid:",4) || !cid_valid(src+4)) return;
        if (!c->image_budget) return;
        --c->image_budget;
        for (i=0;i<4 && c->pending[i];++i) {}
        if (i==4) return;
        p=g_new0(Pending,1); p->token=next_token(); p->cid=g_strdup(src+4); p->caption=g_strdup(*found?"":caption);
        c->pending[i]=p; ++*found; b=cached(c,p->cid);
        if (c->automatic>=(int)BAREV_BOB_MAX || (b && b->size<=(size_t)c->automatic)) {
            if (b) { notify(c,p->token,2,b->size,"image",p->caption,b); pending_free(p); c->pending[i]=NULL; }
            else if (!request(c,p)) { pending_free(p); c->pending[i]=NULL; }
        } else if (!notify(c,p->token,1,0,"inline-image.png","Inline image (at most 256 KiB)",NULL)) {
            pending_free(p); c->pending[i]=NULL;
        }
        return;
    }
    for (n=node->child;n;n=n->next) if (n->type==XMLNODE_TYPE_TAG) find_images(c,n,caption,depth+1,found);
}
static gboolean references(xmlnode *node,const char *cid,unsigned depth)
{
    xmlnode *n; const char *src;
    if (!node || depth>16 || g_strcmp0(xmlnode_get_namespace(node),XHTML)) return FALSE;
    if (!strcmp(node->name,"img")) {
        src=attr(node,"src"); return src && !strncmp(src,"cid:",4) && !strcmp(src+4,cid);
    }
    for (n=node->child;n;n=n->next)
        if (n->type==XMLNODE_TYPE_TAG && references(n,cid,depth+1)) return TRUE;
    return FALSE;
}
static Blob *read_bob(xmlnode *data,const char *expected)
{
    const char *cid=attr(data,"cid"),*mime=attr(data,"type"); char *encoded;
    guchar *bytes; gsize size=0; Blob *b;
    if (!cid_valid(cid) || (expected && strcmp(cid,expected)) || !mime) return NULL;
    encoded=text(data,350552); bytes=encoded?decode(encoded,BAREV_BOB_MAX,&size):NULL; g_free(encoded);
    if (!bytes) return NULL;
    b=allocate(size);
    if (b) {
        memcpy(b->data,bytes,size);
        if (!identify(b) || strcmp(b->cid,cid) || strcmp(b->mime,mime)) { release(b); b=NULL; }
    }
    g_free(bytes); return b;
}
gboolean barev_image_wire_receive(BarevImageWire *c,xmlnode *p)
{
    const char *kind,*id,*sid; xmlnode *data,*si,*n; unsigned i;
    Transfer *t;
    if (!c || !p) return FALSE;
    if (xmlnode_get_namespace(p) && strcmp(xmlnode_get_namespace(p), "jabber:client")) return FALSE;
    kind=attr(p,"type"); id=attr(p,"id");
    if (!strcmp(p->name,"message")) {
        xmlnode *html,*rich; char *caption,*body; unsigned found=0; Blob *b;
        if (kind && *kind && strcmp(kind,"chat") && strcmp(kind,"normal")) return FALSE;
        html=unique(p,XHTML_IM,"html"); if (!html) html=unique(p,XHTML,"html"); rich=unique(html,XHTML,"body");
        if (!rich) return FALSE;
        body=text(unique(p,"jabber:client","body"),8192);
        if (!body) body=text(xmlnode_get_child(p,"body"),8192);
        caption=body && strcmp(body,"[Image]")?purple_markup_escape_text(body,-1):g_strdup(""); g_free(body);
        data=unique(p,BOB,"data");
        b=data && c->image_budget && cid_valid(attr(data,"cid")) && references(rich,attr(data,"cid"),0)?read_bob(data,NULL):NULL;
        if (b) { cache(c,b); release(b); }
        find_images(c,rich,caption,0,&found); g_free(caption); return found>0;
    }
    if (strcmp(p->name,"iq") || !kind || !valid_id(id)) return FALSE;
    data=unique(p,BOB,"data");
    if (!strcmp(kind,"get") && data) {
        Blob *b=cached(c,attr(data,"cid"));
        if (!b || b->size>BAREV_BOB_MAX) reject(c,id,"item-not-found");
        else if (!c->budget || c->packets.length) reject(c,id,"resource-constraint");
        else {
            char *encoded=g_base64_encode(b->data,b->size); xmlnode *reply=packet(id,"result"),*d=child(reply,BOB,"data"); --c->budget;
            xmlnode_set_attrib(d,"cid",b->cid); xmlnode_set_attrib(d,"type",b->mime); xmlnode_set_attrib(d,"max-age","600");
            xmlnode_insert_data(d,encoded,-1); g_free(encoded); queue(c,reply);
        }
        return TRUE;
    }
    if (!strcmp(kind,"get") && unique(p,DISCO,"query")) {
        xmlnode *reply=packet(id,"result"),*q=child(reply,DISCO,"query");
        xmlnode_set_attrib(child(q,DISCO,"feature"),"var",BOB); xmlnode_set_attrib(child(q,DISCO,"feature"),"var",IBB);
        xmlnode_set_attrib(child(q,DISCO,"feature"),"var",SI); xmlnode_set_attrib(child(q,DISCO,"feature"),"var",FILE_NS);
        xmlnode_set_attrib(child(q,DISCO,"feature"),"var",XHTML_IM);
        queue(c,reply); return TRUE;
    }
    if (!strcmp(kind,"result") || !strcmp(kind,"error")) {
        for (i=0;i<4;++i) if (c->pending[i] && !g_strcmp0(c->pending[i]->id,id)) {
            Pending *pending=c->pending[i]; Blob *b=!strcmp(kind,"result")?read_bob(data,pending->cid):NULL;
            c->pending[i]=NULL;
            if (b) { cache(c,b); notify(c,pending->token,2,b->size,"image",pending->caption,b); }
            else notify(c,pending->token,4,0,"image","Inline image unavailable or invalid.",NULL);
            release(b); pending_free(pending); return TRUE;
        }
        t=c->tx; if (!t || strcmp(t->id,id)) return FALSE;
        if (!strcmp(kind,"error")) { fail(c,&c->tx); return TRUE; }
        t->age=0;
        if (t->phase==WAIT_OFFER) {
            xmlnode *reply;
            if (!method(p,FALSE)) { fail(c,&c->tx); return TRUE; }
            g_free(t->id); t->id=identifier("biu",next_token()); reply=packet(t->id,"set"); n=child(reply,IBB,"open");
            xmlnode_set_attrib(n,"sid",t->sid); xmlnode_set_attrib(n,"block-size","4096"); xmlnode_set_attrib(n,"stanza","iq");
            t->phase=WAIT_OPEN; if (!queue(c,reply)) fail(c,&c->tx);
        } else if (t->phase==WAIT_OPEN) send_block(c);
        else if (t->phase==WAIT_DATA) { t->done+=t->count; t->seq=(t->seq+1)%65536; send_block(c); }
        else if (t->phase==WAIT_CLOSE) { notify(c,t->token,3,t->size,t->name,"",NULL); transfer_free(t); c->tx=NULL; }
        else fail(c,&c->tx);
        return TRUE;
    }
    if (strcmp(kind,"set")) return FALSE;
    si=unique(p,SI,"si");
    if (si) {
        const char *mime=attr(si,"mime-type"),*name; size_t size;
        if (!method(p,TRUE)) return FALSE;
        n=unique(si,FILE_NS,"file"); name=attr(n,"name"); sid=attr(si,"id");
        if (g_strcmp0(attr(si,"profile"),FILE_NS) || !mime || (strcmp(mime,"image/png") && strcmp(mime,"image/jpeg")) ||
            !valid_id(sid) || !filename(name) || !number(attr(n,"size"),&size) || !size || size>BAREV_IMAGE_MAX) {
            reject(c,id,"not-acceptable"); return TRUE;
        }
        if (c->rx) { reject(c,id,"resource-constraint"); return TRUE; }
        if (!c->image_budget) { reject(c,id,"resource-constraint"); return TRUE; }
        --c->image_budget;
        t=g_new0(Transfer,1); t->token=next_token(); t->id=g_strdup(id); t->sid=g_strdup(sid); t->size=size;
        t->name=g_strdup(name); t->mime=g_strdup(mime); t->phase=CONSENT; c->rx=t;
        if (size<=(size_t)c->automatic) barev_image_wire_accept(c,t->token,TRUE);
        else if (!notify(c,t->token,1,size,name,"Receive original image over the messaging connection",NULL)) { reject(c,id,"resource-constraint"); fail(c,&c->rx); }
        return TRUE;
    }
    data=unique(p,IBB,"open");
    if (data) {
        size_t block; const char *stanza=attr(data,"stanza"); t=c->rx; sid=attr(data,"sid");
        if (!t || g_strcmp0(sid,t->sid) || t->phase!=WAIT_OPEN || (stanza && strcmp(stanza,"iq")) ||
            !number(attr(data,"block-size"),&block) || block<1 || block>16384) { reject(c,id,"unexpected-request"); return TRUE; }
        t->block=block; t->phase=RECEIVING; t->age=0; result(c,id); return TRUE;
    }
    data=unique(p,IBB,"data");
    if (data) {
        size_t seq,size=0; char *encoded; guchar *raw; t=c->rx; sid=attr(data,"sid");
        if (!t || g_strcmp0(sid,t->sid) || t->phase!=RECEIVING) { reject(c,id,"unexpected-request"); return TRUE; }
        encoded=text(data,23000); raw=encoded?decode(encoded,t->block,&size):NULL; g_free(encoded);
        if (!number(attr(data,"seq"),&seq) || seq!=t->seq || !raw || !size || size>t->size-t->done) {
            g_free(raw); reject(c,id,"bad-request"); fail(c,&c->rx); return TRUE;
        }
        memcpy(t->blob->data+t->done,raw,size); g_free(raw); t->done+=size; t->seq=(t->seq+1)%65536; t->age=0;
        result(c,id); return TRUE;
    }
    data=unique(p,IBB,"close");
    if (data) {
        t=c->rx; sid=attr(data,"sid");
        if (c->tx && !g_strcmp0(sid,c->tx->sid)) { result(c,id); fail(c,&c->tx); return TRUE; }
        if (!t || g_strcmp0(sid,t->sid)) { reject(c,id,"item-not-found"); return TRUE; }
        if (t->phase!=RECEIVING || t->done!=t->size || !identify(t->blob) || strcmp(t->blob->mime,t->mime)) {
            reject(c,id,"not-acceptable"); fail(c,&c->rx); return TRUE;
        }
        result(c,id); notify(c,t->token,2,t->size,t->name,"",t->blob); if (t->size<=BAREV_BOB_MAX) cache(c,t->blob);
        transfer_free(t); c->rx=NULL; return TRUE;
    }
    return FALSE;
}
xmlnode *barev_image_wire_packet(BarevImageWire *c) { return c?g_queue_pop_head(&c->packets):NULL; }
BarevImageEvent *barev_image_wire_event(BarevImageWire *c) { return c?g_queue_pop_head(&c->events):NULL; }
int barev_image_wire_progress(BarevImageWire *c,int token)
{ if (c && c->tx && c->tx->token==token) return c->tx->done; if (c && c->rx && c->rx->token==token) return c->rx->done; return -1; }
void barev_image_wire_cancel(BarevImageWire *c,int token)
{
    unsigned i;
    if (!c) return;
    if (c->tx && c->tx->token==token) {
        char *id=identifier("bix",next_token()); xmlnode *p=packet(id,"set"),*close=child(p,IBB,"close"); g_free(id);
        xmlnode_set_attrib(close,"sid",c->tx->sid); queue(c,p); fail(c,&c->tx);
    } else if (c->rx && c->rx->token==token) {
        if (c->rx->phase==CONSENT) reject(c,c->rx->id,"forbidden");
        else {
            char *id=identifier("bix",next_token()); xmlnode *p=packet(id,"set"),*close=child(p,IBB,"close"); g_free(id);
            xmlnode_set_attrib(close,"sid",c->rx->sid); queue(c,p);
        }
        fail(c,&c->rx);
    }
    else for (i=0;i<4;++i) if (c->pending[i] && c->pending[i]->token==token) { pending_free(c->pending[i]); c->pending[i]=NULL; }
}
void barev_image_wire_disconnect(BarevImageWire *c)
{
    xmlnode *p; unsigned i;
    if (!c) return;
    while ((p=g_queue_pop_head(&c->packets))) xmlnode_free(p);
    fail(c,&c->tx); fail(c,&c->rx);
    for (i=0;i<4;++i) if (c->pending[i]) {
        notify(c,c->pending[i]->token,4,0,"image","Messaging connection closed.",NULL);
        pending_free(c->pending[i]); c->pending[i]=NULL;
    }
}
void barev_image_wire_tick(BarevImageWire *c)
{
    unsigned i;
    if (!c) return;
    c->budget=c->image_budget=8;
    if (c->tx && (++c->tx->age>120 || !c->tx->phase)) fail(c,&c->tx);
    if (c->rx && ++c->rx->age>120) { reject(c,c->rx->id,"remote-server-timeout"); fail(c,&c->rx); }
    for (i=0;i<4;++i) if (c->pending[i] && ++c->pending[i]->age>120) {
        notify(c,c->pending[i]->token,4,0,"image","Image request timed out.",NULL); pending_free(c->pending[i]); c->pending[i]=NULL;
    }
}
void barev_image_wire_free(BarevImageWire *c)
{
    unsigned i; BarevImageEvent *e;
    if (!c) return;
    barev_image_wire_disconnect(c); while ((e=barev_image_wire_event(c))) barev_image_event_free(e);
    for (i=0;i<8;++i) release(c->cache[i]);
    g_free(c);
}
size_t barev_image_wire_memory(void) { return memory; }
