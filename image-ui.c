/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "image-ui.h"
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <glib/gstdio.h>
#include <libpurple/connection.h>
#include <libpurple/conversation.h>
#include <libpurple/ft.h>
#include <libpurple/imgstore.h>
#include <libpurple/notify.h>
#include <libpurple/request.h>
#include <libpurple/server.h>
#include <libpurple/util.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define MAX_IMAGE (16u*1024*1024)
#define MAX_PIXELS (16u*1024*1024)
#define FIT_BYTES (256u*1024)
typedef struct Sending Sending;
typedef struct Receiving Receiving;
struct BarevImageUI { PurpleAccount *account; BarevImageBackend backend; GList *sending, *receiving;
    unsigned refs; gboolean closed; };
struct Sending { BarevImageUI *ui; char *who, *name; guchar *bytes; size_t size; GdkPixbuf *fit; void *request; unsigned refs; };
struct Receiving { BarevImageUI *ui; PurpleXfer *xfer; char *who; int token; };

static void ref(BarevImageUI *ui) { ++ui->refs; }
static void unref(BarevImageUI *ui) { if (!--ui->refs) g_free(ui); }
static void notice(BarevImageUI *ui, const char *who, const char *text)
{
    PurpleConversation *conv;
    if (ui->closed) return;
    conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, ui->account, who);
    purple_conversation_write(conv, NULL, text, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time(NULL));
}

typedef struct { int edge, width, height; gboolean reject; } Dimensions;
static void dimensions(GdkPixbufLoader *loader, int width, int height, gpointer data)
{
    Dimensions *d = data;
    d->width = width; d->height = height;
    if (width < 1 || height < 1 || width > 8192 || height > 8192 || (guint)width > MAX_PIXELS/(guint)height) {
        d->reject = TRUE; gdk_pixbuf_loader_set_size(loader, 1, 1);
    } else if (MAX(width, height) > d->edge) {
        double ratio = (double)d->edge/MAX(width, height);
        gdk_pixbuf_loader_set_size(loader, MAX(1, (int)(width*ratio)), MAX(1, (int)(height*ratio)));
    }
}

static GdkPixbuf *decode(const guchar *bytes, size_t size, Dimensions *d)
{
    const char *type = NULL;
    GdkPixbufLoader *loader;
    GdkPixbuf *pixbuf = NULL;
    GError *error = NULL;
    gboolean okay = TRUE;
    size_t at;
    if (!bytes || !size || size > MAX_IMAGE) return NULL;
    if (size >= 8 && !memcmp(bytes, "\x89PNG\r\n\x1a\n", 8)) type = "png";
    else if (size >= 3 && bytes[0] == 255 && bytes[1] == 216 && bytes[2] == 255) type = "jpeg";
    if (!type) return NULL;
    if (!strcmp(type, "png")) {
        size_t offset = 8;
        while (offset+12 <= size) {
            guint32 count = ((guint32)bytes[offset]<<24) | ((guint32)bytes[offset+1]<<16) |
                ((guint32)bytes[offset+2]<<8) | bytes[offset+3];
            if (count > size-offset-12 || !memcmp(bytes+offset+4, "acTL", 4)) return NULL;
            offset += count+12;
        }
        if (offset != size) return NULL;
    }
    loader = gdk_pixbuf_loader_new_with_type(type, &error);
    if (!loader) { g_clear_error(&error); return NULL; }
    g_signal_connect(loader, "size-prepared", G_CALLBACK(dimensions), d);
    for (at = 0; at < size && okay && !d->reject; at += 4096)
        okay = gdk_pixbuf_loader_write(loader, bytes+at, MIN((size_t)4096, size-at), &error);
    if (!gdk_pixbuf_loader_close(loader, error ? NULL : &error)) okay = FALSE;
    if (okay && !d->reject && d->width && d->height) {
        pixbuf = gdk_pixbuf_loader_get_pixbuf(loader);
        if (pixbuf) g_object_ref(pixbuf);
    }
    g_clear_error(&error); g_object_unref(loader); return pixbuf;
}

static gboolean encode_fit(GdkPixbuf *source, guchar **bytes, size_t *size)
{
    GdkPixbuf *pixbuf = g_object_ref(source);
    gboolean okay = FALSE;
    unsigned pass;
    for (pass = 0; pass < 8; ++pass) {
        gchar *buffer = NULL;
        gsize length = 0;
        GdkPixbuf *smaller;
        if (gdk_pixbuf_get_has_alpha(pixbuf))
            okay = gdk_pixbuf_save_to_buffer(pixbuf, &buffer, &length, "png", NULL, NULL);
        else okay = gdk_pixbuf_save_to_buffer(pixbuf, &buffer, &length, "jpeg", NULL, "quality", "85", NULL);
        if (okay && length <= FIT_BYTES) { *bytes = (guchar *)buffer; *size = length; break; }
        g_free(buffer); okay = FALSE;
        smaller = gdk_pixbuf_scale_simple(pixbuf, MAX(1, gdk_pixbuf_get_width(pixbuf)/2),
            MAX(1, gdk_pixbuf_get_height(pixbuf)/2), GDK_INTERP_BILINEAR);
        g_object_unref(pixbuf); pixbuf = smaller; if (!pixbuf) break;
    }
    if (pixbuf) g_object_unref(pixbuf);
    return okay;
}

static void sending_unref(Sending *s)
{
    BarevImageUI *ui = s->ui;
    if (--s->refs) return;
    g_free(s->who); g_free(s->name); g_free(s->bytes); g_object_unref(s->fit); g_free(s); unref(ui);
}
static void sending_free(Sending *s)
{ s->ui->sending = g_list_remove(s->ui->sending, s); sending_unref(s); }
static void send_choice(gpointer data, int choice)
{
    Sending *s = data;
    BarevImageUI *ui = s->ui;
    guchar *bytes = NULL; size_t size = 0;
    ui->sending = g_list_remove(ui->sending, s);
    if (!ui->closed && choice != 2) {
        gboolean okay = choice == 1 || encode_fit(s->fit, &bytes, &size);
        if (!okay || !ui->backend.send(ui->backend.owner, s->who,
            choice == 1 ? s->bytes : bytes, choice == 1 ? s->size : size,
            choice == 1 ? s->name : (gdk_pixbuf_get_has_alpha(s->fit) ? "image.png" : "image.jpg")))
            notice(ui, s->who, "Image could not be sent. Connect the contact and check image limits; older peers may require Send File.");
    } else if (!ui->closed) notice(ui, s->who, "Image sending cancelled.");
    g_free(bytes); sending_free(s);
}

BarevImageUI *BarevImageUI_New(PurpleAccount *account, const BarevImageBackend *backend)
{
    BarevImageUI *ui = g_new0(BarevImageUI, 1); ui->account = account; ui->backend = *backend; ui->refs = 1; return ui;
}

char *BarevImageUI_Strip(const char *markup)
{
    const char *at = markup, *start, *end;
    GData *attributes;
    GString *text = g_string_new(NULL);
    while (purple_markup_find_tag("img", at, &start, &end, &attributes)) {
        g_string_append_len(text, at, start-at); g_datalist_clear(&attributes); at = end+1;
    }
    g_string_append(text, at); return g_string_free(text, FALSE);
}

int BarevImageUI_Send(BarevImageUI *ui, const char *who, const char *markup, char **stripped)
{
    const char *at = markup, *start, *end;
    GData *attributes;
    GList *requests = NULL, *it;
    int count = 0, result = 0;
    *stripped = NULL;
    if (!ui || ui->closed) return -ENOTCONN;
    ref(ui);
    while (purple_markup_find_tag("img", at, &start, &end, &attributes)) {
        const char *value = g_datalist_get_data(&attributes, "id");
        char *tail = NULL;
        gint64 id = value ? g_ascii_strtoll(value, &tail, 10) : 0;
        PurpleStoredImage *image = id > 0 && id <= G_MAXINT && tail && !*tail ? purple_imgstore_find_by_id(id) : NULL;
        Sending *s = NULL;
        Dimensions d = {.edge = 1280};
        size_t size = image ? purple_imgstore_get_size(image) : 0;
        if (++count <= 4 && size && size <= MAX_IMAGE && g_list_length(ui->sending)+count <= 4) {
            GdkPixbuf *fit = decode(purple_imgstore_get_data(image), size, &d);
            if (fit) {
                const char *filename = purple_imgstore_get_filename(image);
                s = g_new0(Sending, 1); s->refs = 1; s->ui = ui; ref(ui); s->who = g_strdup(who);
                s->name = filename ? g_path_get_basename(filename) : g_strdup("image.png");
                s->size = size; s->bytes = g_malloc(size); memcpy(s->bytes, purple_imgstore_get_data(image), size); s->fit = fit;
                requests = g_list_append(requests, s);
            }
        }
        g_datalist_clear(&attributes);
        if (!s) { result = -EINVAL; break; }
        at = end+1;
    }
    if (!count) { unref(ui); return 0; }
    if (result < 0) {
        for (it = requests; it; it = it->next) sending_free(it->data);
        g_list_free(requests); notice(ui, who, "Send Image accepts up to four static PNG/JPEG images, each at most 16 MiB and 16 megapixels. Use Send File for other files.");
        unref(ui); return result;
    }
    *stripped = BarevImageUI_Strip(markup);
    for (it = requests; it; it = it->next) {
        Sending *s = it->data;
        if (ui->closed) { sending_free(s); continue; }
        const char *mode = purple_account_get_string(ui->account, "image_send_mode", "ask");
        int threshold = CLAMP(purple_account_get_int(ui->account, "image_resize_kib", 256), 16, 16384);
        ui->sending = g_list_prepend(ui->sending, s);
        if (ui->closed) sending_free(s);
        else if (s->size <= (size_t)threshold*1024 && gdk_pixbuf_get_width(s->fit) < 1280 && gdk_pixbuf_get_height(s->fit) < 1280)
            send_choice(s, 1);
        else if (!strcmp(mode, "fit")) send_choice(s, 0);
        else if (!strcmp(mode, "original")) send_choice(s, 1);
        else {
            char *description = g_strdup_printf("Original: %.1f KiB. Fit for chat resizes a copy to at most 1280 pixels and 256 KiB; your original file is unchanged.", s->size/1024.0);
            void *request;
            ++s->refs;
            request = purple_request_action(ui, "Send image", "Resize this image or send the original?", description,
                    0, ui->account, who, NULL, s, 3, "Fit for chat", G_CALLBACK(send_choice),
                    "Send original", G_CALLBACK(send_choice), "Cancel", G_CALLBACK(send_choice));
            if (g_list_find(ui->sending, s)) {
                s->request = request;
                if (!request) sending_free(s);
            } else if (request) purple_request_close(PURPLE_REQUEST_ACTION, request);
            sending_unref(s);
            g_free(description);
        }
    }
    g_list_free(requests); unref(ui); return 1;
}

static gboolean same_peer(BarevImageUI *ui, const char *left, const char *right)
{
    char *key = g_strdup(purple_normalize(ui->account, left));
    gboolean equal = !g_strcmp0(key, purple_normalize(ui->account, right));
    g_free(key); return equal;
}

static Receiving *find(BarevImageUI *ui, const char *who, int token)
{
    GList *it;
    for (it = ui->receiving; it; it = it->next) {
        Receiving *r = it->data; if (r->token == token && same_peer(ui, r->who, who)) return r;
    }
    return NULL;
}
static void detach(Receiving *r)
{
    r->ui->receiving = g_list_remove(r->ui->receiving, r); r->xfer->data = NULL;
    purple_xfer_set_init_fnc(r->xfer, NULL); purple_xfer_set_request_denied_fnc(r->xfer, NULL);
    purple_xfer_set_cancel_recv_fnc(r->xfer, NULL);
    purple_xfer_set_cancel_send_fnc(r->xfer, NULL);
}
static void receiving_free(Receiving *r)
{ purple_xfer_unref(r->xfer); g_free(r->who); unref(r->ui); g_free(r); }
static void cancelled(PurpleXfer *xfer)
{
    Receiving *r = xfer->data;
    if (r) {
        BarevImageUI *ui = r->ui;
        detach(r);
        if (!ui->closed) ui->backend.cancel(ui->backend.owner, r->who, r->token);
        receiving_free(r);
    }
}
static void accepted(PurpleXfer *xfer)
{
    Receiving *r = xfer->data;
    BarevImageUI *ui;
    char *who; int token;
    if (!r) return;
    ui = r->ui; ref(ui); who = g_strdup(r->who); token = r->token;
    purple_xfer_ref(xfer);
    purple_xfer_start(xfer, -1, NULL, 0);
    if (!ui->closed && !purple_xfer_is_canceled(xfer) && !ui->backend.accept(ui->backend.owner, who, token, TRUE)) {
        r = find(ui, who, token);
        if (r) { detach(r); purple_xfer_cancel_remote(xfer); receiving_free(r); }
    }
    purple_xfer_unref(xfer); g_free(who); unref(ui);
}

void BarevImageUI_Event(BarevImageUI *ui, const char *who, int token, int kind, size_t size,
                       const char *name, const char *caption, const guchar *bytes, size_t length)
{
    Receiving *r;
    if (!ui || ui->closed) return;
    ref(ui); r = find(ui, who, token);
    if ((kind == 1 || kind == 5) && !r) {
        r = g_new0(Receiving, 1); r->ui = ui; ref(ui); r->who = g_strdup(who); r->token = token;
        r->xfer = purple_xfer_new(ui->account, kind == 5 ? PURPLE_XFER_SEND : PURPLE_XFER_RECEIVE, who); purple_xfer_ref(r->xfer);
        if (ui->closed) {
            purple_xfer_cancel_remote(r->xfer); receiving_free(r); unref(ui); return;
        }
        r->xfer->data = r; ui->receiving = g_list_prepend(ui->receiving, r);
        purple_xfer_set_filename(r->xfer, name); purple_xfer_set_size(r->xfer, size);
        purple_xfer_set_message(r->xfer, caption);
        if (kind == 5) {
            /* The protocol backend owns the in-memory source and in-band I/O. */
            purple_xfer_set_local_filename(r->xfer, name);
            r->xfer->status = PURPLE_XFER_STATUS_STARTED; r->xfer->start_time = time(NULL);
            purple_xfer_set_cancel_send_fnc(r->xfer, cancelled); purple_xfer_add(r->xfer);
        } else {
            purple_xfer_set_init_fnc(r->xfer, accepted); purple_xfer_set_request_denied_fnc(r->xfer, cancelled);
            purple_xfer_set_cancel_recv_fnc(r->xfer, cancelled); purple_xfer_request(r->xfer);
        }
    } else if (kind == 2) {
        Dimensions d = {.edge = 640}; GdkPixbuf *pixbuf = decode(bytes, length, &d);
        if (r) {
            PurpleXfer *xfer = r->xfer;
            gboolean okay;
            detach(r);
            purple_xfer_set_size(xfer, length); purple_xfer_set_bytes_sent(xfer, 0);
            okay = pixbuf && purple_xfer_write_file(xfer, bytes, length) && !purple_xfer_is_canceled(xfer);
            if (okay && xfer->dest_fp && fflush(xfer->dest_fp)) okay = FALSE;
            if (okay) {
                purple_xfer_set_size(xfer, length); purple_xfer_set_bytes_sent(xfer, length);
                purple_xfer_update_progress(xfer); purple_xfer_set_completed(xfer, TRUE); purple_xfer_end(xfer);
            } else {
                if (!purple_xfer_is_canceled(xfer)) purple_xfer_cancel_remote(xfer);
                if (pixbuf) { g_object_unref(pixbuf); pixbuf = NULL; }
            }
            receiving_free(r);
        }
        if (pixbuf && !ui->closed) {
            gchar *preview = NULL; gsize preview_size = 0;
            if (gdk_pixbuf_save_to_buffer(pixbuf, &preview, &preview_size, "png", NULL, NULL)) {
                int id = purple_imgstore_add_with_id(preview, preview_size, "preview.png");
                if (id) {
                    char *markup = g_strdup_printf("%s%s<img id=\"%d\" alt=\"Image\"/>", caption ? caption : "", caption && *caption ? "<br/>" : "", id);
                    serv_got_im(purple_account_get_connection(ui->account), who, markup,
                                PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_IMAGES, time(NULL));
                    g_free(markup); purple_imgstore_unref_by_id(id);
                } else g_free(preview);
            }
        } else if (!ui->closed) notice(ui, who, "Received image could not be decoded safely.");
        if (pixbuf) g_object_unref(pixbuf);
    } else if (kind == 3 && r) {
        PurpleXfer *xfer = r->xfer;
        detach(r); purple_xfer_set_bytes_sent(xfer, size); purple_xfer_set_completed(xfer, TRUE); purple_xfer_end(xfer);
        receiving_free(r);
    } else if (kind == 4) {
        if (r) { PurpleXfer *xfer = r->xfer; detach(r); purple_xfer_cancel_remote(xfer); receiving_free(r); }
        notice(ui, who, caption && *caption ? caption : "Image transfer failed.");
    }
    unref(ui);
}

void BarevImageUI_Progress(BarevImageUI *ui, const char *who, int token, size_t done)
{
    Receiving *r = ui && !ui->closed ? find(ui, who, token) : NULL;
    if (r && purple_xfer_get_status(r->xfer) == PURPLE_XFER_STATUS_STARTED) {
        purple_xfer_set_bytes_sent(r->xfer, done); purple_xfer_update_progress(r->xfer);
    }
}

void BarevImageUI_Close(BarevImageUI *ui)
{
    if (!ui || ui->closed) return;
    ui->closed = TRUE; purple_request_close_with_handle(ui);
    while (ui->sending) sending_free(ui->sending->data);
    while (ui->receiving) {
        Receiving *r = ui->receiving->data; PurpleXfer *xfer = r->xfer;
        detach(r); purple_xfer_cancel_remote(xfer); receiving_free(r);
    }
    unref(ui);
}

void BarevImageUI_Update(BarevImageUI *ui)
{
    GList *it, *copy = NULL;
    if (!ui || ui->closed || !ui->backend.progress) return;
    ref(ui);
    for (it = ui->receiving; it; it = it->next) {
        Receiving *r = it->data, *snapshot = g_new0(Receiving, 1);
        snapshot->who = g_strdup(r->who); snapshot->token = r->token; copy = g_list_prepend(copy, snapshot);
    }
    for (it = copy; it; it = it->next) {
        Receiving *r = it->data;
        if (!ui->closed) {
            int done = ui->backend.progress(ui->backend.owner, r->who, r->token);
            if (done >= 0) BarevImageUI_Progress(ui, r->who, r->token, done);
        }
        g_free(r->who); g_free(r);
    }
    g_list_free(copy); unref(ui);
}

GList *BarevImageUI_Options(GList *options)
{
    options = g_list_append(options, purple_account_option_string_new("Large images: ask, fit, or original", "image_send_mode", "ask"));
    options = g_list_append(options, purple_account_option_int_new("Offer image resizing above (KiB)", "image_resize_kib", 256));
    options = g_list_append(options, purple_account_option_int_new("Automatically accept images up to (KiB; 0: ask)", "image_auto_kib", 256));
    return g_list_append(options, purple_account_option_int_new("Use BoB for images up to (KiB; maximum 256)", "image_bob_kib", 64));
}

void BarevImageUI_Forget(BarevImageUI *ui, const char *who)
{
    GList *it;
    if (!ui || ui->closed) return;
    ref(ui);
    for (;;) {
        Receiving *r = NULL;
        for (it = ui->receiving; it; it = it->next) if (same_peer(ui, ((Receiving *)it->data)->who, who)) { r = it->data; break; }
        if (!r) break;
        detach(r); purple_xfer_cancel_remote(r->xfer); receiving_free(r);
    }
    for (;;) {
        Sending *s = NULL;
        for (it = ui->sending; it; it = it->next) if (same_peer(ui, ((Sending *)it->data)->who, who)) { s = it->data; break; }
        if (!s) break;
        ui->sending = g_list_remove(ui->sending, s);
        if (s->request) purple_request_close(PURPLE_REQUEST_ACTION, s->request);
        sending_free(s);
    }
    unref(ui);
}

void BarevImageUI_FileCompleted(BarevImageUI *ui, PurpleXfer *xfer)
{
    FILE *file;
    long size;
    guchar *bytes;
    const char *path;
    if (!ui || ui->closed || purple_xfer_get_type(xfer) != PURPLE_XFER_RECEIVE || !purple_xfer_is_completed(xfer) ||
        purple_xfer_get_size(xfer) > MAX_IMAGE || !(path = purple_xfer_get_local_filename(xfer))) return;
    if (xfer->dest_fp && fflush(xfer->dest_fp)) return;
    file = g_fopen(path, "rb"); if (!file) return;
    if (fseek(file, 0, SEEK_END) || (size = ftell(file)) <= 0 || size > MAX_IMAGE || fseek(file, 0, SEEK_SET)) { fclose(file); return; }
    bytes = g_malloc(size);
    if (fread(bytes, 1, size, file) == (size_t)size &&
        ((size >= 8 && !memcmp(bytes, "\x89PNG\r\n\x1a\n", 8)) || (size >= 3 && bytes[0] == 255 && bytes[1] == 216 && bytes[2] == 255)))
        BarevImageUI_Event(ui, purple_xfer_get_remote_user(xfer), 0, 2, size, "image", "", bytes, size);
    fclose(file); g_free(bytes);
}
