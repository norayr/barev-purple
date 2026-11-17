/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "pin-ui.h"
#include <libpurple/request.h>
#include <libpurple/util.h>
#include <string.h>

typedef struct Prompt Prompt;
struct BarevPinUI {
    PurpleAccount *account;
    BarevPinBackend backend;
    unsigned refs;
    gboolean closed;
    Prompt *prompt;
};
struct Prompt {
    BarevPinUI *ui;
    unsigned refs;
    char *who;
    unsigned stage;
    char expected[65], proposed[65], old_fingerprint[72];
};

static void unref(BarevPinUI *ui) { if (!--ui->refs) g_free(ui); }
static void prompt_unref(Prompt *p)
{
    if (--p->refs) return;
    unref(p->ui); g_free(p->who); g_free(p);
}
static gboolean active(Prompt *p) { return !p->ui->closed && p->ui->prompt == p; }
static void detach(Prompt *p)
{
    if (p->ui->prompt == p) { p->ui->prompt = NULL; prompt_unref(p); }
}
static void error(BarevPinUI *ui, const char *message)
{
    if (!ui->closed) purple_notify_error(ui, "Peer identity", "Peer key was not saved", message);
}
static void cancel_input(gpointer data, const char *text)
{
    Prompt *p = data;
    (void)text; ++p->refs; detach(p); prompt_unref(p);
}
static void cancel_action(gpointer data, int choice)
{
    (void)choice; cancel_input(data, NULL);
}
static void approve(gpointer data, int choice)
{
    Prompt *p = data;
    BarevPinUI *ui = p->ui;
    int status;
    (void)choice; ++p->refs;
    if (active(p)) {
        detach(p);
        status = ui->backend.save(ui->backend.owner, p->who, p->expected, p->proposed);
        if (status == 4) error(ui, "The stored key changed while this dialog was open. Reopen Peer identity and compare the fingerprints again.");
        else if (status) error(ui, "The peer pin could not be stored. Check the profile's barev directory and restore unreadable or corrupt pin records from backup.");
        else if (!ui->closed) purple_notify_info(ui, "Peer identity", "Peer key pinned",
            "The manually selected key is saved. Identity authentication is not yet negotiated on chat connections.");
    }
    prompt_unref(p);
}
static void input(gpointer data, const char *text)
{
    Prompt *p = data;
    BarevPinUI *ui = p->ui;
    char fingerprint[72];
    char *description, *contact;
    gpointer request;
    ++p->refs;
    if (!active(p)) goto done;
    if (!text || !ui->backend.describe(ui->backend.owner, text, p->proposed, fingerprint)) {
        detach(p); error(ui, "Enter exactly 64 hexadecimal digits from the contact's Ed25519 public key, not its SHA256 fingerprint.");
        goto done;
    }
    if (!strcmp(p->expected, p->proposed)) { detach(p); goto done; }
    contact = purple_markup_escape_text(p->who, -1);
    description = g_strdup_printf("Contact: %s\n\nCurrent fingerprint: %s\nNew fingerprint: %s\n\nNew public key: %s\n\nCompare the new fingerprint through an independent trusted channel before approving. This saves a key for future authentication; chat connections do not yet prove possession of it.",
        contact, *p->expected ? p->old_fingerprint : "None", fingerprint, p->proposed);
    g_free(contact);
    p->stage = 2;
    request = purple_request_action(ui, "Peer identity",
        *p->expected ? "Replace this contact's pinned key?" : "Pin this contact's identity key?",
        description, 0, ui->account, p->who, NULL, p, 2,
        "Cancel", G_CALLBACK(cancel_action), *p->expected ? "Replace key" : "Pin key", G_CALLBACK(approve));
    g_free(description);
    if (!active(p)) { if (request) purple_request_close(PURPLE_REQUEST_ACTION, request); }
    else if (!request) detach(p);
done:
    prompt_unref(p);
}

BarevPinUI *BarevPinUI_New(PurpleAccount *account, const BarevPinBackend *backend)
{
    BarevPinUI *ui = g_new0(BarevPinUI, 1);
    ui->account = account; ui->backend = *backend; ui->refs = 1;
    return ui;
}
void BarevPinUI_Close(BarevPinUI *ui)
{
    if (!ui || ui->closed) return;
    ui->closed = TRUE;
    purple_request_close_with_handle(ui); purple_notify_close_with_handle(ui);
    if (ui->prompt) detach(ui->prompt);
    unref(ui);
}
void BarevPinUI_Open(BarevPinUI *ui, const char *who)
{
    Prompt *p;
    int status;
    char *description, *contact;
    gpointer request;
    if (!ui || ui->closed || !who || ui->prompt) return;
    ++ui->refs;
    p = g_new0(Prompt, 1); p->ui = ui; p->refs = 1; p->who = g_strdup(who);
    status = ui->backend.load(ui->backend.owner, who, p->expected, p->old_fingerprint);
    if (status != 0 && status != 1) {
        error(ui, "The stored pin is unreadable or corrupt, or this contact has no complete Barev address. Restore the pin from backup or correct the contact address before proceeding.");
        prompt_unref(p); return;
    }
    if (ui->closed) { prompt_unref(p); return; }
    ui->prompt = p; ++p->refs;
    contact = purple_markup_escape_text(who, -1);
    description = g_strdup_printf("Contact: %s\nCurrent fingerprint: %s\n\nPaste the contact's 64-digit Ed25519 public key. A fingerprint alone cannot be used as a public key.",
        contact, *p->expected ? p->old_fingerprint : "None");
    g_free(contact);
    p->stage = 1;
    request = purple_request_input(ui, "Peer identity", "Manually pin a contact's identity key", description,
        p->expected, FALSE, FALSE, NULL, "Continue", G_CALLBACK(input), "Cancel", G_CALLBACK(cancel_input),
        ui->account, who, NULL, p);
    g_free(description);
    if (!active(p) || p->stage != 1) { if (request) purple_request_close(PURPLE_REQUEST_INPUT, request); }
    else if (!request) detach(p);
    prompt_unref(p);
}
void BarevPinUI_Info(BarevPinUI *ui, const char *who, PurpleNotifyUserInfo *info)
{
    char key[65], fingerprint[72];
    int status;
    if (!ui || ui->closed) return;
    ++ui->refs;
    status = ui->backend.load(ui->backend.owner, who, key, fingerprint);
    if (status == 0) {
        purple_notify_user_info_add_pair_plaintext(info, "Pinned Ed25519 public key", key);
        purple_notify_user_info_add_pair_plaintext(info, "Pinned identity fingerprint", fingerprint);
    }
    purple_notify_user_info_add_pair_plaintext(info, "Peer key pin",
        status == 0 ? "Manually pinned" : status == 1 ? "No pinned key" : "Pin unavailable or invalid");
    purple_notify_user_info_add_pair_plaintext(info, "Chat authentication",
        "Identity authentication is not yet negotiated on chat connections.");
    unref(ui);
}
