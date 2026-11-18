/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "auth-stream.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    BarevAuth state;
    int i, action;
    if (argc < 2) return 2;
    barev_auth_init(&state, !strcmp(argv[1], "server"));
    for (i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "open")) action = barev_auth_opened(&state);
        else if (!strcmp(argv[i], "sent")) action = barev_auth_sent(&state);
        else if (!strcmp(argv[i], "secure") || !strcmp(argv[i], "bad-tls"))
            action = barev_auth_secured(&state, !strcmp(argv[i], "secure"));
        else {
            char *wrapped = g_strdup_printf("<root xmlns:stream='http://etherx.jabber.org/streams'>%s</root>", argv[i]);
            xmlnode *root = xmlnode_from_str(wrapped, -1);
            const xmlnode *item = root ? root->child : NULL;
            while (item && item->type != XMLNODE_TYPE_TAG) item = item->next;
            action = barev_auth_receive(&state, item);
            if (root) xmlnode_free(root);
            g_free(wrapped);
        }
        printf("%d %d %d %d %s\n", action, barev_auth_ready(&state), barev_auth_handshaking(&state),
            barev_auth_writing(&state), barev_auth_output(&state));
    }
    return 0;
}
