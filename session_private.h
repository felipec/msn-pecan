/**
 * Copyright (C) 2008-2009 Felipe Contreras.
 * Copyright (C) 1998-2006 Pidgin (see pidgin-copyright)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef SESSION_PRIVATE_H
#define SESSION_PRIVATE_H

#include "session.h"

#include "ab/pn_contact.h"
#include "ab/pn_contactlist.h"

#include "io/pn_node.h"

#include "pn_oim.h"
#include "pn_dp_manager.h"

struct MsnNotification;
struct MsnNexus;
struct MsnSync;
struct pn_peer_call;

typedef void (*PnXferInviteCb) (struct pn_peer_call *call,
                                const char *branch,
                                const char *context);

struct MsnSession
{
    gchar *username;
    gchar *password;

#ifdef INTERNAL_MAINLOOP
    GMainLoop *g_main_loop;
    guint g_main_loop_timer;
#endif

    void *user_data;
    struct pn_contact *user; /**< Store contact information. */

    GHashTable *config; /**< Configuration options. */

    struct pn_contact_list *contactlist;
    PecanOimSession *oim_session;
    PnDpManager *dp_manager;

    PnPermission default_permission;

    gboolean connected;
    gboolean logged_in; /** @todo move to libpurple user_data and cancel
                          operations that require us to be logged in. */

    struct MsnNotification *notification;
    struct MsnNexus *nexus;
    struct PnAuth *auth;
    struct MsnSync *sync;

    GHashTable *conversations;
    GHashTable *chats;

    GHashTable *links;
    GList *direct_conns; /**< The list of all the direct_connections. */

    struct
    {
        char *kv;
        char *sid;
        char *mspauth;
        unsigned long sl;
        int email_enabled;
        char *client_ip;
        int client_port;
        gchar *mail_url;
        gulong mail_url_timestamp;
    } passport_info;
    struct
    {
        gchar *t;
        gchar *p;
    } passport_cookie;

    /* libpurple stuff (should move to user_data) */
    guint inbox_unread_count; /* The number of unread e-mails on the inbox. */
    int conv_seq; /**< The current conversation sequence number. */

    struct
    {
        gboolean enabled;
        guint timer;
    } autoupdate_tune;

    PnXferInviteCb xfer_invite_cb;
    guint conn_count;
};

#endif /* SESSION_PRIVATE_H */
