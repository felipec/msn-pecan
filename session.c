/**
 * Copyright (C) 2008-2009 Felipe Contreras
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

#include "session_private.h"
#include "pn_log.h"
#include "pn_util.h"
#include "pn_locale.h"
#include "notification.h"
#include "pn_status.h"
#include "pn_dp_manager.h"
#include "ab/pn_contact_priv.h"
#include "pn_buffer.h"

#include "cmd/cmdproc_private.h"

#if defined(PECAN_CVR)
#include "cvr/pn_peer_link.h"
#endif /* defined(PECAN_CVR) */

#include "sync.h"
#include "pn_auth.h"

#include <glib/gstdio.h>
#include <string.h>

/* libpurple stuff. */
#include <account.h>
#include <version.h>
#ifdef INTERNAL_MAINLOOP
#include <eventloop.h>
#endif

#ifdef INTERNAL_MAINLOOP
static inline gboolean
g_main_context_iteration_timer ()
{
    g_main_context_iteration (NULL, FALSE);
    return TRUE;
}
#endif

MsnSession *
msn_session_new (const gchar *username,
                 const gchar *password,
                 gboolean http_method)
{
    MsnSession *session;

    session = g_new0 (MsnSession, 1);

    session->username = pn_normalize (username);
    session->password = g_strndup (password, 16);

#ifdef INTERNAL_MAINLOOP
    session->g_main_loop = g_main_loop_new  (NULL, FALSE);
    session->g_main_loop_timer = purple_timeout_add (1000, g_main_context_iteration_timer, NULL);
#endif

    session->config = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    /** @todo sb and ns need this here but should be updated on-the-fly. */
    msn_session_set_bool (session, "use_http_method", http_method);

    session->dp_manager = pn_dp_manager_new (session);

    session->notification = msn_notification_new (session);
    pn_node_set_id(session->notification->cmdproc->conn,
                   session->conn_count++, "ns");

    session->contactlist = pn_contactlist_new (session);

    session->user = pn_contact_new (NULL);
    pn_contact_set_passport (session->user, session->username);

    session->conv_seq = 1;

    session->oim_session = pn_oim_session_new (session);

    session->conversations = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) msn_switchboard_unref);
    session->chats = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, (GDestroyNotify) msn_switchboard_unref);

#if defined(PECAN_CVR)
    session->links = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) pn_peer_link_unref);
#endif /* defined(PECAN_CVR) */

    return session;
}

void
msn_session_destroy (MsnSession *session)
{
    if (!session)
        return;

    pn_oim_session_free (session->oim_session);

    if (session->connected)
        msn_session_disconnect (session);

#if defined(PECAN_CVR)
    g_hash_table_destroy (session->links);
#endif /* defined(PECAN_CVR) */

    msn_notification_destroy (session->notification);

    pn_dp_manager_free (session->dp_manager);

    g_hash_table_destroy (session->conversations);
    g_hash_table_destroy (session->chats);

    pn_contactlist_destroy (session->contactlist);

    g_free (session->passport_info.kv);
    g_free (session->passport_info.sid);
    g_free (session->passport_info.mspauth);
    g_free (session->passport_info.client_ip);

    g_free (session->passport_info.mail_url);

    g_free (session->passport_cookie.t);
    g_free (session->passport_cookie.p);

    if (session->autoupdate_tune.timer)
        g_source_remove (session->autoupdate_tune.timer);

    if (session->sync)
        msn_sync_destroy (session->sync);

    if (session->auth)
        pn_auth_free (session->auth);

    pn_contact_free (session->user);

    g_hash_table_destroy (session->config);

    g_free (session->username);
    g_free (session->password);

#ifdef INTERNAL_MAINLOOP
    purple_timeout_remove (session->g_main_loop_timer);
    g_main_loop_unref (session->g_main_loop);
#endif

    g_free (session);
}

const gchar *
msn_session_get_username (MsnSession *session)
{
    return session->username;
}

const gchar *
msn_session_get_password (MsnSession *session)
{
    return session->password;
}

struct pn_contact *
msn_session_get_contact (MsnSession *session)
{
    g_return_val_if_fail (session, NULL);
    return session->user;
}

void
msn_session_set_user_data (MsnSession *session,
                           void *user_data)
{
    session->user_data = user_data;
}

void *
msn_session_get_user_data (MsnSession *session)
{
    return session->user_data;
}

gboolean
msn_session_connect (MsnSession *session,
                     const char *host,
                     int port)
{
    g_return_val_if_fail (session, FALSE);
    g_return_val_if_fail (!session->connected, TRUE);

    session->connected = TRUE;

    if (!session->notification)
    {
        pn_error ("this shouldn't happen");
        g_return_val_if_reached (FALSE);
    }

    if (msn_notification_connect (session->notification, host, port))
    {
        return TRUE;
    }

    return FALSE;
}

void
msn_session_disconnect (MsnSession *session)
{
    g_return_if_fail (session);
    g_return_if_fail (session->connected);

    session->connected = FALSE;

    g_hash_table_remove_all (session->conversations);
    g_hash_table_remove_all (session->chats);

    if (session->notification)
        msn_notification_close (session->notification);
}

/* TODO: This must go away when conversation is redesigned */
MsnSwitchBoard *
msn_session_find_swboard (const MsnSession *session,
                          const gchar *username)
{
    g_return_val_if_fail (session, NULL);
    g_return_val_if_fail (username, NULL);

    return g_hash_table_lookup (session->conversations, username);
}

static gboolean
find_sb_conv (gpointer key,
              gpointer value,
              gpointer user_data)
{
    MsnSwitchBoard *swboard;
    swboard = value;
    return (swboard->conv == user_data);
}

MsnSwitchBoard *
msn_session_find_swboard_with_conv (const MsnSession *session,
                                    const PurpleConversation *conv)
{
    MsnSwitchBoard *swboard;

    g_return_val_if_fail (session, NULL);
    g_return_val_if_fail (conv, NULL);

    swboard = g_hash_table_find (session->conversations, find_sb_conv, (gpointer) conv);
    if (!swboard)
        swboard = g_hash_table_find (session->chats, find_sb_conv, (gpointer) conv);

    return swboard;
}

MsnSwitchBoard *
msn_session_find_swboard_with_id (const MsnSession *session,
                                  int chat_id)
{
    g_return_val_if_fail (session, NULL);
    g_return_val_if_fail (chat_id >= 0,    NULL);

    return g_hash_table_lookup (session->chats, GINT_TO_POINTER (chat_id));
}

MsnSwitchBoard *
msn_session_get_swboard (MsnSession *session,
                         const char *username)
{
    MsnSwitchBoard *swboard;

    g_return_val_if_fail (session, NULL);

    swboard = msn_session_find_swboard (session, username);

    if (!swboard)
    {
        swboard = msn_switchboard_new(session);
        g_hash_table_insert (session->conversations, g_strdup (username), swboard);
        swboard->im_user = g_strdup(username);
        msn_switchboard_request(swboard);
        msn_switchboard_request_add_user(swboard, username);
        pn_node_set_id(swboard->cmdproc->conn, session->conn_count++, username);
    }

    return swboard;
}

void
msn_session_warning (MsnSession *session,
                     const gchar *fmt,
                     ...)
{
    PurpleAccount *account;
    PurpleConnection *connection;
    gchar *tmp;
    va_list args;

    account = msn_session_get_user_data (session);
    connection = purple_account_get_connection (account);

    va_start (args, fmt);

    tmp = g_strdup_vprintf (fmt, args);

    purple_notify_error (connection, NULL, tmp, NULL);

    g_free (tmp);

    va_end (args);
}


#if PURPLE_VERSION_CHECK(2,3,0)
static PurpleConnectionError msn_error_to_purple_reason(MsnErrorType error)
{
    switch (error) {
        case MSN_ERROR_SERVCONN:
        case MSN_ERROR_HTTP_MALFORMED:
            return PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
        case MSN_ERROR_UNSUPPORTED_PROTOCOL:
            return PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE;
        case MSN_ERROR_SIGN_OTHER:
            return PURPLE_CONNECTION_ERROR_NAME_IN_USE;
        case MSN_ERROR_AUTH:
            return PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;
        default:
            return PURPLE_CONNECTION_ERROR_OTHER_ERROR;
    }
}
#endif

void
msn_session_set_error (MsnSession *session,
                       MsnErrorType error,
                       const char *info)
{
    PurpleAccount *account;
    PurpleConnection *connection;
    char *msg;

    account = msn_session_get_user_data (session);
    connection = purple_account_get_connection (account);

    switch (error)
    {
        case MSN_ERROR_SERVCONN:
            msg = g_strdup (info);
            break;
        case MSN_ERROR_UNSUPPORTED_PROTOCOL:
            msg = g_strdup (_("Our protocol is not supported by the "
                              "server."));
            break;
        case MSN_ERROR_HTTP_MALFORMED:
            msg = g_strdup (_("Error parsing HTTP."));
            break;
        case MSN_ERROR_SIGN_OTHER:
            msg = g_strdup (_("You have signed on from another location."));
            break;
        case MSN_ERROR_SERV_UNAVAILABLE:
            msg = g_strdup (_("The MSN servers are temporarily "
                              "unavailable. Please wait and try "
                              "again."));
            break;
        case MSN_ERROR_SERV_DOWN:
            msg = g_strdup (_("The MSN servers are going down "
                              "temporarily."));
            break;
        case MSN_ERROR_AUTH:
            msg = g_strdup_printf (_("Unable to authenticate: %s"),
                                   info ? info : _("Unknown error"));
            break;
        case MSN_ERROR_BAD_BLIST:
            msg = g_strdup (_("Your MSN buddy list is temporarily "
                              "unavailable. Please wait and try "
                              "again."));
            break;
        default:
            msg = g_strdup (_("Unknown error."));
            break;
    }

    msn_session_disconnect (session);

#if PURPLE_VERSION_CHECK(2,3,0)
    purple_connection_error_reason (connection,
            msn_error_to_purple_reason(error), msg);
#else
    purple_connection_error (connection, msg);
#endif

    g_free (msg);
}

#ifdef HAVE_LIBPURPLE
/* stupid libpurple's local contact list, we don't need you! */
static void
sync_users (MsnSession *session)
{
    PurpleAccount *account;
    GSList *buddies;
    GList *to_remove = NULL;

    account = msn_session_get_user_data(session);

    for (buddies = purple_find_buddies(account, NULL); buddies;
         buddies = g_slist_delete_link(buddies, buddies))
    {
        PurpleBuddy *buddy = buddies->data;
        const gchar *buddy_name = purple_buddy_get_name(buddy);
        const gchar *group_name = purple_group_get_name(purple_buddy_get_group(buddy));
        struct pn_contact *contact;
        gboolean found = FALSE;

        contact = pn_contactlist_find_contact(session->contactlist, buddy_name);

        if (contact && contact->list_op & MSN_LIST_FL_OP) {
            struct pn_group *group;

            group = pn_contactlist_find_group_with_name(session->contactlist,
                                                        group_name);

            found = pn_contact_is_in_group(contact, group);
        }

        if (!found) {
            pn_warning("synchronization issue; buddy %s not found in group %s: removing",
                       purple_buddy_get_name(buddy), group_name);
            to_remove = g_list_prepend(to_remove, buddy);
        }
    }
    if (to_remove) {
        g_list_foreach(to_remove, (GFunc) purple_blist_remove_buddy, NULL);
        g_list_free(to_remove);
    }
}
#endif /* HAVE_LIBPURPLE */

void
msn_session_finish_login (MsnSession *session)
{
    PurpleAccount *account;
    PurpleStoredImage *img;

    if (session->logged_in)
        return;

    account = msn_session_get_user_data (session);

#ifdef HAVE_LIBPURPLE
    sync_users (session);
#endif

    img = purple_buddy_icons_find_account_icon (account);

    {
        struct pn_buffer *image;
        if (img)
            image = pn_buffer_new_memdup ((const gpointer) purple_imgstore_get_data (img),
                                             purple_imgstore_get_size (img));
        else
            image = NULL;
        pn_contact_set_buddy_icon (session->user, image);
    }

    purple_imgstore_unref (img);

    session->logged_in = TRUE;

    /** @todo move this to msn.c */
    pn_update_status (session);
    pn_update_personal_message (session);
    pn_timeout_tune_status (session);

    {
        PurpleConnection *connection;
        connection = purple_account_get_connection (account);
        purple_connection_set_state (connection, PURPLE_CONNECTED);
    }

    pn_contactlist_check_pending (session->contactlist);
}

void
msn_session_set_bool (MsnSession *session,
                      const gchar *fieldname,
                      gboolean value)
{
    g_hash_table_insert (session->config, g_strdup (fieldname), GINT_TO_POINTER (value));
}

gboolean
msn_session_get_bool (const MsnSession *session,
                      const gchar *fieldname)
{
    return GPOINTER_TO_INT (g_hash_table_lookup (session->config, fieldname));
}

void
msn_session_set_prp (MsnSession *session,
                     const char *key,
                     const char *value)
{
    MsnCmdProc *cmdproc;

    cmdproc = session->notification->cmdproc;

    if (value) {
        /*
         * We should investigate if other properties also need striping. If so,
         * then pn_friendly_name_encode should be renamed to pn_prop_encode or
         * something like that, and g_strstrip should be handled internally.
         */
        gchar *tmp = g_strdup (value);
        gchar *enc = pn_friendly_name_encode (g_strstrip (tmp));
        g_free (tmp);

        msn_cmdproc_send (cmdproc, "PRP", "%s %s", key, enc);
        g_free (enc);
    }
    else {
        msn_cmdproc_send (cmdproc, "PRP", "%s", key);
    }
}

void
msn_session_set_public_alias (MsnSession *session,
                              const gchar *value)
{
    msn_session_set_prp (session, "MFN",
                         value ? value : msn_session_get_username (session));
}
