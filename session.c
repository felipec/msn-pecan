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
#include "ab/pecan_contact_priv.h"

#if defined(PECAN_CVR)
#include "cvr/slplink.h"
#endif /* defined(PECAN_CVR) */

#include "sync.h"
#include "nexus.h"

#include <glib/gstdio.h>
#include <string.h>

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <account.h>

static void
conversation_created_cb (PurpleConversation *conv, gpointer data)
{
    gchar *str;
    const gchar *tmp_user, *friendly_name;
    MsnSession *session = data;
    PecanContact *contact;

    tmp_user = purple_conversation_get_name (conv);
    contact = pecan_contactlist_find_contact (session->contactlist, tmp_user);
    if (contact)
        friendly_name = pecan_contact_get_friendly_name (contact);
    else
        friendly_name = tmp_user;
    if (!friendly_name)
        friendly_name = tmp_user;

    if (contact && !(contact->list_op & (1 << MSN_LIST_RL)))
    {
        str = g_strdup_printf (_("You are not in %s's contact list."), friendly_name);

        purple_conversation_write (conv, NULL, str, PURPLE_MESSAGE_SYSTEM, time (NULL));

        g_free (str);
    }
}

MsnSession *
msn_session_new (const gchar *username,
                 const gchar *password,
                 gboolean http_method)
{
    MsnSession *session;

    session = g_new0 (MsnSession, 1);

    session->username = pn_normalize (username);
    session->password = g_strdup (password);

    session->config = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    /** @todo sb and ns need this here but should be updated on-the-fly. */
    msn_session_set_bool (session, "use_http_method", http_method);

#if 0
    if (session->http_method)
    {
        PecanNode *foo;
        foo = PECAN_NODE (pecan_http_server_new ("foo server"));
        foo->session = session;
        session->http_conn = foo;
    }
#endif

    session->dp_manager = pn_dp_manager_new (session);

    session->notification = msn_notification_new (session);
    session->contactlist = pecan_contactlist_new (session);

    session->user = pecan_contact_new (NULL);
    pecan_contact_set_passport (session->user, session->username);

    session->conv_seq = 1;

    session->oim_session = pn_oim_session_new (session);

    session->conversations = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) msn_switchboard_unref);
    session->chats = g_hash_table_new_full (g_int_hash, g_int_equal, NULL, (GDestroyNotify) msn_switchboard_unref);

    purple_signal_connect (purple_conversations_get_handle(), "conversation-created",
                           session, PURPLE_CALLBACK (conversation_created_cb), session);

    return session;
}

void
msn_session_destroy (MsnSession *session)
{
    if (!session)
        return;

    pn_oim_session_free (session->oim_session);

    purple_signal_disconnect (purple_conversations_get_handle(), "conversation-created",
                              session, PURPLE_CALLBACK (conversation_created_cb));

    if (session->connected)
        msn_session_disconnect (session);

    if (session->notification)
        msn_notification_destroy (session->notification);

#if defined(PECAN_CVR)
    while (session->slplinks)
        msn_slplink_destroy (session->slplinks->data);
#endif /* defined(PECAN_CVR) */

    pn_dp_manager_free (session->dp_manager);

    g_hash_table_destroy (session->conversations);
    g_hash_table_destroy (session->chats);

    pecan_contactlist_destroy (session->contactlist);

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

    if (session->nexus)
        msn_nexus_destroy (session->nexus);

    pecan_contact_free (session->user);

    g_hash_table_destroy (session->config);

    g_free (session->username);
    g_free (session->password);

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

PecanContact *
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

    if (session->http_conn)
        pecan_node_close (session->http_conn);
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

    return g_hash_table_lookup (session->conversations, GINT_TO_POINTER (chat_id));
}

MsnSwitchBoard *
msn_session_get_swboard (MsnSession *session,
                         const char *username,
                         MsnSBFlag flag)
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
    }

    swboard->flag |= flag;

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
            connection->wants_to_die = TRUE;
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
            connection->wants_to_die = TRUE;
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

    purple_connection_error (connection, msg);

    g_free (msg);
}

void
msn_session_finish_login (MsnSession *session)
{
    PurpleAccount *account;
    PurpleStoredImage *img;

    if (session->logged_in)
        return;

    account = msn_session_get_user_data (session);

    img = purple_buddy_icons_find_account_icon (account);

    {
        PecanBuffer *image;
        if (img)
            image = pecan_buffer_new_memdup ((const gpointer) purple_imgstore_get_data (img),
                                             purple_imgstore_get_size (img));
        else
            image = NULL;
        pecan_contact_set_buddy_icon (session->user, image);
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

    pecan_contactlist_check_pending (session->contactlist);
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
