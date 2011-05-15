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

#include "session.h"
#include "switchboard.h"
#include "notification.h"

#include "pn_util.h"
#include "pn_log.h"
#include "pn_locale.h"

#if defined(PECAN_CVR)
#include "cvr/pn_peer_link.h"
#include "cvr/pn_peer_call.h"
#include "cvr/pn_peer_call_priv.h"
#endif /* defined(PECAN_CVR) */

#if defined(PECAN_LIBSIREN)
#include "pn_siren7.h"
#endif /* defined(PECAN_LIBSIREN) */

#if defined(PECAN_LIBMSPACK)
#include "ext/libmspack/mspack.h"
#include "ext/swfobject.h"
#include <glib/gprintf.h>
#endif /* defined(PECAN_LIBMSPACK) */

#include "session_private.h"

#include "cmd/cmdproc_private.h"
#include "cmd/transaction_private.h"
#include "cmd/msg_private.h"
#include "cmd/command_private.h"
#include "cmd/table.h"

#include "io/pn_node_private.h"
#include "io/pn_cmd_server.h"
#include "io/pn_http_server.h"

#include <string.h>

/* libpurple stuff. */
#include <account.h>
#include <prefs.h>
#include <version.h>
#include "fix_purple.h" /* for purple_buddy_set_public_alias */

static MsnTable *cbs_table;

static void
ans_usr_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error);

static void
msg_error_helper(MsnCmdProc *cmdproc, MsnMessage *msg, MsnMsgErrorType error);

static void
open_cb (PnNode *conn,
         MsnSwitchBoard *swboard)
{
    MsnSession *session;
    MsnCmdProc *cmdproc;

    g_return_if_fail (conn != NULL);

    session = swboard->session;
    cmdproc = g_object_get_data(G_OBJECT(conn), "cmdproc");

    {
        MsnTransaction *trans;

        if (msn_switchboard_is_invited (swboard))
        {
            swboard->empty = FALSE;

            trans = msn_transaction_new (cmdproc, "ANS", "%s %s %s",
                                         msn_session_get_username (session),
                                         swboard->auth_key, swboard->session_id);
        }
        else
        {
            trans = msn_transaction_new (cmdproc, "USR", "%s %s",
                                         msn_session_get_username (session),
                                         swboard->auth_key);
        }

        msn_transaction_set_error_cb (trans, ans_usr_error);
        msn_transaction_set_data (trans, swboard);
        msn_cmdproc_send_trans (cmdproc, trans);
    }
}

static void
close_cb (PnNode *conn,
          MsnSwitchBoard *swboard)
{
    g_return_if_fail (swboard);

    if (conn->error)
    {
        const char *reason = NULL;

        reason = conn->error->message;

        pn_error ("connection error: (SB):reason=[%s]", reason);

        g_clear_error (&conn->error);
    }
    else
    {
        pn_error ("connection error: (SB)");
    }

    swboard->error = MSN_SB_ERROR_CONNECTION;
    msn_switchboard_close (swboard);
}

static gboolean
timeout (gpointer data)
{
    MsnSwitchBoard *swboard = data;
    msn_switchboard_close (swboard);

    return FALSE;
}

/**************************************************************************
 * Main
 **************************************************************************/

MsnSwitchBoard *
msn_switchboard_new(MsnSession *session)
{
    MsnSwitchBoard *swboard;

    g_return_val_if_fail(session != NULL, NULL);

    swboard = g_new0(MsnSwitchBoard, 1);

    swboard->session = session;

    swboard->msg_queue = g_queue_new();
    swboard->invites = g_queue_new();
    swboard->empty = TRUE;

    {
        PnNode *conn;
        swboard->conn = pn_cmd_server_new (PN_NODE_SB);
        conn = PN_NODE (swboard->conn);

        {
            MsnCmdProc *cmdproc;
            cmdproc = g_object_get_data(G_OBJECT(swboard->conn), "cmdproc");
            cmdproc->session = session;
            cmdproc->cbs_table = cbs_table;
            cmdproc->conn = conn;
            cmdproc->data = swboard;

            swboard->cmdproc = cmdproc;
        }

        conn->session = session;

        if (msn_session_get_bool (session, "use_http_method"))
        {
            /* Each node has it's own http connection. */
            PnNode *http;

            http = PN_NODE (pn_http_server_new ("http gateway (sb)"));
            http->session = session;
            pn_node_link (conn, http);
            g_object_unref (http);
        }

        swboard->open_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), swboard);
        swboard->close_handler = g_signal_connect (conn, "close", G_CALLBACK (close_cb), swboard);
        swboard->error_handler = g_signal_connect (conn, "error", G_CALLBACK (close_cb), swboard);
    }

    swboard->timer = pn_timer_new(timeout, swboard);
    swboard->ref_count++;

    return swboard;
}

static void
msn_switchboard_free (MsnSwitchBoard *swboard)
{
    MsnMessage *msg;
    GList *l;

    pn_log ("begin");

    pn_log ("swboard=%p", swboard);

    g_return_if_fail(swboard);

    pn_timer_free(swboard->timer);

    g_signal_handler_disconnect (swboard->conn, swboard->open_handler);
    g_signal_handler_disconnect (swboard->conn, swboard->close_handler);
    g_signal_handler_disconnect (swboard->conn, swboard->error_handler);

#if defined(PECAN_CVR)
    for (l = swboard->calls; l; l = l->next) {
        struct pn_peer_call *call = l->data;
        call->swboard = NULL;
        pn_peer_call_unref(call);
    }
    g_list_free(swboard->calls);
#endif /* defined(PECAN_CVR) */

    {
        gchar *participant;
        while ((participant = g_queue_pop_tail (swboard->invites)))
            g_free (participant);
    }

    g_queue_free (swboard->invites);

    /* Destroy the message queue */
    while ((msg = g_queue_pop_head(swboard->msg_queue)) != NULL)
    {
        if (swboard->error != MSN_SB_ERROR_NONE)
        {
            /* The messages could not be sent due to a switchboard error */
            msg_error_helper(swboard->cmdproc, msg,
                             MSN_MSG_ERROR_SB);
        }
        msn_message_unref(msg);
    }

    g_queue_free(swboard->msg_queue);

    /* msg_error_helper will both remove the msg from ack_list and
       unref it, so we don't need to do either here */
    while ((l = swboard->ack_list))
        msg_error_helper(swboard->cmdproc, l->data, MSN_MSG_ERROR_SB);

    g_free(swboard->im_user);
    g_free(swboard->auth_key);
    g_free(swboard->session_id);

    for (l = swboard->users; l; l = l->next)
        g_free(l->data);

    g_list_free(swboard->users);

    if (swboard->cmdproc)
        swboard->cmdproc->data = NULL;

    /* make sure all the transactions are destroyed so no timeouts occur after
     * the switchboard is destroyed; the node can still be refed by someone
     * else. */
    pn_node_close (PN_NODE (swboard->conn));

    pn_node_free (PN_NODE (swboard->conn));

    g_free(swboard);

    pn_log ("end");
}

MsnSwitchBoard *
msn_switchboard_ref (MsnSwitchBoard *swboard)
{
    swboard->ref_count++;

    return swboard;
}

MsnSwitchBoard *
msn_switchboard_unref (MsnSwitchBoard *swboard)
{
    swboard->ref_count--;

    if (swboard->ref_count == 0)
    {
        msn_switchboard_free (swboard);
        return NULL;
    }

    return swboard;
}

void
msn_switchboard_set_auth_key(MsnSwitchBoard *swboard, const char *key)
{
    g_return_if_fail(swboard);
    g_return_if_fail(key != NULL);

    swboard->auth_key = g_strdup(key);
}

const char *
msn_switchboard_get_auth_key(MsnSwitchBoard *swboard)
{
    g_return_val_if_fail(swboard, NULL);

    return swboard->auth_key;
}

void
msn_switchboard_set_session_id(MsnSwitchBoard *swboard, const char *id)
{
    g_return_if_fail(swboard);
    g_return_if_fail(id != NULL);

    if (swboard->session_id != NULL)
        g_free(swboard->session_id);

    swboard->session_id = g_strdup(id);
}

const char *
msn_switchboard_get_session_id(MsnSwitchBoard *swboard)
{
    g_return_val_if_fail(swboard, NULL);

    return swboard->session_id;
}

void
msn_switchboard_set_invited(MsnSwitchBoard *swboard, gboolean invited)
{
    g_return_if_fail(swboard);

    swboard->invited = invited;
}

gboolean
msn_switchboard_is_invited(MsnSwitchBoard *swboard)
{
    g_return_val_if_fail(swboard, FALSE);

    return swboard->invited;
}

/**************************************************************************
 * Utility
 **************************************************************************/

static void
send_clientcaps(MsnSwitchBoard *swboard)
{
    MsnMessage *msg;
    static char *client_info = "Client-Name: msn-pecan/" VERSION "\r\n" \
                                "Chat-Logging: Y\r\n";

    msg = msn_message_new(MSN_MSG_CAPS);
    msn_message_set_content_type(msg, "text/x-clientcaps");
    msn_message_set_flag(msg, 'U');
    msn_message_set_bin_data(msg, client_info, strlen(client_info));

    msn_switchboard_send_msg(swboard, msg, TRUE);

    msn_message_unref(msg);
}

static void
msn_switchboard_add_user(MsnSwitchBoard *swboard, const char *user)
{
    PurpleAccount *account;

    g_return_if_fail(swboard);

    account = msn_session_get_user_data (swboard->session);

    swboard->users = g_list_prepend(swboard->users, g_strdup(user));
    swboard->current_users++;
    swboard->empty = FALSE;

#ifdef PECAN_DEBUG_CHAT
    pn_info ("user=[%s],total=%d",
              user, swboard->current_users);
#endif

    if ((swboard->conv != NULL) &&
        (purple_conversation_get_type(swboard->conv) == PURPLE_CONV_TYPE_CHAT))
    {
        purple_conv_chat_add_user(PURPLE_CONV_CHAT(swboard->conv), user, NULL,
                                  PURPLE_CBFLAGS_NONE, TRUE);
    }
    else if (swboard->current_users > 1 || swboard->total_users > 1)
    {
        if (swboard->conv == NULL ||
            purple_conversation_get_type(swboard->conv) != PURPLE_CONV_TYPE_CHAT)
        {
            GList *l;

#ifdef PECAN_DEBUG_CHAT
            pn_info ("switching to chat");
#endif

            /* the switchboard is handled as a conversation, make it a chat */
            if (!swboard->chat_id) {
                MsnSession *session = swboard->session;

                swboard->chat_id = session->conv_seq++;

                g_hash_table_insert(session->chats, GINT_TO_POINTER(swboard->chat_id),
                                    msn_switchboard_ref(swboard));
                g_hash_table_remove(session->conversations, swboard->im_user);

                g_free(swboard->im_user);
                swboard->im_user = NULL;

                /* we should not leave chats on timeouts */
                pn_timer_free(swboard->timer);
                swboard->timer = NULL;

                if (swboard->conv)
                    purple_conversation_destroy(swboard->conv);
            }

            swboard->conv = serv_got_joined_chat(purple_account_get_connection (account),
                                                 swboard->chat_id,
                                                 "MSN Chat");

            for (l = swboard->users; l != NULL; l = l->next)
            {
                const char *tmp_user;

                tmp_user = l->data;

#ifdef PECAN_DEBUG_CHAT
                pn_info ("adding: tmp_user=[%s]", tmp_user);
#endif

                purple_conv_chat_add_user(PURPLE_CONV_CHAT(swboard->conv),
                                          tmp_user, NULL, PURPLE_CBFLAGS_NONE, TRUE);
            }

#ifdef PECAN_DEBUG_CHAT
            pn_info ("add ourselves");
#endif

            purple_conv_chat_add_user(PURPLE_CONV_CHAT(swboard->conv),
                                      purple_account_get_username(account),
                                      NULL, PURPLE_CBFLAGS_NONE, TRUE);
        }
    }
    else if (swboard->conv == NULL)
    {
        swboard->conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
                                                              user, account);
    }
    else
    {
        pn_warning ("this should not happen");
    }
}

static PurpleConversation *
msn_switchboard_get_conv(MsnSwitchBoard *swboard)
{
    PurpleAccount *account;

    g_return_val_if_fail (swboard, NULL);

    if (swboard->conv != NULL)
        return swboard->conv;

    pn_warning ("switchboard with unassigned conversation");

    account = msn_session_get_user_data (swboard->session);

    return (swboard->conv = purple_conversation_new (PURPLE_CONV_TYPE_IM, account, swboard->im_user));
}

static void
swboard_error_helper(MsnSwitchBoard *swboard, int reason, const char *passport)
{
    g_return_if_fail(swboard);

    pn_error ("unable to call the user: passport=[%s],reason[%i]",
              passport ? passport : "(null)", reason);

    /* TODO: if current_users > 0, this is probably a chat and an invite failed,
     * we should report that in the chat or something */
    if (swboard->current_users == 0)
    {
        swboard->error = reason;
        msn_switchboard_close(swboard);
    }
}

static void
cal_error_helper(MsnSwitchBoard *swboard, MsnTransaction *trans, int reason)
{
    const char *passport;
    char **params;

    g_return_if_fail (swboard);

    params = g_strsplit(trans->params, " ", 0);

    passport = params[0];

    pn_warning ("failed: command=[%s],reason=%i",
                trans->command, reason);

    swboard_error_helper(swboard, reason, passport);

    g_strfreev(params);
}

static void
msg_error_helper(MsnCmdProc *cmdproc, MsnMessage *msg, MsnMsgErrorType error)
{
    MsnSwitchBoard *swboard;

    swboard = cmdproc->data;

    if (msg->type == MSN_MSG_TEXT &&
        msn_message_get_flag (msg) != 'U')
    {
        const char *reason;
        char *body;

        if (error == MSN_MSG_ERROR_SB) {
            switch (swboard->error) {
                case MSN_SB_ERROR_OFFLINE:
                    reason = _("Message could not be sent, "
                               "not allowed while invisible:");
                    break;
                case MSN_SB_ERROR_USER_OFFLINE:
                    reason = _("Message could not be sent "
                               "because the user is offline:");
                    break;
                case MSN_SB_ERROR_CONNECTION:
                    reason = _("Message could not be sent "
                               "because a connection error occurred:");
                    break;
                case MSN_SB_ERROR_TOO_FAST:
                    reason = _("Message could not be sent "
                               "because we are sending too quickly:");
                    break;
                case MSN_SB_ERROR_AUTHFAILED:
                    reason = _("Message could not be sent "
                               "because we were unable to establish a "
                               "session with the server. This is "
                               "likely a server problem, try again in "
                               "a few minutes:");
                    break;
                default:
                    reason = _("Message could not be sent "
                               "because an error with "
                               "the switchboard occurred:");
                    break;
            }
        }
        else
            reason = _("Message may have not been sent "
                       "because an unknown error occurred:");

        {
            char *tmp;
            tmp = msn_message_to_string(msg);
            body = g_markup_escape_text(tmp, -1);
            g_free(tmp);
        }

        {
            PurpleConversation *conv;

            if ((conv = msn_switchboard_get_conv(swboard))) {
                purple_conversation_write(conv, NULL, reason, PURPLE_MESSAGE_ERROR, time(NULL));
                purple_conversation_write(conv, NULL, body, PURPLE_MESSAGE_RAW, time(NULL));
            }
        }

        g_free(body);
    }

    if (msg->trans && (msg->type == MSN_MSG_TEXT || msg->type == MSN_MSG_SLP)) {
        swboard->ack_list = g_list_remove(swboard->ack_list, msg);
        msn_message_unref(msg);
    }
}

/**************************************************************************
 * Message Stuff
 **************************************************************************/

/** Called when we receive an error of a message. */
static void
msg_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    msg_error_helper(cmdproc, trans->data, MSN_MSG_ERROR_UNKNOWN);
}

static void
release_msg(MsnSwitchBoard *swboard, MsnMessage *msg)
{
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;
    char *payload;
    gsize payload_len;

    g_return_if_fail(swboard);
    g_return_if_fail(msg     != NULL);

    cmdproc = swboard->cmdproc;

    payload = msn_message_gen_payload(msg, &payload_len);

#ifdef PECAN_DEBUG_SB
    msn_message_show_readable(msg, "SB SEND", FALSE);
#endif

    trans = msn_transaction_new(cmdproc, "MSG", "%c %d",
                                msn_message_get_flag(msg), payload_len);

    /* Data for callbacks */
    msn_transaction_set_data(trans, msg);

    if (msg->type == MSN_MSG_TEXT || msg->type == MSN_MSG_SLP) {
        msn_message_ref(msg);
        swboard->ack_list = g_list_append(swboard->ack_list, msg);
    }

    if (swboard->timer)
        pn_timer_start(swboard->timer, 60);

    trans->payload = payload;
    trans->payload_len = payload_len;

    if (msg->trans)
        msn_transaction_unref(msg->trans);

    msn_transaction_ref(trans);
    msg->trans = trans;

    msn_cmdproc_send_trans(cmdproc, trans);
}

static void
queue_msg(MsnSwitchBoard *swboard, MsnMessage *msg)
{
    g_return_if_fail(swboard);
    g_return_if_fail(msg     != NULL);

    pn_debug ("appending message to queue");

    msn_message_ref(msg);
    g_queue_push_tail(swboard->msg_queue, msg);
}

static void
process_queue(MsnSwitchBoard *swboard)
{
    MsnMessage *msg;

    g_return_if_fail(swboard);

    pn_debug ("processing queue");

    while ((msg = g_queue_pop_head(swboard->msg_queue)) != NULL)
    {
        pn_debug ("sending message");
        release_msg(swboard, msg);
        msn_message_unref(msg);
    }
}

gboolean
msn_switchboard_can_send(MsnSwitchBoard *swboard)
{
    g_return_val_if_fail(swboard, FALSE);

    if (swboard->empty || !g_queue_is_empty(swboard->msg_queue))
        return FALSE;

    return TRUE;
}

void
msn_switchboard_send_msg(MsnSwitchBoard *swboard, MsnMessage *msg,
                         gboolean queue)
{

    if (msn_switchboard_can_send(swboard))
        release_msg(swboard, msg);
    else if (queue)
        queue_msg(swboard, msg);
}

/**************************************************************************
 * Switchboard Commands
 **************************************************************************/

static void
ans_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;

    swboard = cmdproc->data;
    g_return_if_fail (swboard);
    swboard->ready = TRUE;
}

static void
bye_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;
    const char *user;

    swboard = cmdproc->data;
    user = cmd->params[0];

    /* cmdproc->data is set to NULL when the switchboard is destroyed;
     * we may get a bye shortly thereafter. */
    g_return_if_fail(swboard);

    if (swboard->conv == NULL)
    {
        /* This is a helper switchboard */
        msn_switchboard_close(swboard);
    }
    else if ((swboard->current_users > 1) ||
             (purple_conversation_get_type(swboard->conv) == PURPLE_CONV_TYPE_CHAT))
    {
        /* This is a switchboard used for a chat */
        purple_conv_chat_remove_user(PURPLE_CONV_CHAT(swboard->conv), user, NULL);
        swboard->current_users--;
        if (swboard->current_users == 0)
            msn_switchboard_close(swboard);
    }
    else
    {
        /* This is a switchboard used for a im session */
        msn_switchboard_close(swboard);
    }
}

static void
iro_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;

    swboard = cmdproc->data;

    g_return_if_fail (swboard);

    swboard->total_users = atoi (cmd->params[2]);

    msn_switchboard_add_user (swboard, cmd->params[3]);

    /* don't discard the transaction just yet (wait for ANS) */
    cmd->trans = NULL;
}

static void
joi_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;
    const char *passport;

    passport = cmd->params[0];

    session = cmdproc->session;
    swboard = cmdproc->data;
    g_return_if_fail (swboard);

    msn_switchboard_add_user(swboard, passport);

    process_queue(swboard);

    if (!msn_session_get_bool (session, "use_http_method"))
        send_clientcaps(swboard);
}

static void
msg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
    MsnMessage *msg;
    MsnSwitchBoard *swboard = cmdproc->data;

    msg = msn_message_new_from_cmd(cmd);

    msn_message_parse_payload(msg, payload, len);
#ifdef PECAN_DEBUG_SB
    msn_message_show_readable(msg, "SB RECV", FALSE);
#endif

    if (msg->remote_user != NULL)
        g_free (msg->remote_user);

    msg->remote_user = g_strdup(cmd->params[0]);
    msn_cmdproc_process_msg(cmdproc, msg);

    if (swboard->timer)
        pn_timer_start(swboard->timer, 60);

    msn_message_unref(msg);
}

static void
msg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    cmd->payload_len = atoi(cmd->params[2]);
    cmdproc->last_cmd->payload_cb = msg_cmd_post;
}

/** @todo This ACK, NAK, timeout stuff needs to be completely reworked.
 * This leaves way too much room for bugs. */
static void
nak_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnMessage *msg = cmd->trans->data;
    msg_error_helper(cmdproc, msg, MSN_MSG_ERROR_NAK);
}

static void
ack_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;
    MsnMessage *msg;

    msg = cmd->trans->data;

    swboard = cmdproc->data;
    if (swboard)
        swboard->ack_list = g_list_remove(swboard->ack_list, msg);

    if (msg->ack_cb)
        msg->ack_cb(msg, msg->ack_data);

    msg->nak_cb = NULL;

    msn_message_unref(msg);
}

static void
out_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;

    swboard = cmdproc->data;
    g_return_if_fail (swboard);

    if (swboard->current_users > 1)
    {
        PurpleAccount *account;
        PurpleConnection *connection;
        account = msn_session_get_user_data (cmdproc->session);
        connection = purple_account_get_connection (account);
        serv_got_chat_left (connection, swboard->chat_id);
    }

    msn_switchboard_disconnect(swboard);
}

static void
usr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;

    swboard = cmdproc->data;
    g_return_if_fail (swboard);

#if 0
    GList *l;

    for (l = swboard->users; l != NULL; l = l->next)
    {
        const char *user;
        user = l->data;

        msn_cmdproc_send(cmdproc, "CAL", "%s", user);
    }
#endif

    {
        gchar *participant;
        while ((participant = g_queue_pop_head (swboard->invites)))
        {
            msn_cmdproc_send (cmdproc, "CAL", "%s", participant);
            g_free (participant);
        }
    }

    swboard->ready = TRUE;
}

/**************************************************************************
 * Message Handlers
 **************************************************************************/

static void
notify_user (MsnCmdProc *cmdproc,
             const char *passport,
             const char *str)
{
    MsnSwitchBoard *swboard;
    struct pn_contact *contact;
    const char *friendly_name;
    gchar *buf;

    swboard = cmdproc->data;

    if (!swboard->conv)
    {
        PurpleAccount *account;

        account = msn_session_get_user_data (cmdproc->session);

        if (swboard->current_users > 1)
            swboard->conv = purple_find_chat (account->gc, swboard->chat_id);
        else
            swboard->conv = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM, passport, account);

        if (!swboard->conv)
            swboard->conv = purple_conversation_new (PURPLE_CONV_TYPE_IM, account, passport);
    }

    contact = pn_contactlist_find_contact (cmdproc->session->contactlist, passport);

    friendly_name = pn_contact_get_friendly_name (contact);
    if (!friendly_name)
        friendly_name = passport;

    buf = g_strdup_printf ("%s %s", friendly_name, str);

    purple_conversation_write (swboard->conv, NULL, buf, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NOTIFY, time (NULL));

    g_free (buf);
}

#if defined(RECEIVE_PLUS_SOUNDS)
static void
save_plus_sound_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
                   const gchar *sound, size_t len, const gchar *error_message)
{
    FILE *f;
    gchar *path;
    gchar *str;
    MsnCmdProc *cmdproc = user_data;
    const char *passport = cmdproc->extra_data;

    if ((error_message != NULL) || (len == 0))
        return;

    if (purple_mkstemp(&path, TRUE))
    {
        gchar *path_mp3 = g_strconcat (path, ".mp3", NULL);

        f = fopen (path_mp3, "wb");
        fwrite(sound, len, 1, f);

#ifndef ADIUM
#if PURPLE_VERSION_CHECK(2,6,0)
        str = g_strdup_printf (_("sent you a Messenger Plus! sound. Click <a href='audio://%s'>here</a> to play it."), path_mp3);
#else
        str = g_strdup_printf (_("sent you a Messenger Plus! sound. Click <a href='file://%s'>here</a> to play it."), path_mp3);
#endif /* PURPLE_VERSION_CHECK(2,6,0) */
#else
        str = g_strdup_printf (_("sent you a Messenger Plus! sound. Copy the following link in your web browser to play it: file://%s"), path_mp3);
#endif /* ADIUM */
        notify_user (cmdproc, passport, str);

        fclose(f);

        g_free (path_mp3);
    }
    else
    {
        pn_error ("couldn't create temporany file to store the received Plus! sound!\n");

        str = g_strdup_printf (_("sent you a Messenger Plus! sound, but it cannot be played due to an error happened while storing the file."));
        notify_user (cmdproc, passport, str);
    }

    g_free(str);
    g_free(path);
}
#endif /* defined(RECEIVE_PLUS_SOUNDS) */

static void
plain_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    PurpleConnection *gc;
    PurpleAccount *account;
    MsnSwitchBoard *swboard;
    PurpleBuddy *buddy;
    const char *body;
    char *body_str;
    char *body_enc;
    char *body_final;
    char *alias_backup = NULL;
    gboolean alias_faked = FALSE;
    size_t body_len;
    char *passport;
    const char *value;

    account = msn_session_get_user_data (cmdproc->session);
    gc = purple_account_get_connection (account);
    swboard = cmdproc->data;
    g_return_if_fail (swboard);

    body = msn_message_get_bin_data(msg, &body_len);
    body_str = g_strndup(body, body_len);
    body_enc = g_markup_escape_text(body_str, -1);
    g_free(body_str);

    passport = g_strdup (msg->remote_user);

    buddy = purple_find_buddy(account, passport);

    if (!strcmp(passport, "messenger@microsoft.com") &&
        strstr(body, "immediate security update"))
    {
        return;
    }

#if 0
    if ((value = msn_message_get_attr(msg, "User-Agent")) != NULL)
    {
        pn_debug ("user-agent=[%s]", value);
    }
#endif

    if ((value = msn_message_get_attr(msg, "P4-Context")) != NULL)
    {
        alias_backup = g_strdup(buddy->alias);
        purple_buddy_set_public_alias(gc, passport, value);
        alias_faked = TRUE;
    }

    if ((value = msn_message_get_attr(msg, "X-MMS-IM-Format")) != NULL)
    {
        char *pre, *post;

        msn_parse_format(value, &pre, &post);

        body_final = g_strdup_printf("%s%s%s", pre ? pre : "",
                                     body_enc ? body_enc : "", post ? post : "");

        g_free(pre);
        g_free(post);
        g_free(body_enc);
    }
    else
    {
        body_final = body_enc;
    }

#if defined(RECEIVE_PLUS_SOUNDS)
    const char *body_plus_sound = strstr (body_final, "[Messenger Plus! Sound] - Data{");

    if (body_plus_sound && strlen (body_plus_sound) > 43)
    {
        char *plus_sound_link = calloc (48 + 12 + 1, 1);

        strcpy (plus_sound_link, "http://sounds.msgpluslive.net/esnd/snd/get?hash=");
        strncat (plus_sound_link, body_plus_sound + 31, 12);

        cmdproc->extra_data = passport;

        purple_util_fetch_url (plus_sound_link, TRUE, NULL, FALSE, save_plus_sound_cb, cmdproc);

        free (plus_sound_link);

        return;
    }
#endif /* defined(RECEIVE_PLUS_SOUNDS) */

    {
        PurpleAccount *account;
        PurpleConnection *connection;

        account = msn_session_get_user_data (cmdproc->session);
        connection = purple_account_get_connection (account);

        if (swboard->current_users > 1 ||
            (swboard->conv && purple_conversation_get_type (swboard->conv) == PURPLE_CONV_TYPE_CHAT))
        {
            /* If current_users is always ok as it should then there is no need to
             * check if this is a chat. */
            if (swboard->current_users <= 1)
                pn_warning ("plain_msg: current_users=[%d]", swboard->current_users);

            serv_got_chat_in (connection, swboard->chat_id, passport, 0, body_final, time (NULL));
            if (!swboard->conv)
                swboard->conv = purple_find_chat (connection, swboard->chat_id);
        }
        else
        {
            serv_got_im (connection, passport, body_final, 0, time (NULL));
            if (!swboard->conv)
                swboard->conv = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM, passport, account);
        }
    }

    if (alias_faked)
    {
        purple_buddy_set_public_alias(gc, passport, alias_backup);
        g_free(alias_backup);
    }

    g_free(body_final);
    g_free(passport);
}

#if defined(PECAN_CVR)
static void
handwritten_msg (MsnCmdProc *cmdproc, MsnMessage *msg)
{
    const char *body;
    size_t body_len;

    body = msn_message_get_bin_data (msg, &body_len);
    switchboard_show_ink (cmdproc->data, msg->remote_user, body);
}

void
switchboard_show_ink (MsnSwitchBoard *swboard, const char *passport,
                      const char *data)
{
    PurpleConnection *gc;
    PurpleAccount *account;
    guchar *image_data;
    size_t image_len;
#ifndef ADIUM
    int img_id;
#else
    FILE *f;
    gchar *file;
#endif /* ADIUM */
    gchar *image_msg;

    if (!purple_str_has_prefix (data, "base64:"))
    {
        pn_error ("ink receiving: ignoring ink not in base64 format");

        return;
    }

    account = msn_session_get_user_data (swboard->session);
    gc = purple_account_get_connection (account);

    data += sizeof ("base64:") - 1;
    image_data = purple_base64_decode (data, &image_len);
    if (!image_data || !image_len)
    {
        pn_error("ink receiving: unable to decode ink from base64 format");

        return;
    }
#ifndef ADIUM
    img_id = purple_imgstore_add_with_id (image_data, image_len, NULL);

    image_msg = g_strdup_printf ("<img id='%d' />", img_id);
#else
    if ((f = purple_mkstemp (&file, TRUE)))
    {
        const gchar alt_text = _("received handwritten message");

        fwrite (image_data, image_len, 1, f);
        fclose (f);

        image_msg = g_strdup_printf ("<img src=\"file://%s\" alt=\"(%s)\" />", file, alt_text);

        g_free (file);
    }
    else
    {
        pn_error ("ink receiving: unable to store ink image");

        notify_user (swboard->cmdproc, passport, _("sent you an handwritten message,"
                     " but it cannot be displayed due to an error happened while storing the file."));

        return;
    }
#endif /* ADIUM */

    if (swboard->current_users > 1 || ((swboard->conv != NULL) &&
        purple_conversation_get_type(swboard->conv) == PURPLE_CONV_TYPE_CHAT))
        serv_got_chat_in (gc, swboard->chat_id, passport, 0, image_msg, time(NULL));
    else
        serv_got_im (gc, passport, image_msg, 0, time(NULL));

#ifndef ADIUM
    purple_imgstore_unref_by_id (img_id);
#endif /* ADIUM */
    g_free (image_msg);
}
#endif /* defined(PECAN_CVR) */

static void
control_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    MsnSwitchBoard *swboard;
    char *passport;

    swboard = cmdproc->data;
    passport = msg->remote_user;

    g_return_if_fail (swboard);

    if (swboard->current_users == 1 &&
        msn_message_get_attr(msg, "TypingUser") != NULL)
    {
        PurpleAccount *account;
        PurpleConnection *connection;
        account = msn_session_get_user_data (cmdproc->session);
        connection = purple_account_get_connection (account);
        serv_got_typing (connection, passport, 6, PURPLE_TYPING);
    }
}

#if defined(PECAN_LIBSIREN)
static void
got_voice_clip(struct pn_peer_call *call, const guchar *data, gsize size)
{
    FILE *f;
    char *file;

    if ((f = purple_mkstemp(&file, TRUE)))
    {
        gchar *decoded_file;
        gchar *str;

        fwrite(data, size, 1, f);
        fclose(f);

        decoded_file = g_strconcat (file, "_decoded.wav", NULL);

        pn_siren7_decode_file (file, decoded_file);

#ifndef ADIUM
        str = g_strdup_printf(_("sent you a voice clip. Click <a href='file://%s'>here</a> to play it."), decoded_file);
#else
        str = g_strdup_printf(_("sent you a voice clip. Copy the following link in your web browser to play it: file://%s"), decoded_file);
#endif /* ADIUM */

        g_free (decoded_file);

        notify_user (call->swboard->cmdproc, pn_peer_link_get_passport(call->link), str);

        g_free (str);
    } else {
        pn_error ("couldn't create temporany file to store the received voice clip!\n");

        notify_user (call->swboard->cmdproc, pn_peer_link_get_passport(call->link),
                     _("sent you a voice clip, but it cannot be played due"
                       "to an error happened while storing the file."));
    }
}
#endif /* defined(PECAN_LIBSIREN) */

#if defined(PECAN_LIBMSPACK)
static gboolean
extract_wink(struct pn_peer_call *call, const guchar *data, gsize size)
{
    struct mscab_decompressor *dec;
    struct mscabd_cabinet *cab;
    struct mscabd_file *fileincab;
    FILE *f;
    char *msg, *swf_msg, *emot_name, *emot;
    size_t emot_len;
    const gchar *tmpdir;
    char *swf_path, *img_path, *html_path;
    char *path, *craff;
    int imgid;

    if (!(f = purple_mkstemp(&path, TRUE)))
    {
        pn_error("Couldn't open temp file for .cab image.\n");
        return FALSE;
    }

    fwrite(data, size, 1, f);
    fclose(f);

    if (!(dec = mspack_create_cab_decompressor(NULL)))
    {
        pn_error("Couldn't create decompressor.\n");
        return FALSE;
    }
    if (!(cab = dec->open(dec, path)))
    {
        pn_error("Couldn't open .cab file.\n");
        return FALSE;
    }
    tmpdir = (gchar*)g_get_tmp_dir();
    fileincab = cab->files;
    swf_path = img_path = NULL;
    while (fileincab)
    {
        craff = g_build_filename(tmpdir, fileincab->filename, NULL);
        dec->extract(dec, fileincab, craff);
        if (strstr(fileincab->filename, ".swf")) swf_path = craff;
        else if (strstr(fileincab->filename, ".png") || strstr(fileincab->filename, ".jpg") ||
                strstr(fileincab->filename, ".gif"))
            img_path = craff;
        else g_free(craff);
        fileincab = fileincab->next;
    }
    /* don't g_free(tmpdir) - it's just a ref to a global */
    dec->close(dec, cab);
    mspack_destroy_cab_decompressor(dec);
    g_free(path);

    pn_info("swf_path %s\n", swf_path);
    emot_name = swf_msg = NULL;
    if (swf_path)
    {
        if ((f = purple_mkstemp(&html_path, FALSE)))
        {
            g_fprintf(f, "<script type='text/javascript'>\n" \
                SWFOBJECT "\n</script>\n" \
                "<script type='text/javascript'>\n" \
                "setTimeout('Redirect()',0);\n" \
                "function Redirect() {\n" \
                "if (swfobject.hasFlashPlayerVersion('9.0.0')) location.href = 'file://%s';\n" \
                "else document.getElementById('wink').style.visibility = '';\n" \
                "}\n" \
                "</script>\n" \
                "<div style='visibility:hidden' id='wink'>\n" \
                "<h2>Your browser does not support Shockwave Flash.</h2>\n" \
                "This software is required to play winks.<p><img src='%s'/>\n" \
                "<a href='http://www.adobe.com/go/getflashplayer'>\n" \
                "<img src='http://www.adobe.com/images/shared/download_buttons/get_flash_player.gif' " \
                "alt='Get Adobe Flash player' /></a></p>\n" \
                "</div>", swf_path, img_path);
            fclose(f);
            swf_msg = g_strdup_printf(
                _("<a href=\"file://%s\">Click here to view the wink in your web browser</a>"),
                html_path);
            g_free(html_path);
        }
        else
        {
            swf_msg = g_strdup_printf(
                _("<a href=\"file://%s\">Click here to view the wink in your web browser</a>"),
                swf_path);
        }
    }

    imgid = 0;
    if (img_path)
    {
        if (g_file_get_contents(img_path, &emot, &emot_len, NULL))
        {
            PurpleConversation *conv;
            MsnSwitchBoard *swboard;
            PurpleAccount *account;

            swboard = call->swboard;
            conv = swboard->conv;
            account = msn_session_get_user_data(swboard->session);

            if (!conv)
                conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, pn_peer_link_get_passport(call->link));

            imgid = purple_imgstore_add_with_id(emot, emot_len, NULL);
            emot_name = g_strdup_printf ("<IMG ID='%d'/>", imgid);

        }
        else
        {
            emot = NULL;
        }
    }
    if (emot_name)
        msg = g_strdup_printf(_("sent a wink:\n%s\n%s"), emot_name, swf_msg);
    else
        msg = g_strdup_printf(_("sent a wink.\n%s"), swf_msg);

    notify_user (call->swboard->cmdproc, pn_peer_link_get_passport(call->link),
        msg);
    purple_imgstore_unref_by_id (imgid);
    g_free (emot_name);
    /* Blows: probably the smiley code doesn't copy it.. g_free(emot); */
    g_free(msg); g_free(swf_msg); g_free(img_path); g_free(swf_path);
    return TRUE;
}

static void
got_wink(struct pn_peer_call *call, const guchar *data, gsize size)
{
    if (!(extract_wink (call, data, size)))
        notify_user (call->swboard->cmdproc, pn_peer_link_get_passport (call->link),
                     _("sent a wink, but it could not be displayed."));
}
#endif /* defined(PECAN_LIBMSPACK) */

static void
datacast_msg (MsnCmdProc *cmdproc,
              MsnMessage *msg)
{
    PurpleAccount *account;
    PurpleConnection *connection;
    GHashTable *body;
    const char *id, *passport;
    body = msn_message_get_hashtable_from_body(msg);

    id = g_hash_table_lookup(body, "ID");

    account = msn_session_get_user_data (cmdproc->session);
    connection = purple_account_get_connection (account);
    passport = msg->remote_user;

    if (strcmp (id, "1") == 0)
    {
#if PURPLE_VERSION_CHECK(2,5,0)
        MsnSwitchBoard *swboard;

        swboard = cmdproc->data;

        if (swboard->current_users > 1 ||
            (swboard->conv &&
             purple_conversation_get_type (swboard->conv) == PURPLE_CONV_TYPE_CHAT))
            purple_prpl_got_attention_in_chat (connection, swboard->chat_id, passport, 0);
        else
            purple_prpl_got_attention (connection, passport, 0);
#else
        serv_got_attention (account->gc, passport, 0);
#endif /* PURPLE_VERSION_CHECK(2,5,0) */
    }
    else if (strcmp (id, "2") == 0)
    {
#if defined(PECAN_LIBMSPACK)
        /* winks */
        const char *data;
        struct pn_peer_link *link;
        struct pn_msnobj *obj;

        data = g_hash_table_lookup(body, "Data");
        obj = pn_msnobj_new_from_string(data);

        link = msn_session_get_peer_link(cmdproc->session, passport);
        pn_peer_link_request_object(link, data, got_wink, NULL, obj);

        pn_msnobj_free(obj);
#endif /* defined(PECAN_LIBMSPACK) */
    }
    else if (strcmp (id, "3") == 0)
    {
#if defined(PECAN_LIBSIREN)
        const char *data;
        struct pn_peer_link *link;
        struct pn_msnobj *obj;

        data = g_hash_table_lookup(body, "Data");
        obj = pn_msnobj_new_from_string(data);

        link = msn_session_get_peer_link(cmdproc->session, passport);
        pn_peer_link_request_object(link, data, got_voice_clip, NULL, obj);

        pn_msnobj_free(obj);
#endif /* defined(PECAN_LIBSIREN) */
    }
    else
    {
        pn_warning ("Got unknown datacast with ID %s.\n", id);
    }
}

static void
p2p_msg(MsnCmdProc *cmdproc,
        MsnMessage *msg)
{
    MsnSession *session;
    struct pn_peer_link *link;

    session = cmdproc->session;
    link = msn_session_get_peer_link(session, msg->remote_user);

    pn_peer_link_process_msg(link, msg, 0, cmdproc->data);
}

static void
got_emoticon(struct pn_peer_call *call,
             const guchar *data,
             gsize size)
{
    PurpleConversation *conv;
    MsnSwitchBoard *swboard;

    swboard = call->swboard;
    conv = swboard->conv;

    if (conv) {
        /* FIXME: it would be better if we wrote the data as we received it
           instead of all at once, calling write multiple times and
           close once at the very end
           */
        purple_conv_custom_smiley_write(conv, call->data_info, data, size);
        purple_conv_custom_smiley_close(conv, call->data_info);
    }

    pn_debug("got smiley: %s", call->data_info);
}

static void
emoticon_msg(MsnCmdProc *cmdproc,
             MsnMessage *msg)
{
    MsnSession *session;
    struct pn_peer_link *link;
    MsnSwitchBoard *swboard;
    struct pn_msnobj *obj;
    char **tokens;
    char *smile, *body_str;
    const char *body, *who, *sha1;
    guint tok;
    size_t body_len;
    PurpleAccount *account;

    session = cmdproc->session;
    account = msn_session_get_user_data(session);

    if  (!purple_account_get_bool(account, "custom_smileys", TRUE))
        return;

    body = msn_message_get_bin_data(msg, &body_len);
    body_str = g_strndup(body, body_len);

    /* MSN Messenger 7 may send more than one MSNObject in a single message...
     * Maybe 10 tokens is a reasonable max value. */
    tokens = g_strsplit(body_str, "\t", 10);

    g_free(body_str);

    for (tok = 0; tok < 9; tok += 2) {
        gchar *tmp;

        if (!tokens[tok] || !tokens[tok + 1])
            break;

        smile = tokens[tok];

        tmp = pn_url_decode (tokens[tok + 1]);
        obj = pn_msnobj_new_from_string(tmp);
        g_free(tmp);

        if (!obj)
            break;

        who = msg->remote_user;
        sha1 = pn_msnobj_get_sha1(obj);

        link = msn_session_get_peer_link(session, who);

#ifdef HAVE_LIBPURPLE
        {
            PurpleConversation *conv;

            swboard = cmdproc->data;
            conv = swboard->conv;

            if (msn_session_find_swboard (session, pn_peer_link_get_passport (link)) != swboard)
            {
                if (msn_session_find_swboard (session, pn_peer_link_get_passport (link)))
                {
                    /*
                     * Apparently we're using a different switchboard now or
                     * something?  I don't know if this is normal, but it
                     * definitely happens.  So make sure the old switchboard
                     * doesn't still have a reference to us.
                     */
                    g_hash_table_remove (session->conversations, pn_peer_link_get_passport (link));
                }
                g_hash_table_insert (session->conversations, g_strdup (pn_peer_link_get_passport (link)), swboard);
            }

            /* If the conversation doesn't exist then this is a custom smiley
             * used in the first message in a MSN conversation: we need to create
             * the conversation now, otherwise the custom smiley won't be shown.
             * This happens because every GtkIMHtml has its own smiley tree: if
             * the conversation doesn't exist then we cannot associate the new
             * smiley with its GtkIMHtml widget. */
            if (!conv)
                conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, who);

            if (purple_conv_custom_smiley_add(conv, smile, "sha1", sha1, TRUE))
                pn_peer_link_request_object(link, smile, got_emoticon, NULL, obj);
        }
#endif /* HAVE_LIBPURPLE */

        pn_msnobj_free(obj);
    }

    g_strfreev(tokens);
}

#ifdef HAVE_LIBPURPLE
static void
invite_msg (MsnCmdProc *cmdproc, MsnMessage *msg)
{
    GHashTable *body;
    const gchar *guid;

    body = msn_message_get_hashtable_from_body (msg);

    if (!body) {
        pn_warning ("unable to parse invite body");

        return;
    }

    guid = g_hash_table_lookup(body, "Application-GUID");

    if (!guid) {
        const gchar *cmd = g_hash_table_lookup (body, "Invitation-Command");

        if (cmd && strcmp(cmd, "CANCEL") == 0) {
            const gchar *code = g_hash_table_lookup (body, "Cancel-Code");

            pn_info ("MSMSGS invitation cancelled: %s", code ? code : "no reason given");
        }
        else
            pn_warning ("missing: Application-GUID");
    } else if (strcmp (guid, "{02D3C01F-BF30-4825-A83A-DE7AF41648AA}") == 0) {
        gchar *from = msg->remote_user;

        pn_info ("got a call from computer");

        notify_user (cmdproc, from, _(" sent you a voice chat invite, which is not yet supported."));
    }
    else
        pn_warning ("unhandled invite msg with GUID=[%s]", guid);

    g_hash_table_destroy (body);
}
#endif

/**************************************************************************
 * Connect stuff
 **************************************************************************/

static void
ans_usr_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    MsnSwitchBoard *swboard;
    char **params;
    char *passport;
    int reason = MSN_SB_ERROR_UNKNOWN;

    if (error == 911)
    {
        reason = MSN_SB_ERROR_AUTHFAILED;
    }

    pn_warning ("command=[%s],error=%i",
                trans->command, error);

    swboard = trans->data;
    g_return_if_fail (swboard);

    params = g_strsplit(trans->params, " ", 0);
    passport = params[0];

    swboard_error_helper(swboard, reason, passport);

    g_strfreev(params);
}

gboolean
msn_switchboard_connect(MsnSwitchBoard *swboard, const char *host, int port)
{
    g_return_val_if_fail (swboard, FALSE);

    pn_node_connect (PN_NODE (swboard->conn), host, port);

    return TRUE;
}

void
msn_switchboard_disconnect(MsnSwitchBoard *swboard)
{
    g_return_if_fail(swboard);
}

/**************************************************************************
 * Call stuff
 **************************************************************************/
static void
cal_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    int reason = MSN_SB_ERROR_UNKNOWN;

    if (error == 215)
    {
        pn_warning ("already in switchboard");
        return;
    }
    else if (error == 217)
    {
        reason = MSN_SB_ERROR_USER_OFFLINE;
    }

    pn_warning ("command=[%s],error=%i",  trans->command, error);

    cal_error_helper(cmdproc->data, trans, reason);
}

void
msn_switchboard_request_add_user(MsnSwitchBoard *swboard, const char *user)
{
    MsnCmdProc *cmdproc;

    g_return_if_fail(swboard);

    cmdproc = swboard->cmdproc;

    if (!swboard->ready)
    {
        pn_debug ("not ready yet");
        g_queue_push_tail (swboard->invites, g_strdup (user));
        return;
    }

    msn_cmdproc_send (cmdproc, "CAL", "%s", user);
}

/**************************************************************************
 * Create & Transfer stuff
 **************************************************************************/

static void
got_swboard(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;
    char *host;
    int port;

    g_return_if_fail(cmd);
    g_return_if_fail(cmd->trans);

    swboard = cmd->trans->data;
    g_return_if_fail (swboard);

    if (msn_switchboard_unref (swboard) == NULL)
        /* The conversation window was closed. */
        return;

    msn_switchboard_set_auth_key(swboard, cmd->params[4]);

    msn_parse_socket(cmd->params[2], &host, &port);

    if (!msn_switchboard_connect(swboard, host, port))
        msn_switchboard_close(swboard);

    g_free(host);
}

static void
xfr_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    MsnSwitchBoard *swboard;
    int reason = MSN_SB_ERROR_UNKNOWN;

    if (error == 913)
        reason = MSN_SB_ERROR_OFFLINE;
    else if (error == 800)
        reason = MSN_SB_ERROR_TOO_FAST;

    swboard = trans->data;
    g_return_if_fail (swboard);

    pn_error ("error=%i,user=[%s],trans=%p,command=[%s],reason=%i",
              error, swboard->im_user, trans, trans->command, reason);

    swboard_error_helper(swboard, reason, swboard->im_user);
}

void
msn_switchboard_request(MsnSwitchBoard *swboard)
{
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;

    g_return_if_fail(swboard);

    cmdproc = swboard->session->notification->cmdproc;

    trans = msn_transaction_new(cmdproc, "XFR", "%s", "SB");
    msn_transaction_add_cb(trans, "XFR", got_swboard);

    msn_transaction_set_data(trans, swboard);
    msn_transaction_set_error_cb(trans, xfr_error);

    msn_switchboard_ref(swboard); /* The conversation window might get closed. */
    msn_cmdproc_send_trans(cmdproc, trans);
}

void
msn_switchboard_close(MsnSwitchBoard *swboard)
{
    g_return_if_fail(swboard);

    if (swboard->closed) {
        pn_error ("already closed");
        return;
    }

    swboard->closed = TRUE;

    /* Don't let a write error destroy the switchboard before we do. */
    msn_switchboard_ref(swboard);

    if (swboard->error == MSN_SB_ERROR_NONE)
        msn_cmdproc_send_quick(swboard->cmdproc, "OUT", NULL, NULL);

    if (swboard->chat_id)
        g_hash_table_remove (swboard->session->chats, GINT_TO_POINTER (swboard->chat_id));
    else
        g_hash_table_remove (swboard->session->conversations, swboard->im_user);

    msn_switchboard_unref(swboard);
}

/**************************************************************************
 * Init stuff
 **************************************************************************/

void
msn_switchboard_init(void)
{
    cbs_table = msn_table_new();

    msn_table_add_cmd(cbs_table, "ANS", "ANS", ans_cmd);
    msn_table_add_cmd(cbs_table, "ANS", "IRO", iro_cmd);

    msn_table_add_cmd(cbs_table, "MSG", "ACK", ack_cmd);
    msn_table_add_cmd(cbs_table, "MSG", "NAK", nak_cmd);

    msn_table_add_cmd(cbs_table, "USR", "USR", usr_cmd);

    msn_table_add_cmd(cbs_table, NULL, "MSG", msg_cmd);
    msn_table_add_cmd(cbs_table, NULL, "JOI", joi_cmd);
    msn_table_add_cmd(cbs_table, NULL, "BYE", bye_cmd);
    msn_table_add_cmd(cbs_table, NULL, "OUT", out_cmd);

    /* avoid unhandled command warnings */
    msn_table_add_cmd(cbs_table, NULL, "CAL", NULL);

#if 0
    /* They might skip the history */
    msn_table_add_cmd(cbs_table, NULL, "ACK", NULL);
#endif

    msn_table_add_error(cbs_table, "MSG", msg_error);
    msn_table_add_error(cbs_table, "CAL", cal_error);

    /* Register the message type callbacks. */
    msn_table_add_msg_type(cbs_table, "text/plain",
                           plain_msg);
    msn_table_add_msg_type(cbs_table, "text/x-msmsgscontrol",
                           control_msg);
#if defined(PECAN_CVR)
    msn_table_add_msg_type(cbs_table, "application/x-msnmsgrp2p",
                           p2p_msg);
    msn_table_add_msg_type(cbs_table, "text/x-mms-emoticon",
                           emoticon_msg);
    msn_table_add_msg_type(cbs_table, "text/x-mms-animemoticon",
                           emoticon_msg);
    msn_table_add_msg_type(cbs_table, "image/gif",
                           handwritten_msg);
    msn_table_add_msg_type(cbs_table, "text/x-msmsgsinvite",
                           invite_msg);
#endif /* defined(PECAN_CVR) */
    msn_table_add_msg_type(cbs_table, "text/x-msnmsgr-datacast",
                           datacast_msg);
#if 0
    msn_table_add_msg_type(cbs_table, "text/x-msmmsginvite",
                           msn_invite_msg);
#endif
}

void
msn_switchboard_end(void)
{
    msn_table_destroy(cbs_table);
}
