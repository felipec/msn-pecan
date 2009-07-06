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
#include "fix_purple.h"

#include "pn_util.h"
#include "pn_log.h"
#include "pn_locale.h"

#if defined(PECAN_CVR)
#include "cvr/pn_peer_link.h"
#endif /* defined(PECAN_CVR) */

#if defined(PECAN_LIBSIREN)
#include "pn_siren7.h"
#endif /* defined(PECAN_LIBSIREN) */

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
#include "fix_purple_win32.h"
#include <account.h>
#include <prefs.h>

static MsnTable *cbs_table;

static void
ans_usr_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error);

static void
msg_error_helper(MsnCmdProc *cmdproc, MsnMessage *msg, MsnMsgErrorType error);

static void
msn_switchboard_report_user(MsnSwitchBoard *swboard, PurpleMessageFlags flags, const char *msg);

static void
open_cb (PnNode *conn,
         MsnSwitchBoard *swboard)
{
    MsnSession *session;
    MsnCmdProc *cmdproc;

    g_return_if_fail (conn != NULL);

    session = conn->session;
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
        swboard->conn = pn_cmd_server_new ("switchboard server", PN_NODE_SB);
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
            if (session->http_conn)
            {
                /* A single http connection shared by all nodes */
                pn_node_link (conn, session->http_conn);
            }
            else
            {
                /* Each node has it's own http connection. */
                PnNode *foo;

                foo = PN_NODE (pn_http_server_new ("foo server"));
                foo->session = session;
                pn_node_link (conn, foo);
                g_object_unref (foo);
            }
        }

        swboard->open_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), swboard);
        swboard->close_handler = g_signal_connect (conn, "close", G_CALLBACK (close_cb), swboard);
        swboard->error_handler = g_signal_connect (conn, "error", G_CALLBACK (close_cb), swboard);
    }

    swboard->ref_count++;

    return swboard;
}

void
msn_switchboard_free (MsnSwitchBoard *swboard)
{
    MsnMessage *msg;
    GList *l;

    pn_log ("begin");

    pn_log ("swboard=%p", swboard);

    g_return_if_fail(swboard);

    g_signal_handler_disconnect (swboard->conn, swboard->open_handler);
    g_signal_handler_disconnect (swboard->conn, swboard->close_handler);
    g_signal_handler_disconnect (swboard->conn, swboard->error_handler);

#if defined(PECAN_CVR)
    for (l = swboard->links; l; l = l->next) {
        PnPeerLink *link = l->data;
        link->swboard = NULL;
        pn_peer_link_unref(link);
    }
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
    while ((l = swboard->ack_list) != NULL)
        msg_error_helper(swboard->cmdproc, l->data, MSN_MSG_ERROR_SB);

    g_free(swboard->im_user);
    g_free(swboard->auth_key);
    g_free(swboard->session_id);

    for (l = swboard->users; l != NULL; l = l->next)
        g_free(l->data);

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
            MsnSession *session;

#ifdef PECAN_DEBUG_CHAT
            pn_info ("switching to chat");
#endif

            session = swboard->session;

            swboard->chat_id = session->conv_seq++;

            msn_switchboard_ref(swboard);

            g_hash_table_insert(session->chats, GINT_TO_POINTER (swboard->chat_id), swboard);
            g_hash_table_remove(session->conversations, swboard->im_user);

            if (swboard->conv != NULL)
                purple_conversation_destroy(swboard->conv);

            msn_switchboard_unref(swboard);

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

            g_free(swboard->im_user);
            swboard->im_user = NULL;
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
msn_switchboard_report_user(MsnSwitchBoard *swboard, PurpleMessageFlags flags, const char *msg)
{
    PurpleConversation *conv;

    g_return_if_fail(swboard);
    g_return_if_fail(msg != NULL);

    if ((conv = msn_switchboard_get_conv(swboard)) != NULL)
    {
        purple_conversation_write(conv, NULL, msg, flags, time(NULL));
    }
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
cal_error_helper(MsnTransaction *trans, int reason)
{
    MsnSwitchBoard *swboard;
    const char *passport;
    char **params;

    params = g_strsplit(trans->params, " ", 0);

    passport = params[0];

    swboard = trans->data;
    g_return_if_fail (swboard);

    pn_warning ("failed: command=[%s],reason=%i",
                trans->command, reason);

    swboard_error_helper(swboard, reason, passport);

    g_strfreev(params);
}

static void
msg_error_helper(MsnCmdProc *cmdproc, MsnMessage *msg, MsnMsgErrorType error)
{
    MsnSwitchBoard *swboard;

    g_return_if_fail(cmdproc != NULL);
    g_return_if_fail(msg     != NULL);

    if ((error != MSN_MSG_ERROR_SB) && (msg->nak_cb != NULL))
        msg->nak_cb(msg, msg->ack_data);

    swboard = cmdproc->data;

    /* This is not good, and should be fixed somewhere else. */
    g_return_if_fail (swboard);

    if (msg->type == MSN_MSG_TEXT && msn_message_get_flag (msg) != 'U')
    {
        const char *format, *str_reason;
        char *body_str, *body_enc, *pre, *post;

#if 0
        if (swboard->conv == NULL)
        {
            if (msg->ack_ref)
                msn_message_unref(msg);

            return;
        }
#endif

        if (error == MSN_MSG_ERROR_TIMEOUT)
        {
            str_reason = _("Message may have not been sent "
                           "because a timeout occurred:");
        }
        else if (error == MSN_MSG_ERROR_SB)
        {
            switch (swboard->error)
            {
                case MSN_SB_ERROR_OFFLINE:
                    str_reason = _("Message could not be sent, "
                                   "not allowed while invisible:");
                    break;
                case MSN_SB_ERROR_USER_OFFLINE:
                    str_reason = _("Message could not be sent "
                                   "because the user is offline:");
                    break;
                case MSN_SB_ERROR_CONNECTION:
                    str_reason = _("Message could not be sent "
                                   "because a connection error occurred:");
                    break;
                case MSN_SB_ERROR_TOO_FAST:
                    str_reason = _("Message could not be sent "
                                   "because we are sending too quickly:");
                    break;
                case MSN_SB_ERROR_AUTHFAILED:
                    str_reason = _("Message could not be sent "
                                   "because we were unable to establish a "
                                   "session with the server. This is "
                                   "likely a server problem, try again in "
                                   "a few minutes:");
                    break;
                default:
                    str_reason = _("Message could not be sent "
                                   "because an error with "
                                   "the switchboard occurred:");
                    break;
            }
        }
        else
        {
            str_reason = _("Message may have not been sent "
                           "because an unknown error occurred:");
        }

        body_str = msn_message_to_string(msg);
        body_enc = g_markup_escape_text(body_str, -1);
        g_free(body_str);

        format = msn_message_get_attr(msg, "X-MMS-IM-Format");
        msn_parse_format(format, &pre, &post);
        body_str = g_strdup_printf("%s%s%s", pre ? pre : "",
                                   body_enc ? body_enc : "", post ? post : "");
        g_free(body_enc);
        g_free(pre);
        g_free(post);

        msn_switchboard_report_user(swboard, PURPLE_MESSAGE_ERROR,
                                    str_reason);
        msn_switchboard_report_user(swboard, PURPLE_MESSAGE_RAW,
                                    body_str);

        g_free(body_str);
    }

    /* If a timeout occurs we want the msg around just in case we
     * receive the ACK after the timeout. */
    if (msg->ack_ref && error != MSN_MSG_ERROR_TIMEOUT)
    {
        swboard->ack_list = g_list_remove(swboard->ack_list, msg);
        msn_message_unref(msg);
    }
}

/**************************************************************************
 * Message Stuff
 **************************************************************************/

/** Called when a message times out. */
static void
msg_timeout(MsnCmdProc *cmdproc, MsnTransaction *trans)
{
    MsnMessage *msg;

    msg = trans->data;

    msg_error_helper(cmdproc, msg, MSN_MSG_ERROR_TIMEOUT);
}

/** Called when we receive an error of a message. */
static void
msg_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    msg_error_helper(cmdproc, trans->data, MSN_MSG_ERROR_UNKNOWN);
}

#if 0
/** Called when we receive an ack of a special message. */
static void
msg_ack(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnMessage *msg;

    msg = cmd->trans->data;

    if (msg->ack_cb != NULL)
        msg->ack_cb(msg->ack_data);

    msn_message_unref(msg);
}

/** Called when we receive a nak of a special message. */
static void
msg_nak(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnMessage *msg;

    msg = cmd->trans->data;

    msn_message_unref(msg);
}
#endif

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

    if (msg->type == MSN_MSG_TEXT)
    {
        msg->ack_ref = TRUE;
        msn_message_ref(msg);
        swboard->ack_list = g_list_append(swboard->ack_list, msg);
        msn_transaction_set_timeout_cb(trans, msg_timeout);
    }
    else if (msg->type == MSN_MSG_SLP)
    {
        msg->ack_ref = TRUE;
        msn_message_ref(msg);
        swboard->ack_list = g_list_append(swboard->ack_list, msg);
        msn_transaction_set_timeout_cb(trans, msg_timeout);
#if 0
        if (msg->ack_cb != NULL)
        {
            msn_transaction_add_cb(trans, "ACK", msg_ack);
            msn_transaction_add_cb(trans, "NAK", msg_nak);
        }
#endif
    }

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

    g_queue_push_tail(swboard->msg_queue, msg);

    msn_message_ref(msg);
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
    g_return_if_fail(swboard);
    g_return_if_fail(msg     != NULL);

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

    if (swboard->to_close)
    {
        msn_switchboard_close(swboard);
        msn_switchboard_unref(swboard);
    }
}

static void
msg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
    MsnMessage *msg;

    msg = msn_message_new_from_cmd(cmd);

    msn_message_parse_payload(msg, payload, len);
#ifdef PECAN_DEBUG_SB
    msn_message_show_readable(msg, "SB RECV", FALSE);
#endif

    if (msg->remote_user != NULL)
        g_free (msg->remote_user);

    msg->remote_user = g_strdup(cmd->params[0]);
    msn_cmdproc_process_msg(cmdproc, msg);

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
    MsnMessage *msg;

    g_return_if_fail(cmd);
    g_return_if_fail(cmd->trans);

    msg = cmd->trans->data;

    g_return_if_fail(msg);

    msg_error_helper(cmdproc, msg, MSN_MSG_ERROR_NAK);
}

static void
ack_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSwitchBoard *swboard;
    MsnMessage *msg;

    g_return_if_fail(cmd);
    g_return_if_fail(cmd->trans);

    msg = cmd->trans->data;

    if (msg->ack_cb != NULL)
        msg->ack_cb(msg, msg->ack_data);

    swboard = cmdproc->data;
    if (swboard)
        swboard->ack_list = g_list_remove(swboard->ack_list, msg);
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
got_datacast_inform_user (MsnCmdProc *cmdproc,
                          const char *passport,
                          const char *str)
{
    PurpleAccount *account;
    MsnSwitchBoard *swboard;
    PnContact *contact;
    const char *friendly_name;
    gchar *new_str;

    account = msn_session_get_user_data (cmdproc->session);
    swboard = cmdproc->data;
    contact = pn_contactlist_find_contact(cmdproc->session->contactlist, passport);
    friendly_name = pn_contact_get_friendly_name(contact);
    if (!friendly_name)
        friendly_name = passport;

    new_str = g_strdup_printf("%s %s", friendly_name, str);

    /* Grab the conv for this swboard. If there isn't one and it's an IM then create it,
    otherwise the smileys won't work, this needs to be fixed. */
    if (!swboard->conv)
    {
        if (swboard->current_users > 1)
            swboard->conv = purple_find_chat(account->gc, swboard->chat_id);
        else
        {
            swboard->conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
                                                                  passport, account);
            if (!swboard->conv)
                swboard->conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, passport);
        }
    }

    purple_conversation_write(swboard->conv, NULL, new_str, PURPLE_MESSAGE_SYSTEM, time(NULL));

    g_free (new_str);
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
        str = g_strdup_printf (_("sent you a Messenger Plus! sound. Click <a href='file://%s'>here</a> to play it."), path_mp3);
#else
        str = g_strdup_printf (_("sent you a Messenger Plus! sound. Copy the following link in Safari to play it: %s"), path_mp3);
#endif /* ADIUM */
        got_datacast_inform_user (cmdproc, passport, str);

        fclose(f);

        g_free (path_mp3);
    }
    else
    {
        pn_error ("couldn't create temporany file to store the received Plus! sound!\n");

        str = g_strdup_printf (_("sent you a Messenger Plus! sound, but it cannot be played due to an error happened while storing the file."));
        got_datacast_inform_user (cmdproc, passport, str);
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
void
msn_handwritten_msg_show(MsnSwitchBoard *swboard, const char* msgid, const char* data, char* passport)
{
    guchar *guc;
    size_t body_len;
    PurpleAccount *account;
    PurpleConnection *connection;
    
    account = msn_session_get_user_data (swboard->session);
    connection = purple_account_get_connection (account);

    guc = purple_base64_decode(data, &body_len);
    if (!guc || !body_len) 
        return;
    
    /* Grab the conv for this swboard. If there isn't one and it's an IM then create it,
    otherwise the smileys won't work, this needs to be fixed. */
    if (swboard->conv == NULL)
    {
        if (swboard->current_users > 1) 
            swboard->conv = purple_find_chat(connection, swboard->chat_id);
        else
        {
            swboard->conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
                                    passport, account);
            if (swboard->conv == NULL)
                swboard->conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, passport);
        }
    }

    if (purple_conv_custom_smiley_add(swboard->conv, msgid, 0, "", 0)) {
        purple_conv_custom_smiley_write(swboard->conv, msgid, guc, body_len);
        purple_conv_custom_smiley_close(swboard->conv, msgid);
    }
    
    if (swboard->current_users > 1 ||
        ((swboard->conv != NULL) &&
         purple_conversation_get_type(swboard->conv) == PURPLE_CONV_TYPE_CHAT))
        serv_got_chat_in(connection, swboard->chat_id, passport, 0, msgid,
                         time(NULL));
    else
        serv_got_im(connection, passport, msgid, 0, time(NULL));

    g_free(guc);
}

static void
msn_handwritten_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    char *passport, *bodydup;
    const char *body, *msgid;
    size_t body_len;
    
    passport = msg->remote_user;
    msgid = msn_message_get_attr(msg, "Message-ID");

    body = msn_message_get_bin_data(msg, &body_len);
    bodydup = g_strndup(body+7, body_len-7);
    msn_handwritten_msg_show(cmdproc->data, msgid, bodydup, passport);
    g_free(bodydup);
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
got_voice_clip(MsnSlpCall *slpcall, const guchar *data, gsize size)
{
    FILE *f;
    char *file;
    gchar *str;

    if ((f = purple_mkstemp(&file, TRUE)))
    {
        gchar *decoded_file;

        fwrite(data, size, 1, f);
        fclose(f);

        decoded_file = g_strconcat (file, "_decoded.wav", NULL);

        pn_siren7_decode_file (file, decoded_file);

#ifndef ADIUM
        str = g_strdup_printf(_("sent you a voice clip. Click <a href='file://%s'>here</a> to play it."), decoded_file);
#else
        str = g_strdup_printf(_("sent you a voice clip. Copy the following link in Safari to play it: %s"), decoded_file);
#endif /* ADIUM */
        got_datacast_inform_user(slpcall->link->swboard->cmdproc, slpcall->link->remote_user, str);

        g_free (decoded_file);
    } else {
        pn_error ("couldn't create temporany file to store the received voice clip!\n");

        str = g_strdup_printf(_("sent you a voice clip, but it cannot be played due to an error happened while storing the file."));
        got_datacast_inform_user(slpcall->link->swboard->cmdproc, slpcall->link->remote_user, str);
    }

    g_free (str);
}
#endif /* defined(PECAN_LIBSIREN) */

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
        MsnSwitchBoard *swboard;

        swboard = cmdproc->data;

        if (swboard->current_users > 1 ||
            (swboard->conv &&
             purple_conversation_get_type (swboard->conv) == PURPLE_CONV_TYPE_CHAT))
            purple_prpl_got_attention_in_chat (connection, swboard->chat_id, passport, 0);
        else
            purple_prpl_got_attention (connection, passport, 0);
    }
    else if (strcmp (id, "2") == 0)
    {
        /* winks */
    }
    else if (strcmp (id, "3") == 0)
    {
#if defined(PECAN_LIBSIREN)
        const char *data;
        PnPeerLink *link;
        PnMsnObj *obj;

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

    params = g_strsplit(trans->params, " ", 0);
    passport = params[0];
    swboard = trans->data;
    g_return_if_fail (swboard);

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

    cal_error_helper(trans, reason);
}

void
msn_switchboard_request_add_user(MsnSwitchBoard *swboard, const char *user)
{
    MsnCmdProc *cmdproc;

    g_return_if_fail(swboard);

    cmdproc = swboard->cmdproc;

    if (!swboard->ready)
    {
        pn_warning ("not ready yet");
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
    swboard->conv = NULL;

    /* Don't let a write error destroy the switchboard before we do. */
    msn_switchboard_ref(swboard);

    if (swboard->chat_id)
        g_hash_table_remove (swboard->session->chats, GINT_TO_POINTER (swboard->chat_id));
    else
        g_hash_table_remove (swboard->session->conversations, swboard->im_user);

    if (swboard->error != MSN_SB_ERROR_NONE)
    {
        msn_switchboard_unref(swboard);
    }
    else if (g_queue_is_empty(swboard->msg_queue) ||
             !swboard->session->connected)
    {
        MsnCmdProc *cmdproc;

        cmdproc = swboard->cmdproc;

        msn_cmdproc_send_quick(cmdproc, "OUT", NULL, NULL);

        msn_switchboard_unref(swboard);
    }
    else
    {
        /* Messages are still pending */
        /* Destroy the switchboard when they are sent. */
        swboard->to_close = TRUE;
    }
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
                           msn_p2p_msg);
    msn_table_add_msg_type(cbs_table, "text/x-mms-emoticon",
                           msn_emoticon_msg);
    msn_table_add_msg_type(cbs_table, "text/x-mms-animemoticon",
                           msn_emoticon_msg);
    msn_table_add_msg_type(cbs_table, "image/gif",
                           msn_handwritten_msg);
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
