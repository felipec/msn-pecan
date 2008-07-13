/**
 * Copyright (C) 2007-2008 Felipe Contreras
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "notification.h"
#include "pecan_log.h"
#include "sync.h"
#include "nexus.h"

#include "session.h"
#include "session_private.h"

#include "cmd/cmdproc_private.h"
#include "cmd/command_private.h"
#include "cmd/transaction_private.h"
#include "cmd/msg_private.h"

#include "ab/pecan_contactlist.h"
#include "ab/pecan_contactlist_priv.h"
#include "ab/pecan_contact_priv.h"

#include "io/pecan_cmd_server.h"
#include "io/pecan_http_server.h"
#include "io/pecan_node_priv.h"
#include "io/pecan_cmd_server_priv.h"

#include "cvr/slplink.h" /* for slplink_destroy */

#include "error.h" /* for error_get_text */
#include "pecan_util.h" /* for parse_socket */

#include "msn_intl.h"

#include <glib/gstdio.h>

#include <string.h>

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <account.h>
#include <cipher.h>

static MsnTable *cbs_table;

typedef struct
{
    gchar *who;
    gchar *group_guid;
} MsnAddBuddy;

static void
open_cb (PecanNode *conn,
         MsnNotification *notification)
{
    MsnSession *session;
    PecanCmdServer *cmd_conn;

    g_return_if_fail (conn != NULL);

    pecan_log ("begin");

    session = conn->session;
    cmd_conn = CMD_PECAN_NODE (conn);

    if (session->login_step == PECAN_LOGIN_STEP_START)
        msn_session_set_login_step (session, PECAN_LOGIN_STEP_HANDSHAKE);
    else
        msn_session_set_login_step (session, PECAN_LOGIN_STEP_HANDSHAKE2);

    msn_cmdproc_send (cmd_conn->cmdproc, "VER", "MSNP12 CVR0");

    pecan_log ("end");
}

static void
close_cb (PecanNode *conn,
          MsnNotification *notification)
{
    char *tmp;

    {
        const char *reason = NULL;

        if (conn->error)
        {
            reason = conn->error->message;

            pecan_error ("connection error: (NS):reason=[%s]", reason);
            tmp = pecan_strdup_printf (_("Error on notification server:\n%s"), reason);

            g_clear_error (&conn->error);
        }
        else
        {
            pecan_error ("connection error: (NS)");
            tmp = pecan_strdup_printf (_("Error on notification server:\nUnknown"));
        }
    }

    pecan_node_close (PECAN_NODE (notification->conn));
    notification->closed = TRUE;
    msn_session_set_error (notification->session, MSN_ERROR_SERVCONN, tmp);

    g_free (tmp);
}

/**************************************************************************
 * Main
 **************************************************************************/

static void
error_handler (MsnCmdProc *cmdproc,
               MsnTransaction *trans,
               gint error)
{
    MsnNotification *notification;
    gchar *reason;

    notification = cmdproc->data;
    g_return_if_fail (notification);

    reason = msn_error_get_text (error);
    pecan_error ("connection error: (NS):reason=[%s]", reason);

    switch (error)
    {
        case 913:
        case 208:
            /* non-fatal */
            break;
        default:
            {
                char *tmp;
                tmp = pecan_strdup_printf (_("Error on notification server:\n%s"), reason);
                msn_session_set_error (notification->session, MSN_ERROR_SERVCONN, tmp);
                g_free (tmp);
            }
    }

    g_free (reason);
}

MsnNotification *
msn_notification_new(MsnSession *session)
{
    MsnNotification *notification;

    g_return_val_if_fail(session != NULL, NULL);

    notification = g_new0(MsnNotification, 1);

    notification->session = session;

    {
        PecanNode *conn;
        notification->conn = pecan_cmd_server_new ("notification server", PECAN_NODE_NS);
        conn = PECAN_NODE (notification->conn);

        {
            MsnCmdProc *cmdproc;
            cmdproc = notification->conn->cmdproc;
            cmdproc->session = session;
            cmdproc->cbs_table = cbs_table;
            cmdproc->conn = conn;
            cmdproc->error_handler = error_handler;
            cmdproc->data = notification;

            notification->cmdproc = cmdproc;
        }

        conn->session = session;

        if (session->http_method)
        {
            if (session->http_conn)
            {
                /* A single http connection shared by all nodes */
                pecan_node_link (conn, session->http_conn);
            }
            else
            {
                /* Each node has it's own http connection. */
                PecanNode *foo;

                foo = PECAN_NODE (pecan_http_server_new ("foo server"));
                foo->session = session;
                pecan_node_link (conn, foo);
                g_object_unref (foo);
            }
        }

        notification->open_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), notification);
        notification->close_handler = g_signal_connect (conn, "close", G_CALLBACK (close_cb), notification);
        notification->error_handler = g_signal_connect (conn, "error", G_CALLBACK (close_cb), notification);
    }

    return notification;
}

void
msn_notification_destroy(MsnNotification *notification)
{
    if (notification->cmdproc)
        notification->cmdproc->data = NULL;

    g_signal_handler_disconnect (notification->conn, notification->open_handler);
    g_signal_handler_disconnect (notification->conn, notification->close_handler);
    g_signal_handler_disconnect (notification->conn, notification->error_handler);

    pecan_cmd_server_free (notification->conn);

    g_free(notification);
}

/**************************************************************************
 * Connect
 **************************************************************************/

gboolean
msn_notification_connect(MsnNotification *notification, const char *host, int port)
{
    g_return_val_if_fail(notification != NULL, FALSE);

    pecan_node_connect (PECAN_NODE (notification->conn), host, port);

    return TRUE;
}

/**************************************************************************
 * Util
 **************************************************************************/

static void
group_error_helper(MsnSession *session, const char *msg, const gchar *group_guid, int error)
{
    PurpleAccount *account;
    PurpleConnection *gc;
    char *reason = NULL;
    char *title = NULL;

    account = session->account;
    gc = purple_account_get_connection(account);

    if (error == 224)
    {
        const char *group_name;
        group_name = pecan_contactlist_find_group_name(session->contactlist, group_guid);
        reason = pecan_strdup_printf(_("%s is not a valid group."),
                                     group_name);
    }
    else
    {
        reason = g_strdup(_("Unknown error."));
    }

    title = pecan_strdup_printf(_("%s on %s (%s)"), msg,
                                purple_account_get_username(account),
                                purple_account_get_protocol_name(account));
    purple_notify_error(gc, NULL, title, reason);
    g_free(title);
    g_free(reason);
}

/**************************************************************************
 * Login
 **************************************************************************/

void
msn_got_login_params(MsnSession *session, const char *login_params)
{
    MsnCmdProc *cmdproc;

    cmdproc = session->notification->cmdproc;

    msn_session_set_login_step(session, PECAN_LOGIN_STEP_AUTH_END);

    {
        gchar **tokens;
        tokens = g_strsplit (login_params, "&", 2);
        session->passport_cookie.t = g_strdup (tokens[0] + 2);
        session->passport_cookie.p = g_strdup (tokens[1] + 2);
        g_strfreev (tokens);
    }

    msn_cmdproc_send(cmdproc, "USR", "TWN S %s", login_params);
}

static void
cvr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    msn_cmdproc_send(cmdproc, "USR", "TWN I %s",
                     msn_session_get_username(cmdproc->session));
}

static void
usr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    PurpleAccount *account;
    PurpleConnection *gc;

    session = cmdproc->session;
    account = session->account;
    gc = purple_account_get_connection(account);

    if (!g_ascii_strcasecmp(cmd->params[1], "OK"))
    {
        /* OK */
        msn_session_set_login_step(session, PECAN_LOGIN_STEP_SYN);

        msn_cmdproc_send(cmdproc, "SYN", "%s %s", "0", "0");
    }
    else if (!g_ascii_strcasecmp(cmd->params[1], "TWN"))
    {
        /* Passport authentication */
        char **elems, **cur, **tokens;

        session->nexus = msn_nexus_new(session);

        /* Parse the challenge data. */

        elems = g_strsplit(cmd->params[3], ",", 0);

        for (cur = elems; *cur != NULL; cur++)
        {
            tokens = g_strsplit(*cur, "=", 2);
            g_hash_table_insert(session->nexus->challenge_data, tokens[0], tokens[1]);
            /* Don't free each of the tokens, only the array. */
            g_free(tokens);
        }

        g_strfreev(elems);

        msn_session_set_login_step(session, PECAN_LOGIN_STEP_AUTH_START);

        msn_nexus_connect(session->nexus);
    }
}

static void
usr_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    MsnErrorType msnerr = 0;

    switch (error)
    {
        case 500:
        case 601:
        case 910:
        case 921:
            msnerr = MSN_ERROR_SERV_UNAVAILABLE;
            break;
        case 911:
            msnerr = MSN_ERROR_AUTH;
            break;
        default:
            return;
            break;
    }

    msn_session_set_error(cmdproc->session, msnerr, NULL);
}

static void
ver_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    gboolean protocol_supported = FALSE;
    const gchar *proto_str;
    guint i;

    session = cmdproc->session;

    proto_str = "MSNP12";

    for (i = 1; i < cmd->param_count; i++)
    {
        if (!strcmp(cmd->params[i], proto_str))
        {
            protocol_supported = TRUE;
            break;
        }
    }

    if (!protocol_supported)
    {
        msn_session_set_error(session, MSN_ERROR_UNSUPPORTED_PROTOCOL,
                              NULL);
        return;
    }

    msn_cmdproc_send(cmdproc, "CVR",
                     "0x0409 winnt 5.1 i386 MSNMSGR 6.0.0602 MSMSGS %s",
                     msn_session_get_username(session));
}

/**************************************************************************
 * Log out
 **************************************************************************/

static void
out_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    if (!g_ascii_strcasecmp(cmd->params[0], "OTH"))
        msn_session_set_error(cmdproc->session, MSN_ERROR_SIGN_OTHER,
                              NULL);
    else if (!g_ascii_strcasecmp(cmd->params[0], "SSD"))
        msn_session_set_error(cmdproc->session, MSN_ERROR_SERV_DOWN, NULL);
}

void
msn_notification_close(MsnNotification *notification)
{
    g_return_if_fail(notification != NULL);

    if (!notification->closed)
    {
        msn_cmdproc_send_quick (notification->cmdproc, "OUT", NULL, NULL);
        pecan_node_close (PECAN_NODE (notification->conn));
    }
}

/**************************************************************************
 * Messages
 **************************************************************************/

static void
msg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
             size_t len)
{
    MsnMessage *msg;

    msg = msn_message_new_from_cmd(cmd);

    msn_message_parse_payload(msg, payload, len);
#ifdef PECAN_DEBUG_NS
    msn_message_show_readable(msg, "Notification", TRUE);
#endif

    msn_cmdproc_process_msg(cmdproc, msg);

    msn_message_destroy(msg);
}

static void
msg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    /* NOTE: cmd is not always cmdproc->last_cmd, sometimes cmd is a queued
     * command and we are processing it */

    if (cmd->payload == NULL)
    {
        cmdproc->last_cmd->payload_cb  = msg_cmd_post;
        cmd->payload_len = atoi(cmd->params[2]);
    }
    else
    {
        g_return_if_fail(cmd->payload_cb != NULL);

        cmd->payload_cb(cmdproc, cmd, cmd->payload, cmd->payload_len);
    }
}

/**************************************************************************
 * Challenges
 **************************************************************************/

static void
chl_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnTransaction *trans;
    gchar buf[32];

#if 0
    PurpleCipher *cipher;
    PurpleCipherContext *context;
    guchar digest[16];
    const char *challenge_resp;
    int i;

    cipher = purple_ciphers_find_cipher("md5");
    context = purple_cipher_context_new(cipher, NULL);

    purple_cipher_context_append(context, (const guchar *)cmd->params[1],
                                 strlen(cmd->params[1]));

    challenge_resp = "VT6PX?UQTM4WM%YR";

    purple_cipher_context_append(context, (const guchar *)challenge_resp,
                                 strlen(challenge_resp));
    purple_cipher_context_digest(context, sizeof(digest), digest, NULL);
    purple_cipher_context_destroy(context);

    for (i = 0; i < 16; i++)
        g_snprintf(buf + (i*2), 3, "%02x", digest[i]);
#else
    pecan_handle_challenge (cmd->params[1], "PROD0101{0RM?UBW", buf);
#endif

    /* trans = msn_transaction_new(cmdproc, "QRY", "%s 32", "PROD0038W!61ZTF9"); */
    trans = msn_transaction_new (cmdproc, "QRY", "%s 32", "PROD0101{0RM?UBW");

    msn_transaction_set_payload (trans, buf, 32);

    msn_cmdproc_send_trans (cmdproc, trans);
}

/**************************************************************************
 * Buddy Lists
 **************************************************************************/

static void
adc_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    PecanContact *user = NULL;
    const gchar *list = NULL;
    const gchar *passport = NULL;
    gchar *friendly = NULL;
    const gchar *user_guid = NULL;
    const gchar *group_guid = NULL;
    MsnListId list_id;
    guint i = 1;

    list = cmd->params[i++];

    for (; i < cmd->param_count; i++)
    {
        const char *chopped_str;

        chopped_str = cmd->params[i] + 2;

        /* Check for Name/email. */
        if (strncmp (cmd->params[i], "N=", 2) == 0)
            passport = chopped_str;
        /* Check for Friendlyname. */
        else if (strncmp (cmd->params[i], "F=", 2) == 0)
            friendly = pecan_url_decode (chopped_str);
        /* Check for Contact GUID. */
        else if (strncmp (cmd->params[i], "C=", 2) == 0)
            user_guid = chopped_str;
        else
            break;
    }

    group_guid = cmd->params[i++];

    session = cmdproc->session;

    if (passport)
        user = pecan_contactlist_find_contact (session->contactlist, passport);
    else if (user_guid)
        user = pecan_contactlist_find_contact_by_guid (session->contactlist, user_guid);

    if (user == NULL)
    {
        user = pecan_contact_new (session->contactlist);
        pecan_contact_set_passport (user, passport);
    }

    list_id = msn_get_list_id(list);

    if (list_id == MSN_LIST_FL)
        pecan_contact_set_guid (user, user_guid);

    msn_got_add_contact(session, user, list_id, group_guid);

    /* There is a user that must me moved to this group */
    if (cmd->trans && cmd->trans->data)
    {
        MsnAddBuddy *data = cmd->trans->data;

        msn_notification_add_buddy (session->notification, "FL", data->who,
                                    user_guid, friendly, data->group_guid);

        g_free (data->who);
        g_free (data->group_guid);
    }

    pecan_contact_update(user);

    g_free (friendly);
}

static void
adc_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    MsnSession *session;
    PurpleAccount *account;
    PurpleConnection *gc;
    const char *list, *passport;
    const char *reason;
    char *msg = NULL;
    char **params;

    session = cmdproc->session;
    account = session->account;
    gc = purple_account_get_connection(account);
    params = g_strsplit(trans->params, " ", 0);

    list     = params[0];
    passport = params[1];

    if (!strcmp(list, "FL"))
        msg = pecan_strdup_printf(_("Unable to add user on %s (%s)"),
                                  purple_account_get_username(account),
                                  purple_account_get_protocol_name(account));
    else if (!strcmp(list, "BL"))
        msg = pecan_strdup_printf(_("Unable to block user on %s (%s)"),
                                  purple_account_get_username(account),
                                  purple_account_get_protocol_name(account));
    else if (!strcmp(list, "AL"))
        msg = pecan_strdup_printf(_("Unable to permit user on %s (%s)"),
                                  purple_account_get_username(account),
                                  purple_account_get_protocol_name(account));

    reason = msn_error_get_text(error);

    if (msg != NULL)
    {
        purple_notify_error(gc, NULL, msg, reason);
        g_free(msg);
    }

    if (!strcmp(list, "FL"))
    {
        PurpleBuddy *buddy;

        buddy = purple_find_buddy(account, passport);

        if (buddy != NULL)
            purple_blist_remove_buddy(buddy);
    }

    g_strfreev(params);
}

static void
adg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    const gchar *group_guid;
    char *group_name;

    session = cmdproc->session;

    group_guid = cmd->params[2];

    group_name = pecan_url_decode(cmd->params[1]);

    pecan_group_new(session->contactlist, group_name, group_guid);

    /* There is a user that must me moved to this group */
    if (cmd->trans && cmd->trans->data)
    {
        /* pecan_contactlist_move_buddy(); */
        PecanContactList *contactlist = cmdproc->session->contactlist;
        MsnMoveBuddy *data = cmd->trans->data;

        pecan_contactlist_add_buddy(contactlist, data->who, MSN_LIST_FL, group_name);
        g_free(data->who);

        if (data->old_group_guid != NULL)
        {
            pecan_contactlist_rem_buddy(contactlist, data->who, MSN_LIST_FL, data->old_group_guid);
            g_free(data->old_group_guid);
        }
        g_free (data);
    }

    g_free (group_name);
}

static void
qng_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    /** @todo set the png timeout to the argument of this command */
}

static void
fln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSlpLink *slplink;
    PecanContact *user;

    user = pecan_contactlist_find_contact(cmdproc->session->contactlist, cmd->params[0]);
    pecan_contact_set_state(user, NULL);
    pecan_contact_update(user);

    slplink = msn_session_find_slplink(cmdproc->session, cmd->params[0]);

    if (slplink != NULL)
        msn_slplink_destroy(slplink);

}

static void
iln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    PurpleAccount *account;
    PurpleConnection *gc;
    PecanContact *user;
    MsnObject *msnobj;
    const char *state, *passport;
    gchar *friendly;

    session = cmdproc->session;
    account = session->account;
    gc = purple_account_get_connection(account);

    state    = cmd->params[1];
    passport = cmd->params[2];
    friendly = pecan_url_decode(cmd->params[3]);

    user = pecan_contactlist_find_contact(session->contactlist, passport);

    pecan_contact_set_friendly_name(user, friendly);

    if (cmd->param_count >= 5)
    {
        gulong client_id;
        client_id = atol (cmd->params[4]);
        pecan_contact_set_client_id (user, client_id);
    }

    if (session->protocol_ver >= 9 && cmd->param_count == 6)
    {
        gchar *tmp;
        tmp = pecan_url_decode (cmd->params[5]);
        msnobj = msn_object_new_from_string (tmp);
        pecan_contact_set_object(user, msnobj);
        g_free (tmp);
    }

    pecan_contact_set_state(user, state);
    pecan_contact_update(user);

    g_free (friendly);
}

static void
ipg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
    pecan_info ("incoming page: [%s]", payload);
}

static void
ipg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    cmd->payload_len = atoi(cmd->params[0]);
    cmdproc->last_cmd->payload_cb = ipg_cmd_post;
}

static void
nln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    PurpleAccount *account;
    PurpleConnection *gc;
    PecanContact *user;
    MsnObject *msnobj;
    int clientid;
    const char *state, *passport;
    gchar *friendly;

    session = cmdproc->session;
    account = session->account;
    gc = purple_account_get_connection(account);

    state    = cmd->params[0];
    passport = cmd->params[1];
    friendly = pecan_url_decode(cmd->params[2]);

    user = pecan_contactlist_find_contact(session->contactlist, passport);

    if (!user)
    {
        pecan_error ("unknown user: passport=[%s]", passport);
        return;
    }

    pecan_contact_set_friendly_name(user, friendly);

    if (cmd->param_count == 5)
    {
        gchar *tmp;
        tmp = pecan_url_decode(cmd->params[4]);
        msnobj = msn_object_new_from_string(tmp);
        pecan_contact_set_object(user, msnobj);
        g_free (tmp);
    }
    else
    {
        pecan_contact_set_object(user, NULL);
    }

    clientid = atoi(cmd->params[3]);
    user->mobile = (clientid & MSN_CLIENT_CAP_MSNMOBILE);

    pecan_contact_set_state(user, state);
    pecan_contact_update(user);

    /* store the friendly name on the server. */
    if (!session->server_alias)
        msn_cmdproc_send (cmdproc, "SBP", "%s %s %s", pecan_contact_get_guid (user), "MFN", friendly);

    g_free (friendly);
}

#if 0
static void
chg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    char *state = cmd->params[1];
    int state_id = 0;

    if (!strcmp(state, "NLN"))
        state_id = MSN_ONLINE;
    else if (!strcmp(state, "BSY"))
        state_id = MSN_BUSY;
    else if (!strcmp(state, "IDL"))
        state_id = MSN_IDLE;
    else if (!strcmp(state, "BRB"))
        state_id = MSN_BRB;
    else if (!strcmp(state, "AWY"))
        state_id = MSN_AWAY;
    else if (!strcmp(state, "PHN"))
        state_id = MSN_PHONE;
    else if (!strcmp(state, "LUN"))
        state_id = MSN_LUNCH;
    else if (!strcmp(state, "HDN"))
        state_id = MSN_HIDDEN;

    cmdproc->session->state = state_id;
}
#endif


static void
not_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
}

static void
not_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    cmd->payload_len = atoi(cmd->params[0]);
    cmdproc->last_cmd->payload_cb = not_cmd_post;
}

#if 0
static void
rea_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    const char *who;
    const char *alias;

    session = cmdproc->session;
    who = cmd->params[2];
    alias = purple_url_decode(cmd->params[3]);

    if (strcmp(who, purple_account_get_username (session->account)) == 0)
    {
        /* This is for us. */
        PurpleConnection *gc;
        gc = session->account->gc;
        purple_connection_set_display_name(gc, alias);
    }
    else
    {
        /* This is for a buddy. */
        PecanContact *user;
        user = pecan_contactlist_find_contact(session->contactlist, who);
        if (user)
        {
            pecan_contact_set_store_name(user, alias);
        }
        else
        {
            pecan_error ("unknown user: who=[%s]", who);
            return;
        }
    }
}
#endif

static void
sbp_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session;
    const gchar *contact_guid;
    const gchar *type;
    const gchar *value;
    PecanContact *contact;

    session = cmdproc->session;
    contact_guid = cmd->params[1];
    type = cmd->params[2];
    value = cmd->params[3];

    contact = pecan_contactlist_find_contact_by_guid (session->contactlist, contact_guid);

    if (contact)
    {
        if (strcmp (type, "MFN") == 0)
        {
            gchar *tmp;
            tmp = pecan_url_decode (value);
            if (session->server_alias)
                pecan_contact_set_store_name (contact, tmp);
            g_free (tmp);
        }
    }
}

static void
prp_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session = cmdproc->session;
    PurpleConnection *gc = session->account->gc;
    const gchar *type, *value;
    PecanContact *user;

    g_return_if_fail(cmd->param_count >= 3);

    type = cmd->params[1];
    user = msn_session_get_contact (session);

    if (cmd->param_count == 3)
    {
        gchar *tmp;
        value = cmd->params[2];
        tmp = pecan_url_decode (value);
        if (!strcmp(type, "PHH"))
            pecan_contact_set_home_phone(user, tmp);
        else if (!strcmp(type, "PHW"))
            pecan_contact_set_work_phone(user, tmp);
        else if (!strcmp(type, "PHM"))
            pecan_contact_set_mobile_phone(user, tmp);
        else if (!strcmp(type, "MFN"))
            purple_connection_set_display_name(gc, tmp);
        g_free (tmp);
    }
    else
    {
        if (!strcmp(type, "PHH"))
            pecan_contact_set_home_phone(user, NULL);
        else if (!strcmp(type, "PHW"))
            pecan_contact_set_work_phone(user, NULL);
        else if (!strcmp(type, "PHM"))
            pecan_contact_set_mobile_phone(user, NULL);
    }
}

static void
reg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    const gchar *group_guid;
    char *group_name;

    session = cmdproc->session;
    group_guid = cmd->params[1];
    group_name = pecan_url_decode(cmd->params[2]);

    pecan_contactlist_rename_group_id(session->contactlist, group_guid, group_name);

    g_free (group_name);
}

static void
reg_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    const gchar *group_guid;
    char **params;

    params = g_strsplit(trans->params, " ", 0);

    group_guid = params[0];

    group_error_helper(cmdproc->session, _("Unable to rename group"), group_guid, error);

    g_strfreev(params);
}

static void
rem_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    PecanContact *user;
    const char *list;
    const gchar *user_id; /* passport or guid */
    MsnListId list_id;
    const gchar *group_guid;

    session = cmdproc->session;
    list = cmd->params[1];
    user_id = cmd->params[2];

    if (strcmp (list, "FL") == 0)
        user = pecan_contactlist_find_contact_by_guid (session->contactlist, user_id);
    else
        user = pecan_contactlist_find_contact (session->contactlist, user_id);

    g_return_if_fail(user != NULL);

    list_id = msn_get_list_id(list);

    if (cmd->param_count == 4)
        group_guid = cmd->params[3];
    else
        group_guid = NULL;

    msn_got_rem_contact(session, user, list_id, group_guid);
    pecan_contact_update(user);
}

static void
rmg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    const gchar *group_guid;

    session = cmdproc->session;
    group_guid = cmd->params[1];

    pecan_contactlist_remove_group_id(session->contactlist, group_guid);
}

static void
rmg_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    const gchar *group_guid;
    char **params;

    params = g_strsplit(trans->params, " ", 0);

    group_guid = params[0];

    group_error_helper(cmdproc->session, _("Unable to delete group"), group_guid, error);

    g_strfreev(params);
}

static void
syn_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    MsnSync *sync;
    int total_users;

    session = cmdproc->session;

    if (cmd->param_count == 2)
    {
        /*
         * This can happen if we sent a SYN with an up-to-date
         * buddy list revision, but we send 0 to get a full list.
         * So, error out.
         */

        msn_session_set_error(cmdproc->session, MSN_ERROR_BAD_BLIST, NULL);
        return;
    }

    total_users  = atoi(cmd->params[3]);

    sync = msn_sync_new(session);
    sync->total_users = total_users;
    sync->old_cbs_table = cmdproc->cbs_table;

    session->sync = sync;
    cmdproc->cbs_table = sync->cbs_table;
}

static void
ubx_cmd_post (MsnCmdProc *cmdproc,
              MsnCommand *cmd,
              gchar *payload,
              gsize len)
{
    MsnSession *session;
    PecanContact *contact;
    const gchar *passport;

    session = cmdproc->session;

    passport = cmd->params[0];
    contact = pecan_contactlist_find_contact (session->contactlist, passport);

    if (contact)
    {
        gchar *psm = NULL;
        const gchar *start;
        const gchar *end;

        start = g_strstr_len (payload, len, "<PSM>");
        if (start)
        {
            start += 5;
            end = g_strstr_len (start, len - (start - payload), "</PSM>");

            /*check that the closing <PSM> tag is there, and that the PSM isn't empty*/
	    if (end > start)
                psm = g_strndup (start, end - start);
        }

        pecan_contact_set_personal_message (contact, psm);
        g_free (psm);

        pecan_contact_update (contact);
    }
}

static void
ubx_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    cmdproc->last_cmd->payload_cb = ubx_cmd_post;
    cmd->payload_len = atoi (cmd->params[1]);
}

/**************************************************************************
 * Misc commands
 **************************************************************************/

static void
url_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session;
    PurpleConnection *connection;
    const gchar *rru;
    const gchar *url;
    gchar creds[64];
    glong tmp_timestamp;

    session = cmdproc->session;
    connection = purple_account_get_connection (session->account);

    rru = cmd->params[1];
    url = cmd->params[2];

    session->passport_info.mail_url_timestamp = time (NULL);
    tmp_timestamp = session->passport_info.mail_url_timestamp - session->passport_info.sl;

    {
        PurpleCipher *cipher;
        PurpleCipherContext *context;
        guchar digest[16];
        gchar *buf;

        buf = pecan_strdup_printf ("%s%ld%s",
                                   session->passport_info.mspauth ? session->passport_info.mspauth : "BOGUS",
                                   tmp_timestamp,
                                   purple_connection_get_password (connection));

        cipher = purple_ciphers_find_cipher ("md5");
        context = purple_cipher_context_new (cipher, NULL);

        purple_cipher_context_append (context, (const guchar *) buf, strlen (buf));
        purple_cipher_context_digest (context, sizeof (digest), digest, NULL);
        purple_cipher_context_destroy (context);

        g_free (buf);

        memset (creds, 0, sizeof (creds));

        {
            gchar buf2[3];
            gint i;

            for (i = 0; i < 16; i++)
            {
                g_snprintf (buf2, sizeof (buf2), "%02x", digest[i]);
                strcat (creds, buf2);
            }
        }
    }

    g_free (session->passport_info.mail_url);

    session->passport_info.mail_url = g_strdup_printf ("%s&auth=%s&creds=%s&sl=%ld&username=%s&mode=ttl&sid=%s&id=2&rru=%ssvc_mail&js=yes",
                                                       url,
                                                       session->passport_info.mspauth,
                                                       creds,
                                                       tmp_timestamp,
                                                       msn_session_get_username (session),
                                                       session->passport_info.sid,
                                                       rru);

    /* The user wants to check his email */
    if (cmd->trans && cmd->trans->data)
    {
        purple_notify_uri (connection, session->passport_info.mail_url);
        return;
    }

    if (purple_account_get_check_mail (session->account))
    {
        static gboolean is_initial = TRUE;

        if (!is_initial)
            return;

        if (session->inbox_unread_count > 0)
        {
            const gchar *passport;
            const gchar *main_url;

            passport = msn_session_get_username (session);
            main_url = session->passport_info.mail_url;

            purple_notify_emails (connection, session->inbox_unread_count, FALSE, NULL, NULL,
                                  &passport, &main_url, NULL, NULL);
        }

        is_initial = FALSE;
    }
}

/**************************************************************************
 * Switchboards
 **************************************************************************/

static void
rng_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;
    const char *session_id;
    char *host;
    int port;

    session = cmdproc->session;
    session_id = cmd->params[0];

    msn_parse_socket(cmd->params[1], &host, &port);

    swboard = msn_switchboard_new(session);

    msn_switchboard_set_invited(swboard, TRUE);
    msn_switchboard_set_session_id(swboard, cmd->params[0]);
    msn_switchboard_set_auth_key(swboard, cmd->params[3]);
    swboard->im_user = g_strdup(cmd->params[4]);
    /* msn_switchboard_add_user(swboard, cmd->params[4]); */

    if (!msn_switchboard_connect(swboard, host, port))
        msn_switchboard_destroy(swboard);

    g_free(host);
}

static void
xfr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    char *host;
    int port;

    if (strcmp(cmd->params[1], "SB") && strcmp(cmd->params[1], "NS"))
    {
        /* Maybe we can have a generic bad command error. */
        pecan_error ("bad XFR command: params=[%s]", cmd->params[1]);
        return;
    }

    msn_parse_socket(cmd->params[2], &host, &port);

    if (!strcmp(cmd->params[1], "SB"))
    {
        pecan_error ("this shouldn't be handled here");
    }
    else if (!strcmp(cmd->params[1], "NS"))
    {
        MsnSession *session;

        session = cmdproc->session;

        msn_session_set_login_step(session, PECAN_LOGIN_STEP_TRANSFER);

        msn_notification_connect(session->notification, host, port);
    }

    g_free(host);
}

/**************************************************************************
 * Message Types
 **************************************************************************/

static void
profile_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    MsnSession *session;
    const char *value;

    session = cmdproc->session;

    if (strcmp(msg->remote_user, "Hotmail"))
    {
        pecan_warning ("unofficial message");
        return;
    }

    if ((value = msn_message_get_attr(msg, "kv")) != NULL)
    {
        g_free(session->passport_info.kv);
        session->passport_info.kv = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "sid")) != NULL)
    {
        g_free(session->passport_info.sid);
        session->passport_info.sid = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "MSPAuth")) != NULL)
    {
        g_free(session->passport_info.mspauth);
        session->passport_info.mspauth = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "ClientIP")) != NULL)
    {
        g_free(session->passport_info.client_ip);
        session->passport_info.client_ip = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "ClientPort")) != NULL)
        session->passport_info.client_port = g_ntohs(atoi(value));

    if ((value = msn_message_get_attr(msg, "LoginTime")) != NULL)
        session->passport_info.sl = atol(value);

    if ((value = msn_message_get_attr(msg, "EmailEnabled")) != NULL)
        session->passport_info.email_enabled = atol(value);
}

static void
initial_mdata_msg (MsnCmdProc *cmdproc,
                   MsnMessage *msg)
{
    MsnSession *session;
    PurpleConnection *gc;
    GHashTable *table;

    session = cmdproc->session;
    gc = session->account->gc;

    if (strcmp (msg->remote_user, "Hotmail"))
    {
        pecan_warning ("unofficial message");
        return;
    }

    table = msn_message_get_hashtable_from_body (msg);

    {
        gchar *mdata;
        mdata = g_hash_table_lookup (table, "Mail-Data");

        if (mdata)
        {
            gchar *iu = NULL;
            const gchar *start;
            const gchar *end;
            guint len;

            len = strlen (mdata);
            start = g_strstr_len (mdata, len, "<IU>");

            if (start)
            {
                start += strlen ("<IU>");
                end = g_strstr_len (start, len - (start - mdata), "</IU>");

                if (end > start)
                    iu = g_strndup (start, end - start);
            }

            if (iu)
            {
                session->inbox_unread_count = atoi (iu);

                g_free (iu);
            }

            do
            {
                start = g_strstr_len (start, len - (start - mdata), "<M>");

                if (start)
                {
                    start += strlen ("<M>");
                    end = g_strstr_len (start, len - (start - mdata), "</M>");

                    if (end > start)
                    {
#if 0
                        {
                            gchar *field;
                            gchar *tmp;
                            tmp = pecan_get_xml_field ("N", start, end);
                            field = purple_mime_decode_field (tmp);
                            g_print ("field={%s}\n", field);
                            g_free (field);
                            g_free (tmp);
                        }
#endif

                        {
                            gchar *passport;
                            gchar *message_id;

                            passport = pecan_get_xml_field ("E", start, end);

                            message_id = pecan_get_xml_field ("I", start, end);

                            pecan_oim_session_request (session->oim_session,
                                                       passport,
                                                       message_id);

                            g_free (passport);
                            g_free (message_id);
                        }

                        start = end + strlen ("</M>");
                    }
                }
            } while (start);
        }

        if (purple_account_get_check_mail (session->account) &&
            session->passport_info.email_enabled == 1)
        {
            msn_cmdproc_send (cmdproc, "URL", "%s", "INBOX");
        }
    }

    g_hash_table_destroy(table);
}

static void
email_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    MsnSession *session;
    PurpleConnection *gc;
    GHashTable *table;
    char *from, *subject, *tmp;

    session = cmdproc->session;
    gc = session->account->gc;

    if (!purple_account_get_check_mail (session->account))
        return;

    if (strcmp(msg->remote_user, "Hotmail"))
    {
        pecan_warning ("unofficial message");
        return;
    }

    if (!session->passport_info.mail_url)
    {
        pecan_error ("no url");
        return;
    }


    table = msn_message_get_hashtable_from_body(msg);

    from = subject = NULL;

    tmp = g_hash_table_lookup(table, "From");
    if (tmp != NULL)
        from = purple_mime_decode_field(tmp);

    tmp = g_hash_table_lookup(table, "Subject");
    if (tmp != NULL)
        subject = purple_mime_decode_field(tmp);

    /** @todo go to the extact email */
    purple_notify_email(gc,
                        (subject != NULL ? subject : ""),
                        (from != NULL ?  from : ""),
                        msn_session_get_username (session),
                        session->passport_info.mail_url, NULL, NULL);

    g_free(from);
    g_free(subject);

    g_hash_table_destroy(table);
}

static void
system_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    GHashTable *table;
    const char *type_s;

    if (strcmp(msg->remote_user, "Hotmail"))
    {
        pecan_warning ("unofficial message");
        return;
    }

    table = msn_message_get_hashtable_from_body(msg);

    if ((type_s = g_hash_table_lookup(table, "Type")) != NULL)
    {
        int type = atoi(type_s);
        char buf[MSN_BUF_LEN];
        int minutes;

        switch (type)
        {
            case 1:
                minutes = atoi(g_hash_table_lookup(table, "Arg1"));
                g_snprintf(buf, sizeof(buf), dngettext(PACKAGE, 
                                                       "The MSN server will shut down for maintenance "
                                                       "in %d minute. You will automatically be "
                                                       "signed out at that time.  Please finish any "
                                                       "conversations in progress.\n\nAfter the "
                                                       "maintenance has been completed, you will be "
                                                       "able to successfully sign in.",
                                                       "The MSN server will shut down for maintenance "
                                                       "in %d minutes. You will automatically be "
                                                       "signed out at that time.  Please finish any "
                                                       "conversations in progress.\n\nAfter the "
                                                       "maintenance has been completed, you will be "
                                                       "able to successfully sign in.", minutes),
                           minutes);
            default:
                break;
        }

        if (*buf != '\0')
            purple_notify_info(cmdproc->session->account->gc, NULL, buf, NULL);
    }

    g_hash_table_destroy(table);
}

void
msn_notification_add_buddy(MsnNotification *notification, const char *list,
                           const char *who, const gchar *user_guid, const char *store_name,
                           const gchar *group_guid)
{
    MsnCmdProc *cmdproc;
    cmdproc = notification->cmdproc;

    /* moogman: 
     * If old_group_name == NULL, then ADC cmd is different.
     * If a new buddy (as opposed to a buddy move), ADC cmd is different. 
     * If !Fl, then do same as "new". */
    if (user_guid && group_guid)
    {
        /* Buddy already in FL. Add it to group_guid. */
        msn_cmdproc_send (cmdproc, "ADC", "%s C=%s %s", list, user_guid, group_guid);
    }
    else if (strcmp(list, "FL") == 0)
    {
        /* Add buddy to our FL. */
        /* FunkTastic Foo! */
        MsnTransaction *trans;
        MsnAddBuddy *data;

        data = g_new0 (MsnAddBuddy, 1);

        data->who = g_strdup (who);
        data->group_guid = g_strdup (group_guid);

        trans = msn_transaction_new (cmdproc, "ADC", "%s N=%s F=%s",
                                     list, who, purple_url_encode (store_name));

        msn_transaction_set_data (trans, data);

        msn_cmdproc_send_trans (cmdproc, trans);
    }
    else
    {
        /* Add buddy to another list (BL, AL). */
        msn_cmdproc_send (cmdproc, "ADC", "%s N=%s", list, who);
    }
}

void
msn_notification_rem_buddy(MsnNotification *notification, const char *list,
                           const char *who, const gchar *user_guid, const gchar *group_guid)
{
    MsnCmdProc *cmdproc;
    const gchar *final_who;

    cmdproc = notification->cmdproc;
    final_who = ((strcmp (list, "FL") == 0) ? user_guid : who);

    /* moogman: If user is only in one group, set group_guid == NULL (force a complete remove).
     * It seems as if we don't need to do the above check. I've tested it as it is and it seems 
     * to work fine. However, a note is left here incase things change. */
    if (group_guid)
    {
        msn_cmdproc_send (cmdproc, "REM", "%s %s %s", list, final_who, group_guid);
    }
    else
    {
        msn_cmdproc_send (cmdproc, "REM", "%s %s", list, final_who);
    }
}

/**************************************************************************
 * Init
 **************************************************************************/

void
msn_notification_init(void)
{
    /* TODO: check prp, blp */

    cbs_table = msn_table_new();

    /* Synchronous */
    msn_table_add_cmd(cbs_table, "CHG", "CHG", NULL);
    msn_table_add_cmd(cbs_table, "CHG", "ILN", iln_cmd);
    msn_table_add_cmd(cbs_table, "ADC", "ADC", adc_cmd);
    msn_table_add_cmd(cbs_table, "ADC", "ILN", iln_cmd);
    msn_table_add_cmd(cbs_table, "REM", "REM", rem_cmd);
    msn_table_add_cmd(cbs_table, "USR", "USR", usr_cmd);
    msn_table_add_cmd(cbs_table, "USR", "XFR", xfr_cmd);
    msn_table_add_cmd(cbs_table, "SYN", "SYN", syn_cmd);
    msn_table_add_cmd(cbs_table, "CVR", "CVR", cvr_cmd);
    msn_table_add_cmd(cbs_table, "VER", "VER", ver_cmd);
    /* msn_table_add_cmd(cbs_table, "REA", "REA", rea_cmd); */
    msn_table_add_cmd(cbs_table, "SBP", "SBP", sbp_cmd);
    msn_table_add_cmd(cbs_table, "PRP", "PRP", prp_cmd);
    /* msn_table_add_cmd(cbs_table, "BLP", "BLP", blp_cmd); */
    msn_table_add_cmd(cbs_table, "BLP", "BLP", NULL);
    msn_table_add_cmd(cbs_table, "REG", "REG", reg_cmd);
    msn_table_add_cmd(cbs_table, "ADG", "ADG", adg_cmd);
    msn_table_add_cmd(cbs_table, "RMG", "RMG", rmg_cmd);
    msn_table_add_cmd(cbs_table, "XFR", "XFR", xfr_cmd);

    /* Asynchronous */
    msn_table_add_cmd(cbs_table, NULL, "IPG", ipg_cmd);
    msn_table_add_cmd(cbs_table, NULL, "MSG", msg_cmd);
    msn_table_add_cmd(cbs_table, NULL, "NOT", not_cmd);

    msn_table_add_cmd(cbs_table, NULL, "CHL", chl_cmd);
    msn_table_add_cmd(cbs_table, NULL, "REM", rem_cmd);
    msn_table_add_cmd(cbs_table, NULL, "ADC", adc_cmd);

    msn_table_add_cmd(cbs_table, NULL, "QRY", NULL);
    msn_table_add_cmd(cbs_table, NULL, "QNG", qng_cmd);
    msn_table_add_cmd(cbs_table, NULL, "FLN", fln_cmd);
    msn_table_add_cmd(cbs_table, NULL, "NLN", nln_cmd);
    msn_table_add_cmd(cbs_table, NULL, "ILN", iln_cmd);
    msn_table_add_cmd(cbs_table, NULL, "OUT", out_cmd);
    msn_table_add_cmd(cbs_table, NULL, "RNG", rng_cmd);

    msn_table_add_cmd(cbs_table, NULL, "UBX", ubx_cmd);

    msn_table_add_cmd(cbs_table, NULL, "URL", url_cmd);

    msn_table_add_cmd(cbs_table, "fallback", "XFR", xfr_cmd);

    msn_table_add_error(cbs_table, "ADC", adc_error);
    msn_table_add_error(cbs_table, "REG", reg_error);
    msn_table_add_error(cbs_table, "RMG", rmg_error);
    /* msn_table_add_error(cbs_table, "REA", rea_error); */
    msn_table_add_error(cbs_table, "USR", usr_error);

    msn_table_add_msg_type(cbs_table,
                           "text/x-msmsgsprofile",
                           profile_msg);
    msn_table_add_msg_type(cbs_table,
                           "text/x-msmsgsinitialmdatanotification",
                           initial_mdata_msg);
    msn_table_add_msg_type(cbs_table,
                           "text/x-msmsgsemailnotification",
                           email_msg);
    msn_table_add_msg_type(cbs_table,
                           "application/x-msmsgssystemmessage",
                           system_msg);
}

void
msn_notification_end(void)
{
    msn_table_destroy(cbs_table);
}
