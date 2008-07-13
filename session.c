/**
 * Copyright (C) 2008 Felipe Contreras
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

#include "session_private.h"
#include "pecan_log.h"
#include "notification.h"
#include "pecan_status.h"
#include "pecan_util.h"

#include "cvr/slplink.h"

#include "sync.h"
#include "nexus.h"

#include "io/pecan_http_server_priv.h"

#include <glib/gstdio.h>
#include <string.h>
#include "msn_intl.h"

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <account.h>

MsnSession *
msn_session_new(PurpleAccount *account)
{
	MsnSession *session;

	g_return_val_if_fail(account != NULL, NULL);

	session = g_new0(MsnSession, 1);

        session->http_method = purple_account_get_bool (account, "http_method", FALSE);
        session->server_alias = purple_account_get_bool (account, "server_alias", FALSE);
#if 0
        if (session->http_method)
        {
            PecanNode *foo;
            foo = PECAN_NODE (pecan_http_server_new ("foo server"));
            foo->session = session;
            session->http_conn = foo;
        }
#endif

	session->account = account;
	session->notification = msn_notification_new(session);
	session->contactlist = pecan_contactlist_new(session);

	session->user = pecan_contact_new (NULL);

	session->protocol_ver = 9;
	session->conv_seq = 1;

	session->oim_session = pecan_oim_session_new (session);

	return session;
}

void
msn_session_destroy(MsnSession *session)
{
	g_return_if_fail(session != NULL);

	session->destroying = TRUE;

        pecan_oim_session_free (session->oim_session);

	if (session->connected)
		msn_session_disconnect(session);

	if (session->notification != NULL)
		msn_notification_destroy(session->notification);

	while (session->switches != NULL)
		msn_switchboard_destroy(session->switches->data);

	while (session->slplinks != NULL)
		msn_slplink_destroy(session->slplinks->data);

	pecan_contactlist_destroy(session->contactlist);

	g_free(session->passport_info.kv);
	g_free(session->passport_info.sid);
	g_free(session->passport_info.mspauth);
	g_free(session->passport_info.client_ip);

        g_free (session->passport_info.mail_url);

	if (session->sync != NULL)
		msn_sync_destroy(session->sync);

	if (session->nexus != NULL)
		msn_nexus_destroy(session->nexus);

	if (session->user != NULL)
		pecan_contact_free(session->user);

	g_free (session->username);
	g_free (session->password);

	g_free(session);
}

void
msn_session_set_username (MsnSession *session,
                          const gchar *value)
{
    g_free (session->username);
    session->username = pecan_normalize (value);
    pecan_contact_set_passport (session->user, session->username);
}

const gchar *
msn_session_get_username (MsnSession *session)
{
    return session->username;
}

void
msn_session_set_password (MsnSession *session,
                          const gchar *value)
{
    g_free (session->password);
    session->password = g_strdup (value);
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

PurpleAccount *
msn_session_get_account (MsnSession *session)
{
    g_return_val_if_fail (session, NULL);
    return session->account;
}

gboolean
msn_session_connect(MsnSession *session, const char *host, int port)
{
	g_return_val_if_fail(session != NULL, FALSE);
	g_return_val_if_fail(!session->connected, TRUE);

	session->connected = TRUE;

	if (session->notification == NULL)
	{
		pecan_error ("this shouldn't happen");
		g_return_val_if_reached(FALSE);
	}

	if (msn_notification_connect(session->notification, host, port))
	{
		return TRUE;
	}

	return FALSE;
}

void
msn_session_disconnect(MsnSession *session)
{
	g_return_if_fail(session != NULL);
	g_return_if_fail(session->connected);

	session->connected = FALSE;

	while (session->switches != NULL)
		msn_switchboard_close(session->switches->data);

	if (session->notification != NULL)
		msn_notification_close(session->notification);

        if (session->http_conn)
            pecan_node_close (session->http_conn);
}

/* TODO: This must go away when conversation is redesigned */
MsnSwitchBoard *
msn_session_find_swboard(const MsnSession *session, const gchar *username)
{
	GList *l;

	g_return_val_if_fail(session  != NULL, NULL);
	g_return_val_if_fail(username != NULL, NULL);

	for (l = session->switches; l != NULL; l = l->next)
	{
		MsnSwitchBoard *swboard;

		swboard = l->data;

		if ((swboard->im_user != NULL) && !strcmp(username, swboard->im_user))
			return swboard;
	}

	return NULL;
}

MsnSwitchBoard *
msn_session_find_swboard_with_conv(const MsnSession *session, const PurpleConversation *conv)
{
	GList *l;

	g_return_val_if_fail(session  != NULL, NULL);
	g_return_val_if_fail(conv != NULL, NULL);

	for (l = session->switches; l != NULL; l = l->next)
	{
		MsnSwitchBoard *swboard;

		swboard = l->data;

		if (swboard->conv == conv)
			return swboard;
	}

	return NULL;
}

MsnSwitchBoard *
msn_session_find_swboard_with_id(const MsnSession *session, int chat_id)
{
	GList *l;

	g_return_val_if_fail(session != NULL, NULL);
	g_return_val_if_fail(chat_id >= 0,    NULL);

	for (l = session->switches; l != NULL; l = l->next)
	{
		MsnSwitchBoard *swboard;

		swboard = l->data;

		if (swboard->chat_id == chat_id)
			return swboard;
	}

	return NULL;
}

MsnSwitchBoard *
msn_session_get_swboard(MsnSession *session, const char *username,
						MsnSBFlag flag)
{
	MsnSwitchBoard *swboard;

	g_return_val_if_fail(session != NULL, NULL);

	swboard = msn_session_find_swboard(session, username);

	if (swboard == NULL)
	{
		swboard = msn_switchboard_new(session);
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
    PurpleConnection *gc;
    gchar *tmp;
    va_list args;

    gc = purple_account_get_connection (session->account);

    va_start (args, fmt);

    tmp = g_strdup_vprintf (fmt, args);

    purple_notify_error (gc, NULL, tmp, NULL);

    g_free (tmp);

    va_end (args);
}

void
msn_session_set_error(MsnSession *session, MsnErrorType error,
					  const char *info)
{
	PurpleConnection *gc;
	char *msg;

	gc = purple_account_get_connection(session->account);
        g_return_if_fail (gc);

	switch (error)
	{
		case MSN_ERROR_SERVCONN:
			msg = g_strdup(info);
			break;
		case MSN_ERROR_UNSUPPORTED_PROTOCOL:
			msg = g_strdup(_("Our protocol is not supported by the "
							 "server."));
			break;
		case MSN_ERROR_HTTP_MALFORMED:
			msg = g_strdup(_("Error parsing HTTP."));
			break;
		case MSN_ERROR_SIGN_OTHER:
			gc->wants_to_die = TRUE;
			msg = g_strdup(_("You have signed on from another location."));
			break;
		case MSN_ERROR_SERV_UNAVAILABLE:
			msg = g_strdup(_("The MSN servers are temporarily "
							 "unavailable. Please wait and try "
							 "again."));
			break;
		case MSN_ERROR_SERV_DOWN:
			msg = g_strdup(_("The MSN servers are going down "
							 "temporarily."));
			break;
		case MSN_ERROR_AUTH:
			gc->wants_to_die = TRUE;
                        msg = pecan_strdup_printf(_("Unable to authenticate: %s"),
                                                  (info == NULL ) ?
                                                  _("Unknown error") : info);
			break;
		case MSN_ERROR_BAD_BLIST:
			msg = g_strdup(_("Your MSN buddy list is temporarily "
							 "unavailable. Please wait and try "
							 "again."));
			break;
		default:
			msg = g_strdup(_("Unknown error."));
			break;
	}

	msn_session_disconnect(session);

	purple_connection_error(gc, msg);

	g_free(msg);
}

static const char *
get_login_step_text(MsnSession *session)
{
	const char *steps_text[] = {
		_("Connecting"),
		_("Handshaking"),
		_("Transferring"),
		_("Handshaking"),
		_("Starting authentication"),
		_("Getting cookie"),
		_("Authenticating"),
		_("Sending cookie"),
		_("Retrieving buddy list")
	};

	return steps_text[session->login_step];
}

void
msn_session_set_login_step(MsnSession *session, MsnLoginStep step)
{
	PurpleConnection *gc;

	/* Prevent the connection progress going backwards, eg. if we get
	 * transferred several times during login */
	if (session->login_step > step)
		return;

	/* If we're already logged in, we're probably here because of a
	 * mid-session XFR from the notification server, so we don't want to
	 * popup the connection progress dialog */
	if (session->logged_in)
		return;

	gc = session->account->gc;

	session->login_step = step;

	purple_connection_update_progress(gc, get_login_step_text(session), step,
									PECAN_LOGIN_STEPS);
}

void
msn_session_finish_login(MsnSession *session)
{
	PurpleAccount *account;
	PurpleConnection *gc;
	PurpleStoredImage *img;

	if (session->logged_in)
		return;

	account = session->account;
	gc = purple_account_get_connection(account);

	img = purple_buddy_icons_find_account_icon(session->account);

        {
            PecanBuffer *image;
            image = pecan_buffer_new_memdup ((const gpointer) purple_imgstore_get_data (img),
                                             purple_imgstore_get_size (img));
            pecan_contact_set_buddy_icon (session->user, image);
        }

	purple_imgstore_unref(img);

	session->logged_in = TRUE;

        /** @todo move this to msn.c */
	pecan_update_status (session);
	pecan_update_personal_message (session);

	purple_connection_set_state(gc, PURPLE_CONNECTED);

        pecan_contactlist_check_pending (session->contactlist);
}
