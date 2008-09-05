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

#include "slp.h"
#include "slplink.h"
#include "slpcall.h"
#include "slpmsg.h"
#include "slpsession.h"
#include "pecan_log.h"
#include "io/pecan_buffer.h"

#include "session_private.h"

#include "cmd/cmdproc_private.h"
#include "cmd/msg_private.h"

#include "ab/pecan_contact.h"
#include "ab/pecan_contact_priv.h"
#include "ab/pecan_contactlist_priv.h"

#include "cvr/pecan_slp_object.h"
#include "switchboard.h"

#ifdef MSN_DIRECTCONN
#include "directconn.h"
#endif /* MSN_DIRECTCONN */

#include "pecan_util.h"

#include <string.h>

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <account.h>

/* ms to delay between sending buddy icon requests to the server. */
#define BUDDY_ICON_DELAY 20000

static void send_ok(MsnSlpCall *slpcall, const char *branch,
					const char *type, const char *content);

static void send_decline(MsnSlpCall *slpcall, const char *branch,
						 const char *type, const char *content);

/**************************************************************************
 * Util
 **************************************************************************/

static char *
get_token(const char *str, const char *start, const char *end)
{
	const char *c, *c2;

	if ((c = strstr(str, start)) == NULL)
		return NULL;

	c += strlen(start);

	if (end != NULL)
	{
		if ((c2 = strstr(c, end)) == NULL)
			return NULL;

		return g_strndup(c, c2 - c);
	}
	else
	{
		/* This has to be changed */
		return g_strdup(c);
	}

}

/**************************************************************************
 * Xfer
 **************************************************************************/

static void
msn_xfer_init(PurpleXfer *xfer)
{
	MsnSlpCall *slpcall;
	/* MsnSlpLink *slplink; */
	char *content;

	pecan_info ("xfer_init");

	slpcall = xfer->data;

	/* Send Ok */
        content = pecan_strdup_printf("SessionID: %lu\r\n\r\n",
                                      slpcall->session_id);

	send_ok(slpcall, slpcall->branch, "application/x-msnmsgr-sessionreqbody",
			content);

	g_free(content);
	msn_slplink_unleash(slpcall->slplink);
}

void
msn_xfer_cancel(PurpleXfer *xfer)
{
	MsnSlpCall *slpcall;
	char *content;

	g_return_if_fail(xfer != NULL);
	g_return_if_fail(xfer->data != NULL);

	slpcall = xfer->data;

	if (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL)
	{
		if (slpcall->started)
		{
			msn_slp_call_close(slpcall);
		}
		else
		{
			content = pecan_strdup_printf("SessionID: %lu\r\n\r\n",
									  slpcall->session_id);

			send_decline(slpcall, slpcall->branch, "application/x-msnmsgr-sessionreqbody",
						 content);

			g_free(content);
			msn_slplink_unleash(slpcall->slplink);

			msn_slp_call_destroy(slpcall);
		}
	}
}

void
msn_xfer_progress_cb(MsnSlpCall *slpcall, gsize total_length, gsize len, gsize offset)
{
	PurpleXfer *xfer;

	xfer = slpcall->xfer;

	xfer->bytes_sent = (offset + len);
	xfer->bytes_remaining = total_length - (offset + len);

	purple_xfer_update_progress(xfer);
}

void
msn_xfer_end_cb(MsnSlpCall *slpcall, MsnSession *session)
{
	if ((purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_DONE) &&
		(purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_CANCEL_REMOTE) &&
		(purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_CANCEL_LOCAL))
	{
		purple_xfer_cancel_remote(slpcall->xfer);
	}
}

void
msn_xfer_completed_cb(MsnSlpCall *slpcall, const guchar *body,
					  gsize size)
{
	PurpleXfer *xfer = slpcall->xfer;
	purple_xfer_set_completed(xfer, TRUE);
	purple_xfer_end(xfer);
}

/**************************************************************************
 * SLP Control
 **************************************************************************/

#ifdef MSN_DIRECTCONN
static void
got_transresp(MsnSlpCall *slpcall, const char *nonce,
			  const char *ips_str, int port)
{
	MsnDirectConn *directconn;
	char **ip_addrs, **c;

	directconn = msn_directconn_new(slpcall->slplink);

	directconn->initial_call = slpcall;

	/* msn_directconn_parse_nonce(directconn, nonce); */
	directconn->nonce = g_strdup(nonce);

	ip_addrs = g_strsplit(ips_str, " ", -1);

	for (c = ip_addrs; *c != NULL; c++)
	{
		pecan_info ("ip_addr = %s", *c);
		if (msn_directconn_connect(directconn, *c, port))
			break;
	}

	g_strfreev(ip_addrs);
}
#endif /* MSN_DIRECTCONN */

static void
send_ok(MsnSlpCall *slpcall, const char *branch,
		const char *type, const char *content)
{
	MsnSlpLink *slplink;
	MsnSlpMessage *slpmsg;

	slplink = slpcall->slplink;

	/* 200 OK */
	slpmsg = msn_slpmsg_sip_new(slpcall, 1,
								"MSNSLP/1.0 200 OK",
								branch, type, content);

#ifdef PECAN_DEBUG_SLP
	slpmsg->info = "SLP 200 OK";
	slpmsg->text_body = TRUE;
#endif

	msn_slplink_queue_slpmsg(slplink, slpmsg);

	msn_slp_call_session_init(slpcall);
}

static void
send_decline(MsnSlpCall *slpcall, const char *branch,
			 const char *type, const char *content)
{
	MsnSlpLink *slplink;
	MsnSlpMessage *slpmsg;

	slplink = slpcall->slplink;

	/* 603 Decline */
	slpmsg = msn_slpmsg_sip_new(slpcall, 1,
								"MSNSLP/1.0 603 Decline",
								branch, type, content);

#ifdef PECAN_DEBUG_SLP
	slpmsg->info = "SLP 603 Decline";
	slpmsg->text_body = TRUE;
#endif

	msn_slplink_queue_slpmsg(slplink, slpmsg);
}

#define MAX_FILE_NAME_LEN 0x226

static void
got_sessionreq(MsnSlpCall *slpcall, const char *branch,
			   const char *euf_guid, const char *context)
{
	if (!strcmp(euf_guid, "A4268EEC-FEC5-49E5-95C3-F126696BDBF6"))
	{
		/* Emoticon or UserDisplay */
		char *content;
		gsize len;
		MsnSlpSession *slpsession;
		MsnSlpLink *slplink;
		MsnSlpMessage *slpmsg;
		MsnObject *obj;
		char *msnobj_data;
		PecanBuffer *image;
		int type;

		/* Send Ok */
                content = pecan_strdup_printf("SessionID: %lu\r\n\r\n",
                                              slpcall->session_id);

		send_ok(slpcall, branch, "application/x-msnmsgr-sessionreqbody",
				content);

		g_free(content);

		slplink = slpcall->slplink;

		msnobj_data = (char *)purple_base64_decode(context, &len);
		obj = msn_object_new_from_string(msnobj_data);
		type = msn_object_get_type(obj);
		g_free(msnobj_data);

		if (!(type == MSN_OBJECT_USERTILE))
		{
			pecan_error ("Wrong object?");
			msn_object_destroy(obj);
			g_return_if_reached();
		}

		image = msn_object_get_image (obj);
		if (!image)
		{
                    pecan_error ("Wrong object");
                    msn_object_destroy (obj);
                    g_return_if_reached ();
		}

		msn_object_destroy(obj);

		slpsession = msn_slplink_find_slp_session(slplink,
												  slpcall->session_id);

		/* DATA PREP */
		slpmsg = msn_slpmsg_new(slplink);
		slpmsg->slpcall = slpcall;
		slpmsg->slpsession = slpsession;
		slpmsg->session_id = slpsession->id;
		msn_slpmsg_set_body(slpmsg, NULL, 4);
#ifdef PECAN_DEBUG_SLP
		slpmsg->info = "SLP DATA PREP";
#endif
		msn_slplink_queue_slpmsg(slplink, slpmsg);

		/* DATA */
		slpmsg = msn_slpmsg_new(slplink);
		slpmsg->slpcall = slpcall;
		slpmsg->slpsession = slpsession;
		slpmsg->flags = 0x20;
#ifdef PECAN_DEBUG_SLP
		slpmsg->info = "SLP DATA";
#endif
		msn_slpmsg_set_image (slpmsg, image);
		msn_slplink_queue_slpmsg(slplink, slpmsg);
	}
	else if (!strcmp(euf_guid, "5D3E02AB-6190-11D3-BBBB-00C04F795683"))
	{
		/* File Transfer */
		PurpleAccount *account;
		PurpleXfer *xfer;
		char *bin;
		gsize bin_len;
		guint32 file_size;
		char *file_name;
		gunichar2 *uni_name;

		account = slpcall->slplink->session->account;

		slpcall->cb = msn_xfer_completed_cb;
		slpcall->end_cb = msn_xfer_end_cb;
		slpcall->progress_cb = msn_xfer_progress_cb;
		slpcall->branch = g_strdup(branch);

		slpcall->pending = TRUE;

		xfer = purple_xfer_new(account, PURPLE_XFER_RECEIVE,
							   slpcall->slplink->remote_user);
		if (xfer)
		{
			bin = (char *)purple_base64_decode(context, &bin_len);
			file_size = GUINT32_FROM_LE(*(gsize *)(bin + 8));

			uni_name = (gunichar2 *)(bin + 20);
			while(*uni_name != 0 && ((char *)uni_name - (bin + 20)) < MAX_FILE_NAME_LEN) {
				*uni_name = GUINT16_FROM_LE(*uni_name);
				uni_name++;
			}

			file_name = g_utf16_to_utf8((const gunichar2 *)(bin + 20), -1,
										NULL, NULL, NULL);

			g_free(bin);

			purple_xfer_set_filename(xfer, file_name);
			purple_xfer_set_size(xfer, file_size);
			purple_xfer_set_init_fnc(xfer, msn_xfer_init);
			purple_xfer_set_request_denied_fnc(xfer, msn_xfer_cancel);
			purple_xfer_set_cancel_recv_fnc(xfer, msn_xfer_cancel);

			slpcall->xfer = xfer;
			purple_xfer_ref(slpcall->xfer);

			xfer->data = slpcall;

			purple_xfer_request(xfer);
		}
	}
}

void
send_bye(MsnSlpCall *slpcall, const char *type)
{
	MsnSlpLink *slplink;
	MsnSlpMessage *slpmsg;
	char *header;

	slplink = slpcall->slplink;

	g_return_if_fail(slplink != NULL);

        header = pecan_strdup_printf("BYE MSNMSGR:%s MSNSLP/1.0",
                                     slplink->local_user);

	slpmsg = msn_slpmsg_sip_new(slpcall, 0, header,
								"A0D624A6-6C0C-4283-A9E0-BC97B4B46D32",
								type,
								"\r\n");
	g_free(header);

#ifdef PECAN_DEBUG_SLP
	slpmsg->info = "SLP BYE";
	slpmsg->text_body = TRUE;
#endif

	msn_slplink_queue_slpmsg(slplink, slpmsg);
}

static void
got_invite(MsnSlpCall *slpcall,
		   const char *branch, const char *type, const char *content)
{
	MsnSlpLink *slplink;

	slplink = slpcall->slplink;

	if (!strcmp(type, "application/x-msnmsgr-sessionreqbody"))
	{
		char *euf_guid, *context;
		char *temp;

		euf_guid = get_token(content, "EUF-GUID: {", "}\r\n");

		temp = get_token(content, "SessionID: ", "\r\n");
		if (temp != NULL)
			slpcall->session_id = atoi(temp);
		g_free(temp);

		temp = get_token(content, "AppID: ", "\r\n");
		if (temp != NULL)
			slpcall->app_id = atoi(temp);
		g_free(temp);

		context = get_token(content, "Context: ", "\r\n");

		if (context != NULL)
			got_sessionreq(slpcall, branch, euf_guid, context);

		g_free(context);
		g_free(euf_guid);
	}
	else if (!strcmp(type, "application/x-msnmsgr-transreqbody"))
	{
		/* A direct connection? */

		const gchar *listening;
		gchar *new_content, *nonce;

		if (FALSE)
		{
#if 0
			MsnDirectConn *directconn;
			/* const char *ip_addr; */
			char *ip_port;
			int port;

			/* ip_addr = purple_prefs_get_string("/purple/ft/public_ip"); */
			ip_port = "5190";
			listening = "true";
			nonce = msn_rand_guid();

			directconn = msn_directconn_new(slplink);

			/* msn_directconn_parse_nonce(directconn, nonce); */
			directconn->nonce = g_strdup(nonce);

			msn_directconn_listen(directconn);

			port = directconn->port;

                        new_content = pecan_strdup_printf(
                                                          "Bridge: TCPv1\r\n"
                                                          "Listening: %s\r\n"
                                                          "Nonce: {%s}\r\n"
                                                          "Ipv4Internal-Addrs: 192.168.0.82\r\n"
                                                          "Ipv4Internal-Port: %d\r\n"
                                                          "\r\n",
                                                          listening,
                                                          nonce,
                                                          port);
#endif
		}
		else
		{
			listening = "false";
			nonce = g_strdup("00000000-0000-0000-0000-000000000000");

                        new_content = pecan_strdup_printf(
                                                          "Bridge: TCPv1\r\n"
                                                          "Listening: %s\r\n"
                                                          "Nonce: {%s}\r\n"
                                                          "\r\n",
                                                          listening,
                                                          nonce);
		}

		send_ok(slpcall, branch,
				"application/x-msnmsgr-transrespbody", new_content);

		g_free(new_content);
		g_free(nonce);
	}
#ifdef MSN_DIRECTCONN
	else if (!strcmp(type, "application/x-msnmsgr-transrespbody"))
	{
		char *ip_addrs;
		char *temp;
		char *nonce;
		int port;

		nonce = get_token(content, "Nonce: {", "}\r\n");
		ip_addrs = get_token(content, "IPv4Internal-Addrs: ", "\r\n");

		temp = get_token(content, "IPv4Internal-Port: ", "\r\n");
		if (temp != NULL)
			port = atoi(temp);
		else
			port = -1;
		g_free(temp);

		if (ip_addrs == NULL)
			return;

		if (port > 0)
			got_transresp(slpcall, nonce, ip_addrs, port);

		g_free(nonce);
		g_free(ip_addrs);
	}
#endif /* MSN_DIRECTCONN */
}

static void
got_ok(MsnSlpCall *slpcall,
	   const char *type, const char *content)
{
	g_return_if_fail(slpcall != NULL);
	g_return_if_fail(type    != NULL);

	if (!strcmp(type, "application/x-msnmsgr-sessionreqbody"))
	{
#ifdef MSN_DIRECTCONN
		if (slpcall->type == MSN_SLPCALL_DC)
		{
			/* First let's try a DirectConnection. */

			MsnSlpLink *slplink;
			MsnSlpMessage *slpmsg;
			char *header;
			gchar *new_content;
			char *branch;

			slplink = slpcall->slplink;

			branch = msn_rand_guid();

                        new_content = pecan_strdup_printf(
                                                          "Bridges: TRUDPv1 TCPv1\r\n"
                                                          "NetID: 0\r\n"
                                                          "Conn-Type: Direct-Connect\r\n"
                                                          "UPnPNat: false\r\n"
                                                          "ICF: false\r\n"
                                                         );

                        header = pecan_strdup_printf("INVITE MSNMSGR:%s MSNSLP/1.0",
                                                     slplink->remote_user);

			slpmsg = msn_slpmsg_sip_new(slpcall, 0, header, branch,
										"application/x-msnmsgr-transreqbody",
										new_content);

#ifdef PECAN_DEBUG_SLP
			slpmsg->info = "SLP INVITE";
			slpmsg->text_body = TRUE;
#endif
			msn_slplink_send_slpmsg(slplink, slpmsg);

			g_free(header);
			g_free(new_content);

			g_free(branch);
		}
		else
		{
			msn_slp_call_session_init(slpcall);
		}
#else
                msn_slp_call_session_init(slpcall);
#endif /* MSN_DIRECTCONN */
	}
	else if (!strcmp(type, "application/x-msnmsgr-transreqbody"))
	{
		/* Do we get this? */
		pecan_info ("OK with transreqbody");
	}
#ifdef MSN_DIRECTCONN
	else if (!strcmp(type, "application/x-msnmsgr-transrespbody"))
	{
		char *ip_addrs;
		char *temp;
		char *nonce;
		int port;

		{
			char *listening;
			listening = get_token(content, "Listening: ", "\r\n");
			if (strcmp (listening, "false") == 0)
			{
				/** @todo I'm not sure if this is OK. */
				msn_slp_call_session_init(slpcall);
				g_free (listening);
				return;
			}
			g_free (listening);
		}

		nonce = get_token(content, "Nonce: {", "}\r\n");
		ip_addrs = get_token(content, "IPv4Internal-Addrs: ", "\r\n");

		temp = get_token(content, "IPv4Internal-Port: ", "\r\n");
		if (temp != NULL)
			port = atoi(temp);
		else
			port = -1;
		g_free(temp);

		if (ip_addrs == NULL)
			return;

		if (port > 0)
			got_transresp(slpcall, nonce, ip_addrs, port);

		g_free(nonce);
		g_free(ip_addrs);
	}
#endif /* MSN_DIRECTCONN */
}

MsnSlpCall *
msn_slp_sip_recv(MsnSlpLink *slplink, const char *body)
{
	MsnSlpCall *slpcall;

	if (body == NULL)
	{
		pecan_warning ("received bogus message");
		return NULL;
	}

	if (!strncmp(body, "INVITE", strlen("INVITE")))
	{
		char *branch;
		char *content;
		char *content_type;

		slpcall = msn_slp_call_new(slplink);

		/* From: <msnmsgr:buddy@hotmail.com> */
#if 0
		slpcall->remote_user = get_token(body, "From: <msnmsgr:", ">\r\n");
#endif

		branch = get_token(body, ";branch={", "}");

		slpcall->id = get_token(body, "Call-ID: {", "}");

#if 0
		long content_len = -1;

		temp = get_token(body, "Content-Length: ", "\r\n");
		if (temp != NULL)
			content_len = atoi(temp);
		g_free(temp);
#endif
		content_type = get_token(body, "Content-Type: ", "\r\n");

		content = get_token(body, "\r\n\r\n", NULL);

		got_invite(slpcall, branch, content_type, content);

		g_free(branch);
		g_free(content_type);
		g_free(content);
	}
	else if (!strncmp(body, "MSNSLP/1.0 ", strlen("MSNSLP/1.0 ")))
	{
		char *content;
		char *content_type;
		/* Make sure this is "OK" */
		const char *status = body + strlen("MSNSLP/1.0 ");
		char *call_id;

		call_id = get_token(body, "Call-ID: {", "}");
		slpcall = msn_slplink_find_slp_call(slplink, call_id);
		g_free(call_id);

		g_return_val_if_fail(slpcall != NULL, NULL);

		if (strncmp(status, "200 OK", 6))
		{
			/* It's not valid. Kill this off. */
			char temp[32];
			const char *c;

			/* Eww */
			if ((c = strchr(status, '\r')) || (c = strchr(status, '\n')) ||
				(c = strchr(status, '\0')))
			{
				size_t offset =  c - status;
				if (offset >= sizeof(temp))
					offset = sizeof(temp) - 1;

				strncpy(temp, status, offset);
				temp[offset] = '\0';
			}

			pecan_error ("received non-OK result: %s", temp);

			slpcall->wasted = TRUE;

			/* msn_slp_call_destroy(slpcall); */
			return slpcall;
		}

		content_type = get_token(body, "Content-Type: ", "\r\n");

		content = get_token(body, "\r\n\r\n", NULL);

		got_ok(slpcall, content_type, content);

		g_free(content_type);
		g_free(content);
	}
	else if (!strncmp(body, "BYE", strlen("BYE")))
	{
		char *call_id;

		call_id = get_token(body, "Call-ID: {", "}");
		slpcall = msn_slplink_find_slp_call(slplink, call_id);
		g_free(call_id);

		if (slpcall != NULL)
			slpcall->wasted = TRUE;

		/* msn_slp_call_destroy(slpcall); */
	}
	else
		slpcall = NULL;

	return slpcall;
}

/**************************************************************************
 * Msg Callbacks
 **************************************************************************/

void
msn_p2p_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	MsnSession *session;
	MsnSlpLink *slplink;

	session = cmdproc->session;
	slplink = msn_session_get_slplink(session, msg->remote_user);

	if (slplink->swboard == NULL)
	{
		/* We will need this in order to change its flags. */
		slplink->swboard = (MsnSwitchBoard *)cmdproc->data;
		/* If swboard is NULL, something has probably gone wrong earlier on
		 * I didn't want to do this, but MSN 7 is somehow causing us to crash
		 * here, I couldn't reproduce it to debug more, and people are
		 * reporting bugs. Hopefully this doesn't cause more crashes. Stu.
		 */
		if (slplink->swboard != NULL)
			slplink->swboard->slplinks = g_list_prepend(slplink->swboard->slplinks, slplink);
		else
			pecan_error ("msn_p2p_msg, swboard is NULL, ouch!");
	}

	msn_slplink_process_msg(slplink, msg);
}

static void
got_emoticon(MsnSlpCall *slpcall,
			 const guchar *data, gsize size)
{

	PurpleConversation *conv;
	PurpleConnection *gc;
	const char *who;

	gc = slpcall->slplink->session->account->gc;
	who = slpcall->slplink->remote_user;

	if ((conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, who, gc->account))) {

		/* FIXME: it would be better if we wrote the data as we received it
		   instead of all at once, calling write multiple times and
		   close once at the very end
		   */
		purple_conv_custom_smiley_write(conv, slpcall->data_info, data, size);
		purple_conv_custom_smiley_close(conv, slpcall->data_info);
	}

	pecan_debug ("got smiley: %s", slpcall->data_info);
}

void
msn_emoticon_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	MsnSession *session;
	MsnSlpLink *slplink;
	MsnObject *obj;
	char **tokens;
	char *smile, *body_str;
	const char *body, *who, *sha1;
	guint tok;
	size_t body_len;

	PurpleConversation *conv;

	session = cmdproc->session;

	if (!purple_account_get_bool(session->account, "custom_smileys", TRUE))
		return;

	body = msn_message_get_bin_data(msg, &body_len);
	body_str = g_strndup(body, body_len);

	/* MSN Messenger 7 may send more than one MSNObject in a single message...
	 * Maybe 10 tokens is a reasonable max value. */
	tokens = g_strsplit(body_str, "\t", 10);

	g_free(body_str);

	for (tok = 0; tok < 9; tok += 2) {
		if (tokens[tok] == NULL || tokens[tok + 1] == NULL) {
			break;
		}

		smile = tokens[tok];
		{
			gchar *tmp;
			tmp = pecan_url_decode (tokens[tok + 1]);
			obj = msn_object_new_from_string(tmp);
			g_free(tmp);
		}

		if (obj == NULL)
			break;

		who = msn_object_get_creator(obj);
		sha1 = msn_object_get_sha1(obj);

		slplink = msn_session_get_slplink(session, who);

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, who,
													 session->account);

		/* If the conversation doesn't exist then this is a custom smiley
		 * used in the first message in a MSN conversation: we need to create
		 * the conversation now, otherwise the custom smiley won't be shown.
		 * This happens because every GtkIMHtml has its own smiley tree: if
		 * the conversation doesn't exist then we cannot associate the new
		 * smiley with its GtkIMHtml widget. */
		if (!conv) {
			conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, session->account, who);
		}

		if (purple_conv_custom_smiley_add(conv, smile, "sha1", sha1, TRUE)) {
			msn_slplink_request_object(slplink, smile, got_emoticon, NULL, obj);
		}

		msn_object_destroy(obj);
		obj =   NULL;
		who =   NULL;
		sha1 = NULL;
	}
	g_strfreev(tokens);
}
