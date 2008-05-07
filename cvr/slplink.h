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

#ifndef MSN_SLPLINK_H
#define MSN_SLPLINK_H

typedef struct MsnSlpLink MsnSlpLink;

struct MsnSession;
struct MsnSwitchboard;
struct MsnSlpMessage;
struct MsnDirectConn;
struct MsnMessage;
struct MsnSlpSession;

struct _PurpleXfer;

#include <glib.h>

#include "slpcall.h"
#include "cvr/pecan_slp_object.h"

typedef void (*MsnSlpCb) (MsnSlpCall *slpcall, const guchar *data, gsize size);
typedef void (*MsnSlpEndCb) (MsnSlpCall *slpcall, struct MsnSession *session);

struct MsnSlpLink
{
	char *local_user;
	char *remote_user;

	int slp_seq_id;
	int slp_session_id;

	GList *slp_calls;
	GList *slp_sessions;
	GList *slp_msgs;

	GQueue *slp_msg_queue;
	struct MsnSession *session;
	struct MsnSwitchBoard *swboard;
	struct MsnDirectConn *directconn;
};

MsnSlpLink *msn_slplink_new(struct MsnSession *session, const char *username);
void msn_slplink_destroy(MsnSlpLink *slplink);
MsnSlpLink *msn_session_find_slplink(struct MsnSession *session,
									 const char *who);
MsnSlpLink *msn_session_get_slplink(struct MsnSession *session, const char *username);
struct MsnSlpSession *msn_slplink_find_slp_session(MsnSlpLink *slplink,
											long session_id);
void msn_slplink_add_slpcall(MsnSlpLink *slplink, MsnSlpCall *slpcall);
void msn_slplink_remove_slpcall(MsnSlpLink *slplink, MsnSlpCall *slpcall);
MsnSlpCall *msn_slplink_find_slp_call(MsnSlpLink *slplink,
									  const char *id);
MsnSlpCall *msn_slplink_find_slp_call_with_session_id(MsnSlpLink *slplink, long id);
void msn_slplink_send_msg(MsnSlpLink *slplink, struct MsnMessage *msg);
void msn_slplink_release_slpmsg(MsnSlpLink *slplink,
								struct MsnSlpMessage *slpmsg);
void msn_slplink_queue_slpmsg(MsnSlpLink *slplink, struct MsnSlpMessage *slpmsg);
void msn_slplink_send_slpmsg(MsnSlpLink *slplink,
							 struct MsnSlpMessage *slpmsg);
void msn_slplink_unleash(MsnSlpLink *slplink);
void msn_slplink_send_ack(MsnSlpLink *slplink, struct MsnMessage *msg);
void msn_slplink_process_msg(MsnSlpLink *slplink, struct MsnMessage *msg);
struct MsnSlpMessage *msn_slplink_message_find(MsnSlpLink *slplink, long session_id, long id);
void msn_slplink_append_slp_msg(MsnSlpLink *slplink, struct MsnSlpMessage *slpmsg);
void msn_slplink_remove_slp_msg(MsnSlpLink *slplink,
								struct MsnSlpMessage *slpmsg);
void msn_slplink_request_ft(MsnSlpLink *slplink, struct _PurpleXfer *xfer);

void msn_slplink_request_object(MsnSlpLink *slplink,
								const char *info,
								MsnSlpCb cb,
								MsnSlpEndCb end_cb,
								const MsnObject *obj);

MsnSlpCall *msn_slp_process_msg(MsnSlpLink *slplink, struct MsnSlpMessage *slpmsg);

#endif /* MSN_SLPLINK_H */
