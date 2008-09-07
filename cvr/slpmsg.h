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

#ifndef MSN_SLPMSG_H
#define MSN_SLPMSG_H

typedef struct MsnSlpMessage MsnSlpMessage;

struct MsnSlpSesison;
struct MsnSlpCall;
struct MsnSlpLink;
struct MsnSession;
struct MsnMessage;

#include "slp.h"
#include "io/pecan_buffer.h"

#include <glib/gstdio.h>

/**
 * A SLP Message  This contains everything that we will need to send a SLP
 * Message even if has to be sent in several parts.
 */
struct MsnSlpMessage
{
	struct MsnSlpSession *slpsession;
	struct MsnSlpCall *slpcall; /**< The slpcall to which this slp message belongs (if applicable). */
	struct MsnSlpLink *slplink; /**< The slplink through which this slp message is being sent. */
	struct MsnSession *session;

	long session_id;
	long id;
	long ack_id;
	long ack_sub_id;
	long long ack_size;
	long app_id;

	gboolean sip; /**< A flag that states if this is a SIP slp message. */
	int ref_count; /**< The reference count. */
	long flags;

	FILE *fp;
	gchar *buffer;
	long long offset;
	long long size;

	GList *msgs; /**< The real messages. */

#if 1
	struct MsnMessage *msg; /**< The temporary real message that will be sent. */
#endif

#ifdef PECAN_DEBUG_SLP
	const gchar *info;
	gboolean text_body;
#endif
};

/**
 * Creates a new slp message
 *
 * @param slplink The slplink through which this slp message will be sent.
 * @return The created slp message.
 */
MsnSlpMessage *msn_slpmsg_new(struct MsnSlpLink *slplink);

/**
 * Destroys a slp message
 *
 * @param slpmsg The slp message to destory.
 */
void msn_slpmsg_destroy(MsnSlpMessage *slpmsg);

void msn_slpmsg_set_body(MsnSlpMessage *slpmsg,
						 gconstpointer *body,
						 long long size);
void msn_slpmsg_set_image (MsnSlpMessage *slpmsg, PecanBuffer *image);
void msn_slpmsg_open_file(MsnSlpMessage *slpmsg,
						  const char *file_name);
MsnSlpMessage * msn_slpmsg_sip_new(struct MsnSlpCall *slpcall, int cseq,
								   const char *header,
								   const char *branch,
								   const char *content_type,
								   const char *content);

#ifdef PECAN_DEBUG_SLP
void msn_slpmsg_show(struct MsnMessage *msg);
#endif

#endif /* MSN_SLPMSG_H */
