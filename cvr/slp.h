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

#ifndef MSN_SLP_H
#define MSN_SLP_H

#include <glib.h>

struct MsnSession;
struct MsnSlpCall;
struct MsnSlpLink;
struct PecanContact;

struct _PurpleXfer;

void msn_xfer_progress_cb(struct MsnSlpCall *slpcall, gsize total_length, gsize
						  len, gsize offset);

struct MsnSlpCall * msn_slp_sip_recv(struct MsnSlpLink *slplink,
							  const char *body);

void send_bye(struct MsnSlpCall *slpcall, const char *type);

void msn_xfer_completed_cb(struct MsnSlpCall *slpcall,
						   const guchar *body, gsize size);

void msn_xfer_cancel(struct _PurpleXfer *xfer);
void msn_xfer_end_cb(struct MsnSlpCall *slpcall, struct MsnSession *session);

#endif /* MSN_SLP_H */
