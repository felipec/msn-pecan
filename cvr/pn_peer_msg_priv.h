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

#ifndef PN_PEER_MSG_PRIV_H
#define PN_PEER_MSG_PRIV_H

struct pn_peer_call;
struct pn_peer_link;

struct MsnSession;
struct MsnMessage;
struct MsnSwitchBoard;

#include <glib.h>
#include <glib/gstdio.h>

/**
 * A SLP Message  This contains everything that we will need to send a SLP
 * Message even if has to be sent in several parts.
 */
struct pn_peer_msg {
    struct pn_peer_call *call; /**< The call to which this slp message belongs (if applicable). */
    struct pn_peer_link *link; /**< The peer link through which this slp message is being sent. */
    struct MsnSession *session;

    long session_id;
    long id;
    long ack_id;
    long ack_sub_id;
    guint64 ack_size;
    long app_id;

    gboolean sip; /**< A flag that states if this is a SIP slp message. */
    long flags;

    FILE *fp;
    gchar *buffer;
    guint64 offset;
    guint64 size;

#ifdef PECAN_DEBUG_SLP
    const gchar *info;
    gboolean text_body;
#endif

    unsigned int ref_count;
    struct MsnSwitchBoard *swboard;
};

#endif /* PN_PEER_MSG_PRIV_H */
