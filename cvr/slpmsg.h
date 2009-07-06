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

#ifndef MSN_SLPMSG_H
#define MSN_SLPMSG_H

typedef struct MsnSlpMessage MsnSlpMessage;

struct MsnSlpSesison;
struct PnPeerCall;
struct PnPeerLink;
struct MsnSession;
struct MsnMessage;

#include "io/pn_buffer.h"

#include <glib/gstdio.h>

/**
 * A SLP Message  This contains everything that we will need to send a SLP
 * Message even if has to be sent in several parts.
 */
struct MsnSlpMessage
{
    struct PnPeerCall *call; /**< The call to which this slp message belongs (if applicable). */
    struct PnPeerLink *link; /**< The peer link through which this slp message is being sent. */
    struct MsnSession *session;

    long session_id;
    long id;
    long ack_id;
    long ack_sub_id;
    guint64 ack_size;
    long app_id;

    gboolean sip; /**< A flag that states if this is a SIP slp message. */
    int ref_count; /**< The reference count. */
    long flags;

    FILE *fp;
    gchar *buffer;
    guint64 offset;
    guint64 size;

    GList *msgs; /**< The real messages. */

    struct MsnMessage *msg; /**< The temporary real message that will be sent. */

#ifdef PECAN_DEBUG_SLP
    const gchar *info;
    gboolean text_body;
#endif
};

/**
 * Creates a new slp message
 *
 * @param link The peer link through which this slp message will be sent.
 * @return The created slp message.
 */
MsnSlpMessage *msn_slpmsg_new(struct PnPeerLink *link);

/**
 * Destroys a slp message
 *
 * @param slpmsg The slp message to destory.
 */
void msn_slpmsg_destroy(MsnSlpMessage *slpmsg);

void msn_slpmsg_set_body(MsnSlpMessage *slpmsg,
                         gconstpointer *body,
                         guint64 size);
void msn_slpmsg_set_image(MsnSlpMessage *slpmsg,
                          PnBuffer *image);
void msn_slpmsg_open_file(MsnSlpMessage *slpmsg,
                          const char *file_name);
MsnSlpMessage *msn_slpmsg_sip_new(struct PnPeerCall *call,
                                  int cseq,
                                  const char *header,
                                  const char *branch,
                                  const char *content_type,
                                  const char *content);

#ifdef PECAN_DEBUG_SLP
void msn_slpmsg_show(struct MsnMessage *msg);
#endif

#endif /* MSN_SLPMSG_H */
