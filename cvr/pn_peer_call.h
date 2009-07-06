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

#ifndef PN_PEER_CALL_H
#define PN_PEER_CALL_H

typedef struct PnPeerCall PnPeerCall;

struct MsnSession;
struct PnPeerLink;

#include <glib.h>

typedef enum {
    PN_PEER_CALL_ANY,
    PN_PEER_CALL_DC,
} PnPeerCallType;

struct PnPeerCall
{
    PnPeerCallType type;

    char *id;
    char *branch;

    long session_id;
    long app_id;

    gboolean pending; /**< A flag that states if we should wait for this
                        call to start and do not time out. */
    gboolean progress; /**< A flag that states if there has been progress since
                         the last time out. */
    gboolean started; /**< A flag that states if this call's session has
                        been initiated. */

    void (*progress_cb)(PnPeerCall *call,
                        gsize total_length, gsize len, gsize offset);
    void (*init_cb)(PnPeerCall *call);

    /* Can be checksum, or smile */
    char *data_info;

    void *xfer;

    void (*cb)(PnPeerCall *call, const guchar *data, gsize size);
    void (*end_cb)(PnPeerCall *call, struct MsnSession *session);

    int timer;

    struct PnPeerLink *link;
    unsigned int ref_count;
};

PnPeerCall *pn_peer_call_new(struct PnPeerLink *link);
void pn_peer_call_destroy(PnPeerCall *call);
PnPeerCall *pn_peer_call_ref(PnPeerCall *call);
PnPeerCall *pn_peer_call_unref(PnPeerCall *call);

void pn_peer_call_init(PnPeerCall *call,
                       PnPeerCallType type);
void pn_peer_call_session_init(PnPeerCall *call);
void pn_peer_call_invite(PnPeerCall *call,
                         const char *euf_guid,
                         int app_id,
                         const char *context);
void pn_peer_call_close(PnPeerCall *call);
gboolean pn_peer_call_timeout(gpointer data);

#endif /* PN_PEER_CALL_H */
