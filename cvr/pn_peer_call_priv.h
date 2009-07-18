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

#ifndef PN_PEER_CALL_PRIV_H
#define PN_PEER_CALL_PRIV_H

struct pn_peer_link;

struct MsnSession;
struct MsnSwitchBoard;

#include <glib.h>

struct pn_peer_call {
    char *id;
    char *branch;

    long session_id;
    long app_id;

    struct MsnSwitchBoard *swboard;

    gboolean pending; /**< A flag that states if we should wait for this
                        call to start and do not time out. */
    gboolean started; /**< A flag that states if this call's session has
                        been initiated. */

    void (*progress_cb)(struct pn_peer_call *call,
                        gsize total_length, gsize len, gsize offset);
    void (*init_cb)(struct pn_peer_call *call);

    /* Can be checksum, or smile */
    char *data_info;

    void *xfer;

    void (*cb)(struct pn_peer_call *call, const guchar *data, gsize size);
    void (*end_cb)(struct pn_peer_call *call, struct MsnSession *session);

    guint timer;

    struct pn_peer_link *link;
    unsigned int ref_count;
};

#endif /* PN_PEER_CALL_PRIV_H */
