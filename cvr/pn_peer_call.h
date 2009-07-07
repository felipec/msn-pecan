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

struct pn_peer_link;

struct MsnSession;
struct MsnSwitchBoard;

#include <glib.h>

struct pn_peer_call *pn_peer_call_new(struct pn_peer_link *link);
void pn_peer_call_free(struct pn_peer_call *call);
struct pn_peer_call *pn_peer_call_ref(struct pn_peer_call *call);
struct pn_peer_call *pn_peer_call_unref(struct pn_peer_call *call);

void pn_peer_call_session_init(struct pn_peer_call *call);
void pn_peer_call_close(struct pn_peer_call *call);

#endif /* PN_PEER_CALL_H */
