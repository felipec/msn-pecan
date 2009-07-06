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

#ifndef MSN_SLP_H
#define MSN_SLP_H

#include <glib.h>

struct PnPeerCall;
struct PnPeerLink;

struct PnPeerCall *msn_slp_sip_recv(struct PnPeerLink *link,
                                   const char *body);

void msn_slp_sip_send_ok(struct PnPeerCall *call,
                         const char *branch,
                         const char *type,
                         const char *content);

void msn_slp_sip_send_decline(struct PnPeerCall *call,
                              const char *branch,
                              const char *type,
                              const char *content);

void msn_slp_sip_send_bye(struct PnPeerCall *call,
                          const char *type);

#endif /* MSN_SLP_H */
