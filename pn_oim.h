/**
 * Copyright (C) 2008-2009 Felipe Contreras
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

#ifndef PN_OIM_H
#define PN_OIM_H

typedef enum
{
    PN_RECEIVE_OIM,
    PN_DELETE_OIM,
    PN_SEND_OIM,
    PN_SSO_AUTH_OIM

} OimRequestType;

typedef struct PecanOimSession PecanOimSession;

#include "session.h"

struct MsnSession;

PecanOimSession *pn_oim_session_new (MsnSession *session);
void pn_oim_session_free (PecanOimSession *oim_session);
void pn_oim_session_request (PecanOimSession *oim_session,
                             const gchar *passport,
                             const gchar *message_id,
                             const gchar *oim_message,
                             OimRequestType type);

#endif /* PN_OIM_H */
