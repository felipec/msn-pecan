/**
 * Copyright (C) 2007-2009 Felipe Contreras
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

#ifndef PN_DP_MANAGER_H
#define PN_DP_MANAGER_H

typedef struct PnDpManager PnDpManager;

#include <glib.h>
#include "session.h"
#include "ab/pn_contact.h"
#include "cvr/pn_msnobj.h"

PnDpManager *pn_dp_manager_new (MsnSession *session);
void pn_dp_manager_free (PnDpManager *dpm);
void pn_dp_manager_contact_set_object (struct pn_contact *contact, gboolean prioritize);

#endif /* PN_DP_MANAGER_H */
