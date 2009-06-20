/**
 * Copyright (C) 2007-2009 Felipe Contreras
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

#ifndef PECAN_DP_MANAGER_H
#define PECAN_DP_MANAGER_H

typedef struct PecanDpManager PecanDpManager;

#include <glib.h>
#include "session.h"
#include "ab/pecan_contact.h"
#include "cvr/pecan_slp_object.h"

PecanDpManager *pecan_dp_manager_new (MsnSession *session);
void pecan_dp_manager_free (PecanDpManager *dpm);
void pecan_dp_manager_contact_set_object (PecanContact *contact, MsnObject *obj);

#endif /* PECAN_DP_MANAGER_H */
