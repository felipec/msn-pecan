/**
 * Copyright (C) 2007-2008 Felipe Contreras
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

#ifndef PECAN_UD_H
#define PECAN_UD_H

typedef struct PecanUdManager PecanUdManager;

#include <glib.h>
#include "session.h"
#include "ab/pecan_contact.h"
#include "cvr/pecan_slp_object.h"

struct PecanUdManager
{
    MsnSession *session;
    GQueue *requests;
    gint window;
    guint timer;
};

PecanUdManager *pecan_ud_manager_new (MsnSession *session);
void pecan_ud_manager_free (PecanUdManager *udm);
void pecan_ud_manager_contact_set_object (PecanContact *contact, MsnObject *obj);

#endif /* PECAN_UD_H */
