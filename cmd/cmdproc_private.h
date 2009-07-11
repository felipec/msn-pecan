/**
 * Copyright (C) 2008-2009 Felipe Contreras.
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

#ifndef MSN_CMDPROC_PRIVATE_H
#define MSN_CMDPROC_PRIVATE_H

#include "cmdproc.h"
#include "table.h"
#include "transaction.h"
#include "pn_timer.h"

struct MsnSession;
struct PnNode;

struct MsnCmdProc
{
    struct MsnSession *session;

    MsnCommand *last_cmd;

    MsnTable *cbs_table;
    MsnErrorCb error_handler;

    /** @todo this doesn't belong here. */
    GHashTable *multiparts; /**< Multi-part message ID's */

    gpointer data; /**< Extra data, like the switchboard. */
    gpointer extra_data; /**< Extra data. */
    guint count;

    GHashTable *transactions;
    struct PnNode *conn;

    struct pn_timer *timer;
};

#endif /* MSN_CMDPROC_PRIVATE_H */
