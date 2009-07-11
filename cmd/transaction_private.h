/**
 * Copyright (C) 2007-2009 Felipe Contreras
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

#ifndef MSN_TRANSACTION_PRIVATE_H
#define MSN_TRANSACTION_PRIVATE_H

#include <glib.h>

#include "transaction.h"
#include "command.h"

/**
 * A transaction. A sending command that will initiate the transaction.
 */
struct MsnTransaction
{
    MsnCmdProc *cmdproc;
    guint trId;

    gchar *command;
    gchar *params;

    gpointer data; /**< The data to be used on the different callbacks. */
    GHashTable *callbacks;
    gboolean has_custom_callbacks;
    MsnErrorCb error_cb;

    gchar *payload;
    gsize payload_len;

    guint ref_count;
};

#endif /* MSN_TRANSACTION_PRIVATE_H */
