/**
 * Copyright (C) 2008 Felipe Contreras
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
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

#ifndef MSN_TABLE_H
#define MSN_TABLE_H

#include <glib.h>

#include "msg.h"
#include "transaction.h"

typedef struct MsnTable MsnTable;

MsnTable *msn_table_new (void);
void msn_table_destroy (MsnTable *table);
void msn_table_add_cmd (MsnTable *table, const gchar *command, const gchar *answer, MsnTransCb);
void msn_table_add_error (MsnTable *table, const gchar *answer, MsnErrorCb cb);
void msn_table_add_msg_type (MsnTable *table, const gchar *type, MsnMsgTypeCb cb);

#endif /* MSN_TABLE_H */
