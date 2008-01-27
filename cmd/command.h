/**
 * Copyright (C) 2008 Felipe Contreras.
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

#ifndef MSN_COMMAND_H
#define MSN_COMMAND_H

#include <glib.h>

typedef struct MsnCommand MsnCommand;

MsnCommand *msn_command_from_string (const gchar *string);
void msn_command_destroy (MsnCommand *cmd);
MsnCommand *msn_command_ref (MsnCommand *cmd);
MsnCommand *msn_command_unref (MsnCommand *cmd);

#endif /* MSN_COMMAND_H */
