/*
 * Copyright © 2006 Felipe Contreras.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __MSN_CMD_H_
#define __MSN_CMD_H_

#include <glib.h>

#include "pecan_buffer.h"

typedef struct MsnCmd MsnCmd;

struct MsnCmd
{
	gchar *id;
	gint trid;
	gchar *args;
	gchar *argv[100];

	gchar *str;
	gchar *buffer_cur;
};

MsnCmd *msn_cmd_new ();
MsnCmd *msn_cmd_new_full (gchar *id, gint trid, gchar *args);
void msn_cmd_print (MsnCmd *cmd);
MsnCmd *msn_cmd_from_string (gchar *string);
void msn_cmd_free (MsnCmd *cmd);
gchar *msn_cmd_get_param (MsnCmd *cmd, gint num);

#endif /* __MSN_CMD_H_ */
