/*
 * Copyright (C) 2008-2009 Felipe Contreras.
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

#ifndef PN_CMD_SERVER_H
#define PN_CMD_SERVER_H

#include <glib-object.h>

typedef struct PnCmdServer PnCmdServer;
typedef struct PnCmdServerClass PnCmdServerClass;

#include "pn_node.h"

#define PN_CMD_SERVER_TYPE (pn_cmd_server_get_type ())
#define PN_CMD_SERVER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), PN_CMD_SERVER_TYPE, PnCmdServer))
#define PN_CMD_SERVER_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), PN_CMD_SERVER_TYPE, PnCmdServerClass))
#define PN_CMD_SERVER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), PN_CMD_SERVER_TYPE, PnCmdServerClass))

PnCmdServer *pn_cmd_server_new (PnNodeType type);
void pn_cmd_server_free (PnCmdServer *conn);

void pn_cmd_server_send (PnCmdServer *conn, const char *command, const char *format, ...);

GType pn_cmd_server_get_type (void);

#endif /* PN_CMD_SERVER_H */
