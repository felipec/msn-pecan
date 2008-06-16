/*
 * Copyright (C) 2008 Felipe Contreras.
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

#ifndef MSN_CMD_CONN_H
#define MSN_CMD_CONN_H

#include <glib-object.h>

typedef struct PecanCmdServer PecanCmdServer;

#include "pecan_node.h"

#define CMD_PECAN_NODE_TYPE (pecan_cmd_server_get_type ())
#define CMD_PECAN_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), CMD_PECAN_NODE_TYPE, PecanCmdServer))
#define CMD_PECAN_NODE_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), CMD_PECAN_NODE_TYPE, PecanCmdServerClass))
#define CMD_PECAN_IS_NODE(obj) (G_TYPE_CHECK_TYPE ((obj), CMD_PECAN_NODE_TYPE))
#define CMD_PECAN_IS_NODE_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), CMD_PECAN_NODE_TYPE))
#define CMD_PECAN_NODE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), CMD_PECAN_NODE_TYPE, PecanCmdServerClass))

PecanCmdServer *pecan_cmd_server_new (const gchar *name, PecanNodeType type);
void pecan_cmd_server_free (PecanCmdServer *conn);

#endif /* MSN_CMD_CONN_H */
