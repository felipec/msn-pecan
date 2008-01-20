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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef MSN_CMD_CONN_H
#define MSN_CMD_CONN_H

typedef struct CmdConnObject CmdConnObject;
typedef struct CmdConnObjectClass CmdConnObjectClass;

#include "conn.h"
#include "cmdproc.h"

struct CmdConnObject
{
    ConnObject parent;
    gboolean dispose_has_run;

    MsnCmdProc *cmdproc;
    gsize payload_len;
    gboolean wasted;
    gchar *rx_buf;
    gsize rx_len;
};

struct CmdConnObjectClass
{
    ConnObjectClass parent_class;
};

#define CMD_CONN_OBJECT_TYPE (cmd_conn_object_get_type ())
#define CMD_CONN_OBJECT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), CMD_CONN_OBJECT_TYPE, CmdConnObject))
#define CMD_CONN_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), CMD_CONN_OBJECT_TYPE, CmdConnObjectClass))
#define CMD_CONN_IS_OBJECT(obj) (G_TYPE_CHECK_TYPE ((obj), CMD_CONN_OBJECT_TYPE))
#define CMD_CONN_IS_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), CMD_CONN_OBJECT_TYPE))
#define CMD_CONN_OBJECT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), CMD_CONN_OBJECT_TYPE, CmdConnObjectClass))

GType cmd_conn_object_get_type ();
CmdConnObject *cmd_conn_object_new (gchar *name, ConnObjectType type);
void cmd_conn_object_free (CmdConnObject *conn);

#endif /* MSN_CMD_CONN_H */
