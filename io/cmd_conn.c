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

#include "cmd_conn.h"
#include "msn_log.h"

static ConnObjectClass *parent_class = NULL;

CmdConnObject *
cmd_conn_object_new (gchar *name,
                     ConnObjectType type)
{
    CmdConnObject *conn;

    msn_log ("begin");

    conn = CMD_CONN_OBJECT (g_type_create_instance (CMD_CONN_OBJECT_TYPE));

    {
        ConnObject *tmp = CONN_OBJECT (conn);
        tmp->name = g_strdup (name);
        tmp->type = type;
    }

    msn_log ("end");

    return conn;
}

void
cmd_conn_object_free (CmdConnObject *conn)
{
    msn_log ("begin");

    g_object_unref (G_OBJECT (conn));

    msn_log ("end");
}

/* GObject stuff. */

static void
dispose (GObject *obj)
{
    CmdConnObject *conn = CMD_CONN_OBJECT (obj);

    if (!conn->dispose_has_run)
    {
        conn->dispose_has_run = TRUE;
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
finalize (GObject *obj)
{
    CmdConnObject *conn = CMD_CONN_OBJECT (obj);

    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    ConnObjectClass *conn_class = CONN_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

#if 0
    conn_class->connect = &connect_impl;
    conn_class->error = &error_impl;
    conn_class->read = &read_impl;
#endif

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
    CmdConnObject *conn = CMD_CONN_OBJECT (instance);

    conn->dispose_has_run = FALSE;
}

GType
cmd_conn_object_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        static const GTypeInfo type_info =
        {
            sizeof (CmdConnObjectClass),
            NULL, /* base_init */
            NULL, /* base_finalize */
            class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (CmdConnObject),
            0, /* n_preallocs */
            instance_init /* instance_init */
        };

        type = g_type_register_static (CONN_OBJECT_TYPE, "CmdConnObjectType", &type_info, 0);
    }

    return type;
}
