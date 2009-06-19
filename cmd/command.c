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

#include "command_private.h"

#include <string.h>
#include <stdlib.h>

static gboolean
is_num (char *str)
{
    char *c;
    for (c = str; *c; c++)
    {
        if (!(g_ascii_isdigit(*c)))
            return FALSE;
    }

    return TRUE;
}

MsnCommand *
msn_command_from_string (const char *string)
{
    MsnCommand *cmd;
    char *tmp;
    char *param_start;

    g_return_val_if_fail (string, NULL);

    tmp = g_strdup (string);
    param_start = strchr (tmp, ' ');

    cmd = g_new0 (MsnCommand, 1);
    cmd->base = tmp;

    /** @todo check string "preferredEmail: " */

    if (param_start)
    {
        *param_start++ = '\0';
        cmd->params = g_strsplit (param_start, " ", 0);
    }

    if (cmd->params && cmd->params[0])
    {
        char *param;
        int c;

        for (c = 0; cmd->params[c]; c++);
        cmd->param_count = c;

        param = cmd->params[0];

        cmd->tr_id = is_num (param) ? atoi (param) : 0;
    }
    else
        cmd->tr_id = 0;

    return cmd;
}

void
msn_command_free (MsnCommand *cmd)
{
    if (!cmd)
        return;

    g_free (cmd->payload);
    g_free (cmd->base);
    g_strfreev (cmd->params);
    g_free (cmd);
}
