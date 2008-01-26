/**
 * Copyright (C) 2007-2008 Felipe Contreras
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

#include "table_private.h"

#include <string.h>

static void
null_cmd_cb(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
}

static void
null_error_cb(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
}

MsnTable *
msn_table_new()
{
	MsnTable *table;

	table = g_new0(MsnTable, 1);

	table->cmds = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_hash_table_destroy);
	table->msgs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	table->errors = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	table->async = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	table->fallback = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	return table;
}

void
msn_table_destroy(MsnTable *table)
{
	g_return_if_fail(table != NULL);

	g_hash_table_destroy(table->cmds);
	g_hash_table_destroy(table->msgs);
	g_hash_table_destroy(table->errors);

	g_hash_table_destroy(table->async);
	g_hash_table_destroy(table->fallback);

	g_free(table);
}

void
msn_table_add_cmd(MsnTable *table,
				  const gchar *command, const gchar *answer, MsnTransCb cb)
{
	GHashTable *cbs;

	g_return_if_fail(table  != NULL);
	g_return_if_fail(answer != NULL);

	cbs = NULL;

	if (command == NULL)
	{
		cbs = table->async;
	}
	else if (strcmp(command, "fallback") == 0)
	{
		cbs = table->fallback;
	}
	else
	{
		cbs = g_hash_table_lookup(table->cmds, command);

		if (cbs == NULL)
		{
			cbs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
			g_hash_table_insert(table->cmds, g_strdup (command), cbs);
		}
	}

	if (cb == NULL)
		cb = null_cmd_cb;

	g_hash_table_insert(cbs, g_strdup (answer), cb);
}

void
msn_table_add_error(MsnTable *table,
					const gchar *answer, MsnErrorCb cb)
{
	g_return_if_fail(table  != NULL);
	g_return_if_fail(answer != NULL);

	if (cb == NULL)
		cb = null_error_cb;

	g_hash_table_insert(table->errors, g_strdup (answer), cb);
}

void
msn_table_add_msg_type(MsnTable *table,
					   const gchar *type, MsnMsgTypeCb cb)
{
	g_return_if_fail(table != NULL);
	g_return_if_fail(type  != NULL);
	g_return_if_fail(cb    != NULL);

#if 0
	if (cb == NULL)
		cb = null_msg_cb;
#endif

	g_hash_table_insert(table->msgs, g_strdup (type), cb);
}
