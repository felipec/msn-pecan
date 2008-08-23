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

#include "cmdproc_private.h"
#include "transaction_private.h"
#include "table_private.h"
#include "command_private.h"

#include "io/pecan_node.h"

#include "pecan_log.h"

#include "history.h"

#include <string.h>
#include <stdlib.h>

#include "msn.h"
#include "session.h"

MsnCmdProc *
msn_cmdproc_new()
{
    MsnCmdProc *cmdproc;

    cmdproc = g_new0(MsnCmdProc, 1);

    cmdproc->history = msn_history_new();

    return cmdproc;
}

void
msn_cmdproc_destroy(MsnCmdProc *cmdproc)
{
    pecan_log ("begin");

    pecan_debug ("cmdproc=%p", cmdproc);

    msn_history_destroy(cmdproc->history);

    if (cmdproc->last_cmd != NULL)
        msn_command_destroy(cmdproc->last_cmd);

    g_free(cmdproc);

    pecan_log ("end");
}

void
msn_cmdproc_flush (MsnCmdProc *cmdproc)
{
    pecan_log ("begin");

    pecan_debug ("cmdproc=%p", cmdproc);

    msn_history_flush (cmdproc->history);

    pecan_log ("end");
}

static void
show_debug_cmd(MsnCmdProc *cmdproc, gboolean incoming, const char *command)
{
    char *show;
    char tmp;
    size_t len;

    len = strlen(command);
    show = g_strdup(command);

    tmp = (incoming) ? 'S' : 'C';

    if ((show[len - 1] == '\n') && (show[len - 2] == '\r'))
    {
        show[len - 2] = '\0';
    }

    pecan_info ("%c: %03d: %s", tmp, cmdproc->cmd_count, show);

    g_free(show);
}

void
msn_cmdproc_send_trans(MsnCmdProc *cmdproc, MsnTransaction *trans)
{
    char *data;
    size_t len;

    g_return_if_fail(cmdproc != NULL);
    g_return_if_fail(trans != NULL);

    msn_history_add(cmdproc->history, trans);

    data = msn_transaction_to_string(trans);

    len = strlen(data);

    show_debug_cmd(cmdproc, FALSE, data);

    if (trans->callbacks == NULL)
        trans->callbacks = g_hash_table_lookup(cmdproc->cbs_table->cmds,
                                               trans->command);

    if (trans->payload != NULL)
    {
        data = g_realloc(data, len + trans->payload_len);
        memcpy(data + len, trans->payload, trans->payload_len);
        len += trans->payload_len;
    }

    {
        GIOStatus status;

        status = pecan_node_write (cmdproc->conn, data, len, NULL, NULL);

        if (status != G_IO_STATUS_NORMAL)
            pecan_node_error (cmdproc->conn);
    }

    g_free(data);
}

void
msn_cmdproc_send_quick(MsnCmdProc *cmdproc, const char *command,
                       const char *format, ...)
{
    char *data;
    char *params = NULL;
    size_t len;

    g_return_if_fail(cmdproc != NULL);
    g_return_if_fail(command != NULL);

    if (format != NULL)
    {
        va_list args;
        va_start (args, format);
        params = g_strdup_vprintf (format, args);
        va_end (args);
    }

    if (params != NULL)
        data = g_strdup_printf ("%s %s\r\n", command, params);
    else
        data = g_strdup_printf ("%s\r\n", command);

    g_free(params);

    len = strlen(data);

    show_debug_cmd(cmdproc, FALSE, data);

    {
        GIOStatus status;

        status = pecan_node_write (cmdproc->conn, data, len, NULL, NULL);

        if (status != G_IO_STATUS_NORMAL)
            pecan_node_error (cmdproc->conn);
    }

    g_free(data);
}

void
msn_cmdproc_send_valist (MsnCmdProc *cmdproc,
                         const char *command,
                         const char *format,
                         va_list args)
{
    MsnTransaction *trans;

    g_return_if_fail (cmdproc != NULL);
    g_return_if_fail (command != NULL);

    trans = g_new0 (MsnTransaction, 1);

    trans->command = g_strdup (command);

    if (format != NULL)
    {
        trans->params = g_strdup_vprintf (format, args);
    }

    msn_cmdproc_send_trans (cmdproc, trans);
}

void
msn_cmdproc_send (MsnCmdProc *cmdproc,
                  const char *command,
                  const char *format,
                  ...)
{
    g_return_if_fail (cmdproc != NULL);
    g_return_if_fail (command != NULL);

    {
        va_list args;
        va_start (args, format);
        msn_cmdproc_send_valist (cmdproc, command, format, args);
        va_end (args);
    }
}

void
msn_cmdproc_process_payload(MsnCmdProc *cmdproc, char *payload,
                            int payload_len)
{
    MsnCommand *last;

    g_return_if_fail(cmdproc != NULL);

    last = cmdproc->last_cmd;
    last->payload = g_memdup(payload, payload_len);
    last->payload_len = payload_len;

    if (last->payload_cb != NULL)
        last->payload_cb(cmdproc, last, payload, payload_len);
}

void
msn_cmdproc_process_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    MsnMsgTypeCb cb;

    if (msn_message_get_content_type(msg) == NULL)
    {
        pecan_warning ("failed to find message content");
        return;
    }

    cb = g_hash_table_lookup(cmdproc->cbs_table->msgs,
                             msn_message_get_content_type(msg));

    if (cb == NULL)
    {
        pecan_warning ("unhandled content-type: [%s]",
                     msn_message_get_content_type (msg));

        return;
    }

    cb(cmdproc, msg);
}

void
msn_cmdproc_process_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnTransCb cb = NULL;
    MsnTransaction *trans = NULL;

    g_return_if_fail (cmdproc->cbs_table);

    pecan_log ("begin");

    if (cmd->trId)
    {
        cmd->trans = trans = msn_history_find(cmdproc->history, cmd->trId);
    }

    /* transaction finished. clear timeouts. */
    if (trans)
        msn_transaction_flush (trans);

    if (g_ascii_isdigit(cmd->command[0]))
    {
        if (trans != NULL)
        {
            MsnErrorCb error_cb = NULL;
            int error;

            error = atoi(cmd->command);

            if (trans->error_cb != NULL)
                error_cb = trans->error_cb;

            if (error_cb == NULL && cmdproc->cbs_table->errors != NULL)
                error_cb = g_hash_table_lookup(cmdproc->cbs_table->errors, trans->command);

            if (!error_cb)
                error_cb = cmdproc->error_handler;

            if (error_cb != NULL)
            {
                error_cb(cmdproc, trans, error);
            }
            else
            {
                pecan_error ("unhandled error: [%s]",
                           cmd->command);
            }

            return;
        }
    }

    if (cmdproc->cbs_table->async != NULL)
        cb = g_hash_table_lookup(cmdproc->cbs_table->async, cmd->command);

    if (cb == NULL && trans != NULL)
    {
        if (trans->callbacks != NULL)
            cb = g_hash_table_lookup(trans->callbacks, cmd->command);
    }

    if (cb == NULL && cmdproc->cbs_table->fallback != NULL)
        cb = g_hash_table_lookup(cmdproc->cbs_table->fallback, cmd->command);

    if (cb != NULL)
    {
        cb(cmdproc, cmd);
    }
    else
    {
        pecan_warning ("unhandled command: [%s]",
                     cmd->command);
    }

    pecan_log ("end");
}

void
msn_cmdproc_process_cmd_text(MsnCmdProc *cmdproc, const char *command)
{
    show_debug_cmd(cmdproc, TRUE, command);

    if (cmdproc->last_cmd != NULL)
        msn_command_destroy(cmdproc->last_cmd);

    cmdproc->last_cmd = msn_command_from_string(command);

    msn_cmdproc_process_cmd(cmdproc, cmdproc->last_cmd);
}
