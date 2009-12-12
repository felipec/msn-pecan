/**
 * Copyright (C) 2008-2009 Felipe Contreras.
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

#include "cmdproc_private.h"
#include "msg_private.h"
#include "transaction_private.h"
#include "table_private.h"
#include "command_private.h"

#include "io/pn_node.h"
#include "io/pn_node_private.h"

#include "pn_log.h"

#include <string.h>
#include <stdlib.h>

#include "session.h"

MsnCmdProc *
msn_cmdproc_new (void)
{
    MsnCmdProc *cmdproc;

    cmdproc = g_new0 (MsnCmdProc, 1);
    cmdproc->transactions = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                   NULL, (GDestroyNotify) msn_transaction_unref);

    cmdproc->multiparts = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                 NULL, (GDestroyNotify) msn_message_unref);

    return cmdproc;
}

void
msn_cmdproc_destroy (MsnCmdProc *cmdproc)
{
    pn_log ("begin");

    pn_debug ("cmdproc=%p", cmdproc);

    pn_timer_free (cmdproc->timer);

    msn_command_free (cmdproc->last_cmd);
    g_hash_table_destroy (cmdproc->transactions);

    g_hash_table_destroy (cmdproc->multiparts);

    g_free (cmdproc);

    pn_log ("end");
}

void
msn_cmdproc_flush (MsnCmdProc *cmdproc)
{
    pn_log ("begin");

    pn_debug ("cmdproc=%p", cmdproc);

    g_hash_table_remove_all (cmdproc->transactions);

    pn_log ("end");
}

void
msn_cmdproc_set_timeout (MsnCmdProc *cmdproc,
                         guint interval,
                         GSourceFunc function,
                         gpointer data)
{
    cmdproc->timer = pn_timer_new (function, data);
    pn_timer_start (cmdproc->timer, interval);
}

static void
show_debug_cmd (MsnCmdProc *cmdproc,
                gboolean incoming,
                const char *command)
{
    char *show;
    char tmp;
    size_t len;

    len = strlen (command);
    show = g_strdup (command);

    tmp = (incoming) ? 'S' : 'C';

    if ((show[len - 1] == '\n') && (show[len - 2] == '\r'))
        show[len - 2] = '\0';

    if (cmdproc->conn->name)
        pn_info ("%c: %03d: %s: %s", tmp, cmdproc->conn->id, cmdproc->conn->name, show);
    else
        pn_info ("%c: %03d: %s", tmp, cmdproc->conn->id, show);

    g_free (show);
}

void
msn_cmdproc_send_trans (MsnCmdProc *cmdproc,
                        MsnTransaction *trans)
{
    char *data;
    size_t len;

    g_return_if_fail (cmdproc);
    g_return_if_fail (trans);

    trans->trId = ++cmdproc->count;
    g_hash_table_insert (cmdproc->transactions, GINT_TO_POINTER (trans->trId), trans);

    data = msn_transaction_to_string (trans);

    len = strlen (data);

    show_debug_cmd (cmdproc, FALSE, data);

    if (!trans->callbacks)
        trans->callbacks = g_hash_table_lookup (cmdproc->cbs_table->cmds,
                                                trans->command);

    if (trans->payload)
    {
        data = g_realloc (data, len + trans->payload_len);
        memcpy (data + len, trans->payload, trans->payload_len);
        len += trans->payload_len;
    }

    if (cmdproc->timer)
        pn_timer_restart(cmdproc->timer);

    {
        GIOStatus status;

        status = pn_node_write (cmdproc->conn, data, len, NULL, NULL);

        if (status != G_IO_STATUS_NORMAL)
            pn_node_error (cmdproc->conn);
    }

    g_free (data);
}

void
msn_cmdproc_send_quick (MsnCmdProc *cmdproc,
                        const char *command,
                        const char *format,
                        ...)
{
    char *data;
    char *params = NULL;
    size_t len;

    g_return_if_fail (cmdproc);
    g_return_if_fail (command);

    if (format)
    {
        va_list args;
        va_start (args, format);
        params = g_strdup_vprintf (format, args);
        va_end (args);
    }

    if (params)
        data = g_strdup_printf ("%s %s\r\n", command, params);
    else
        data = g_strdup_printf ("%s\r\n", command);

    g_free (params);

    len = strlen (data);

    show_debug_cmd (cmdproc, FALSE, data);

    {
        GIOStatus status;

        status = pn_node_write (cmdproc->conn, data, len, NULL, NULL);

        if (status != G_IO_STATUS_NORMAL)
            pn_node_error (cmdproc->conn);
    }

    g_free (data);
}

void
msn_cmdproc_send_valist (MsnCmdProc *cmdproc,
                         const char *command,
                         const char *format,
                         va_list args)
{
    MsnTransaction *trans;

    g_return_if_fail (cmdproc);
    g_return_if_fail (command);

    trans = g_new0 (MsnTransaction, 1);
    trans->ref_count = 1;

    trans->command = g_strdup (command);

    if (format)
        trans->params = g_strdup_vprintf (format, args);

    msn_cmdproc_send_trans (cmdproc, trans);
}

void
msn_cmdproc_send (MsnCmdProc *cmdproc,
                  const char *command,
                  const char *format,
                  ...)
{
    g_return_if_fail (cmdproc);
    g_return_if_fail (command);

    {
        va_list args;
        va_start (args, format);
        msn_cmdproc_send_valist (cmdproc, command, format, args);
        va_end (args);
    }
}

void
msn_cmdproc_process_payload (MsnCmdProc *cmdproc,
                             char *payload,
                             int payload_len)
{
    MsnCommand *last;

    g_return_if_fail (cmdproc);

    last = cmdproc->last_cmd;
    last->payload = g_memdup (payload, payload_len);
    last->payload_len = payload_len;

    if (last->payload_cb)
        last->payload_cb (cmdproc, last, payload, payload_len);
}

void
msn_cmdproc_process_msg (MsnCmdProc *cmdproc,
                         MsnMessage *msg)
{
    MsnMsgTypeCb cb;
    const gchar *message_id = NULL;

    /* Multi-part messages */
    if ((message_id = msn_message_get_attr (msg, "Message-ID")))
    {
        const gchar *chunk_text = msn_message_get_attr (msg, "Chunks");
        guint chunk;

        if (chunk_text)
        {
            chunk = strtol (chunk_text, NULL, 10);
            /* 1024 chunks of ~1300 bytes is ~1MB, which seems OK to prevent
               some random client causing pidgin to hog a ton of memory.
               Probably should figure out the maximum that the official client
               actually supports, though. */
            if (chunk > 0 && chunk < 1024)
            {
                msg->total_chunks = chunk;
                msg->received_chunks = 1;
                g_hash_table_insert (cmdproc->multiparts, (gpointer) message_id, msn_message_ref (msg));

                pn_debug ("chunked message: message_id=[%s],total chunks=[%d]", message_id, chunk);
            }
            else
            {
                pn_error ("chunked message: message_id=[%s] has too many chunks: %d", message_id, chunk);
            }

            return;
        }
        else
        {
            chunk_text = msn_message_get_attr (msg, "Chunk");

            if (chunk_text != NULL)
            {
                MsnMessage *first = g_hash_table_lookup (cmdproc->multiparts, message_id);
                chunk = strtol (chunk_text, NULL, 10);

                if (first == NULL)
                {
                    pn_error ("chunked message: unable to find first chunk of message_id %s to correspond with chunk %d", message_id, chunk+1);
                }
                else if (first->received_chunks == chunk)
                {
                    /* Chunk is from 1 to total-1 (doesn't count first one) */
                    pn_info ("chunked message: received chunk %d of %d, message_id=[%s]", chunk+1, first->total_chunks, message_id);

                    first->body = g_realloc (first->body, first->body_len + msg->body_len);
                    memcpy (first->body + first->body_len, msg->body, msg->body_len);
                    first->body_len += msg->body_len;
                    first->received_chunks++;

                    if (first->received_chunks != first->total_chunks)
                        return;
                    else
                        /* We're done! Send it along... The caller takes care of
                           freeing the old one. */
                        msg = first;
                }
                else
                {
                    /* TODO: Can you legitimately receive chunks out of order? */
                    g_hash_table_remove (cmdproc->multiparts, message_id);
                    return;
                }
            }
            else
            {
                pn_error("chunked message: received message_id=[%s] with no chunk number", message_id);
            }
        }
    }

    if (!msn_message_get_content_type (msg))
    {
        pn_warning ("failed to find message content");
        return;
    }

    cb = g_hash_table_lookup (cmdproc->cbs_table->msgs,
                              msn_message_get_content_type (msg));

    if (cb)
        cb (cmdproc, msg);
    else
        pn_warning ("unhandled content-type: [%s]",
                    msn_message_get_content_type (msg));

    if (message_id != NULL)
        g_hash_table_remove (cmdproc->multiparts, message_id);
}

void
msn_cmdproc_process_cmd (MsnCmdProc *cmdproc,
                         MsnCommand *cmd)
{
    MsnTransCb cb = NULL;
    MsnTransaction *trans = NULL;

    g_return_if_fail (cmdproc->cbs_table);

    pn_log ("begin");

    if (cmd->tr_id)
        cmd->trans = trans = g_hash_table_lookup (cmdproc->transactions, GINT_TO_POINTER (cmd->tr_id));

    if (g_ascii_isdigit (cmd->base[0]))
    {
        if (trans)
        {
            MsnErrorCb error_cb = NULL;
            int error;

            error = atoi (cmd->base);

            if (trans->error_cb)
                error_cb = trans->error_cb;

            if (!error_cb && cmdproc->cbs_table->errors)
                error_cb = g_hash_table_lookup (cmdproc->cbs_table->errors, trans->command);

            if (!error_cb)
                error_cb = cmdproc->error_handler;

            if (error_cb)
                error_cb (cmdproc, trans, error);
            else
                pn_error ("unhandled error: [%s]", cmd->base);

            return;
        }
    }

    if (cmdproc->cbs_table->async)
        cb = g_hash_table_lookup (cmdproc->cbs_table->async, cmd->base);

    if (!cb)
        if (trans && trans->callbacks)
            cb = g_hash_table_lookup (trans->callbacks, cmd->base);

    if (!cb && cmdproc->cbs_table->fallback)
        cb = g_hash_table_lookup (cmdproc->cbs_table->fallback, cmd->base);

    if (cb)
        cb (cmdproc, cmd);
    else
        pn_warning ("unhandled command: [%s]", cmd->base);

    if (cmd->trans)
        g_hash_table_remove (cmdproc->transactions, GINT_TO_POINTER (cmd->tr_id));

    pn_log ("end");
}

void
msn_cmdproc_process_cmd_text (MsnCmdProc *cmdproc,
                              const char *command)
{
    show_debug_cmd (cmdproc, TRUE, command);

    msn_command_free (cmdproc->last_cmd);

    cmdproc->last_cmd = msn_command_from_string (command);

    msn_cmdproc_process_cmd (cmdproc, cmdproc->last_cmd);
}
