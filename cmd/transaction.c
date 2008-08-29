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

#include "transaction_private.h"
#include "pecan_log.h"

#include <string.h> /* For strlen. */

#ifdef HAVE_LIBPURPLE
#include "fix_purple.h"
#endif /* HAVE_LIBPURPLE */

MsnTransaction *
msn_transaction_new (MsnCmdProc *cmdproc,
                     const gchar *command,
                     const gchar *format,
                     ...)
{
    MsnTransaction *trans;
    va_list arg;

    g_return_val_if_fail (command, NULL);

    trans = g_new0 (MsnTransaction, 1);

    trans->cmdproc = cmdproc;
    trans->command = g_strdup (command);

    if (format)
    {
        va_start (arg, format);
        trans->params = g_strdup_vprintf (format, arg);
        va_end (arg);
    }

    return trans;
}

void
msn_transaction_destroy (MsnTransaction *trans)
{
    g_return_if_fail (trans);

    g_free (trans->command);
    g_free (trans->params);
    g_free (trans->payload);

    if (trans->callbacks && trans->has_custom_callbacks)
        g_hash_table_destroy (trans->callbacks);

    if (trans->timer)
        g_source_remove (trans->timer);

    g_free (trans);
}

void
msn_transaction_flush (MsnTransaction *trans)
{
    if (trans->timer)
    {
        g_source_remove (trans->timer);
        trans->timer = 0;
    }
}

gchar *
msn_transaction_to_string (MsnTransaction *trans)
{
    gchar *str;

    g_return_val_if_fail (trans, FALSE);

    if (trans->params)
        str = g_strdup_printf ("%s %u %s\r\n", trans->command, trans->trId, trans->params);
    else
        str = g_strdup_printf ("%s %u\r\n", trans->command, trans->trId);

    return str;
}

void
msn_transaction_set_payload (MsnTransaction *trans,
                             const gchar *payload,
                             gsize payload_len)
{
    g_return_if_fail (trans);
    g_return_if_fail (payload);

    trans->payload = g_strdup (payload);
    trans->payload_len = payload_len ? payload_len : strlen (trans->payload);
}

void
msn_transaction_set_data (MsnTransaction *trans,
                          const gpointer data)
{
    g_return_if_fail (trans);

    trans->data = data;
}

void
msn_transaction_add_cb( MsnTransaction *trans,
                        const gchar *answer,
                        MsnTransCb cb)
{
    g_return_if_fail (trans);
    g_return_if_fail (answer);

    if (!trans->callbacks)
    {
        trans->has_custom_callbacks = TRUE;
        trans->callbacks = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    }
    else if (!trans->has_custom_callbacks)
    {
        g_return_if_reached ();
    }

    g_hash_table_insert (trans->callbacks, g_strdup (answer), cb);
}

static gboolean
transaction_timeout (gpointer data)
{
    MsnTransaction *trans;

    trans = data;
    g_return_val_if_fail (trans, FALSE);

    pecan_log ("cmd=[%s],trid=[%d],params=[%s]",
               trans->command, trans->trId, trans->params);

    if (trans->timeout_cb)
        trans->timeout_cb (trans->cmdproc, trans);

    return FALSE;
}

void
msn_transaction_set_timeout_cb (MsnTransaction *trans,
                                MsnTimeoutCb cb)
{
    if (trans->timer)
    {
        pecan_error ("this shouldn't be happening");
        g_source_remove (trans->timer);
    }
    trans->timeout_cb = cb;
    trans->timer = g_timeout_add_seconds (60, transaction_timeout, trans);
}

void
msn_transaction_set_error_cb (MsnTransaction *trans,
                              MsnErrorCb cb)
{
    trans->error_cb = cb;
}
