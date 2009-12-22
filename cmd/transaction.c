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

#include "transaction_private.h"
#include "pn_log.h"

#include <string.h> /* For strlen. */

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

    trans->ref_count = 1;

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

    g_free (trans);
}

MsnTransaction *
msn_transaction_ref (MsnTransaction *trans)
{
    trans->ref_count++;

    return trans;
}

MsnTransaction *
msn_transaction_unref (MsnTransaction *trans)
{
    trans->ref_count--;

    if (trans->ref_count == 0)
    {
        msn_transaction_destroy (trans);
        return NULL;
    }

    return trans;
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

    trans->payload = g_strndup (payload, payload_len);
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
msn_transaction_add_cb (MsnTransaction *trans,
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

void
msn_transaction_set_error_cb (MsnTransaction *trans,
                              MsnErrorCb cb)
{
    trans->error_cb = cb;
}
