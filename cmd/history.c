/**
 * Copyright (C) 2008 Felipe Contreras
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

#include "history.h"
#include "transaction_private.h"
#include "pecan_log.h"

MsnHistory *
msn_history_new (void)
{
    MsnHistory *history = g_new0 (MsnHistory, 1);

    history->trId = 1;

    history->queue = g_queue_new ();

    return history;
}

void
msn_history_destroy (MsnHistory *history)
{
    MsnTransaction *trans;

    while ((trans = g_queue_pop_head (history->queue)))
        msn_transaction_destroy (trans);

    g_queue_free (history->queue);
    g_free (history);
}

void
msn_history_flush (MsnHistory *history)
{
    MsnTransaction *trans;

    while ((trans = g_queue_pop_head (history->queue)))
        msn_transaction_destroy (trans);
}

static gint
check_trid (gconstpointer a,
            gconstpointer b)
{
    const MsnTransaction *trans;
    guint trid;

    trans = a;
    trid = GPOINTER_TO_INT (b);

    if (trans->trId == trid)
        return 0;

    return 1;
}

MsnTransaction *
msn_history_find (MsnHistory *history,
                  guint trId)
{
    GList *link;

    link = g_queue_find_custom (history->queue, GINT_TO_POINTER (trId), check_trid);

    if (link)
        return link->data;

    return NULL;
}

void
msn_history_add (MsnHistory *history,
                 MsnTransaction *trans)
{
    GQueue *queue;

    g_return_if_fail (history);
    g_return_if_fail (trans);

    queue = history->queue;

    trans->trId = history->trId++;

    g_queue_push_tail (queue, trans);

    if (queue->length > MSN_HIST_ELEMS)
    {
        pecan_warning ("dropping transaction");
        trans = g_queue_pop_head (queue);
        msn_transaction_destroy (trans);
    }
}
