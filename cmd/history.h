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

#ifndef MSN_HISTORY_H
#define MSN_HISTORY_H

#define MSN_HIST_ELEMS 0x30

typedef struct MsnHistory MsnHistory;

#include "transaction.h"

/**
 * The history.
 */
struct MsnHistory
{
    GQueue *queue;
    guint trId;
};

MsnHistory *msn_history_new (void);
void msn_history_destroy (MsnHistory *history);
void msn_history_flush (MsnHistory *history);
MsnTransaction *msn_history_find (MsnHistory *history, guint triId);
void msn_history_add (MsnHistory *history, MsnTransaction *trans);

#endif /* MSN_HISTORY_H */
