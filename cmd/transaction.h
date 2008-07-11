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

#ifndef MSN_TRANSACTION_H
#define MSN_TRANSACTION_H

#include <glib.h>

typedef struct MsnTransaction MsnTransaction;

#include "cmdproc.h"
#include "command.h"

typedef void (*MsnTransCb) (MsnCmdProc *cmdproc, MsnCommand *cmd);
typedef void (*MsnErrorCb) (MsnCmdProc *cmdproc, MsnTransaction *trans, gint error);
typedef void (*MsnTimeoutCb) (MsnCmdProc *cmdproc, MsnTransaction *trans);

MsnTransaction *msn_transaction_new (MsnCmdProc *cmdproc, const gchar *command, const gchar *format, ...);
void msn_transaction_destroy (MsnTransaction *trans);
void msn_transaction_flush (MsnTransaction *trans);
char *msn_transaction_to_string (MsnTransaction *trans);
void msn_transaction_set_payload (MsnTransaction *trans, const gchar *payload, gsize payload_len);
void msn_transaction_set_data (MsnTransaction *trans, void *data);
void msn_transaction_add_cb (MsnTransaction *trans, const gchar *answer, MsnTransCb cb);
void msn_transaction_set_error_cb (MsnTransaction *trans, MsnErrorCb cb);
void msn_transaction_set_timeout_cb (MsnTransaction *trans, MsnTimeoutCb cb);

#endif /* MSN_TRANSACTION_H */
