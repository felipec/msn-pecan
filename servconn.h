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
#ifndef MSN_SERVCONN_H
#define MSN_SERVCONN_H

typedef struct _MsnServConn MsnServConn;

#include "session.h"
#include "cmdproc.h"

#if 0
struct MsnSession;
struct MsnCmdProc;
#endif

/**
 * A Connection.
 */
struct _MsnServConn
{
    MsnSession *session;  /**< The MSN session of this connection. */
    MsnCmdProc *cmdproc;  /**< The command processor of this connection. */

    void (*destroy_cb)(MsnServConn *); /**< The callback to call when destroying. */
};

MsnServConn *msn_servconn_new ();
void msn_servconn_destroy (MsnServConn *servconn);
void msn_servconn_disconnect (MsnServConn *servconn);

#endif /* MSN_SERVCONN_H */
