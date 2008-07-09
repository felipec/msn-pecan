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

#ifndef MSN_CMDPROC_H
#define MSN_CMDPROC_H

typedef struct MsnCmdProc MsnCmdProc;

#include "msg.h"
#include "command.h"
#include "transaction.h"

typedef void (*MsnMsgTypeCb) (MsnCmdProc *cmdproc, MsnMessage *msg);
typedef void (*MsnPayloadCb) (MsnCmdProc *cmdproc, MsnCommand *cmd, gchar *payload, gsize len);

MsnCmdProc *msn_cmdproc_new (void);

void msn_cmdproc_send (MsnCmdProc *cmdproc, const char *command, const char *format, ...);
void msn_cmdproc_send_quick (MsnCmdProc *cmdproc, const char *command, const char *format, ...);
void msn_cmdproc_send_valist (MsnCmdProc *cmdproc, const char *command, const char *format, va_list args);

void msn_cmdproc_send_trans (MsnCmdProc *cmdproc, MsnTransaction *trans);

void msn_cmdproc_destroy (MsnCmdProc *cmdproc);
void msn_cmdproc_flush (MsnCmdProc *cmdproc);
void msn_cmdproc_process_msg (MsnCmdProc *cmdproc, MsnMessage *msg);
void msn_cmdproc_process_cmd (MsnCmdProc *cmdproc, MsnCommand *cmd);
void msn_cmdproc_process_cmd_text (MsnCmdProc *cmdproc, const char *command);
void msn_cmdproc_process_payload (MsnCmdProc *cmdproc, char *payload, int payload_len);

#endif /* MSN_CMDPROC_H */
