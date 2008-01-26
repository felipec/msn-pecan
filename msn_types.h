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

#ifndef MSN_TYPES_H
#define MSN_TYPES_H

typedef struct MsnMessage MsnMessage;
typedef struct MsnCmdProc MsnCmdProc;
typedef struct MsnTransaction MsnTransaction;
typedef struct MsnCommand MsnCommand;
typedef struct MsnTable MsnTable;

#include <glib.h>

typedef void (*MsnTransCb) (MsnCmdProc *cmdproc, MsnCommand *cmd);
typedef void (*MsnErrorCb) (MsnCmdProc *cmdproc, MsnTransaction *trans, int error);
typedef void (*MsnTimeoutCb) (MsnCmdProc *cmdproc, MsnTransaction *trans);
typedef void (*MsnMsgCb) (MsnMessage *, void *data);
typedef void (*MsnMsgTypeCb) (MsnCmdProc *cmdproc, MsnMessage *msg);
typedef void (*MsnPayloadCb) (MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len);

#include "command.h"
#include "cmdproc.h"
#include "msg.h"
#include "transaction.h"
#include "table.h"

struct MsnSession;
struct MsnHistory;
struct ConnObject;

/**
 * A received command.
 */
struct MsnCommand
{
    unsigned int trId;

    char *command;
    char **params;
    guint param_count;

    int ref_count;

    MsnTransaction *trans;

    char *payload;
    size_t payload_len;

    MsnPayloadCb payload_cb;
};

/**
 * A transaction. A sending command that will initiate the transaction.
 */
struct MsnTransaction
{
    MsnCmdProc *cmdproc;
    unsigned int trId;

    char *command;
    char *params;

    int timer;

    void *data; /**< The data to be used on the different callbacks. */
    GHashTable *callbacks;
    gboolean has_custom_callbacks;
    MsnErrorCb error_cb;
    MsnTimeoutCb timeout_cb;

    char *payload;
    size_t payload_len;

    GQueue *queue;
    MsnCommand *pendent_cmd; /**< The command that is waiting for the result of
                               this transaction. */
};

struct MsnCmdProc
{
    struct MsnSession *session;

    GQueue *txqueue;

    MsnCommand *last_cmd;

    MsnTable *cbs_table;

    gpointer data; /**< Extra data, like the switchboard. */
    guint cmd_count;

    struct MsnHistory *history;
    struct ConnObject *conn;
};

struct MsnTable
{
    GHashTable *cmds;
    GHashTable *msgs;
    GHashTable *errors;

    GHashTable *async;
    GHashTable *fallback;
};

typedef struct
{
	guint32 session_id;
	guint32 id;
	guint64 offset;
	guint64 total_size;
	guint32 length;
	guint32 flags;
	guint32 ack_id;
	guint32 ack_sub_id;
	guint64 ack_size;

} MsnSlpHeader;

typedef struct
{
	guint32 value;

} MsnSlpFooter;

/**
 * A message.
 */
struct MsnMessage
{
    size_t ref_count;           /**< The reference count.       */

    MsnMsgType type;

    gboolean msnslp_message;

    char *remote_user;
    char flag;

    char *content_type;
    char *charset;
    char *body;
    gsize body_len;

    GHashTable *attr_table;
    GList *attr_list;

    gboolean ack_ref;           /**< A flag that states if this message has
                                  been ref'ed for using it in a callback. */

    MsnCommand *cmd;
    MsnTransaction *trans;

    MsnMsgCb ack_cb; /**< The callback to call when we receive an ACK of this
                       message. */
    MsnMsgCb nak_cb; /**< The callback to call when we receive a NAK of this
                       message. */
    void *ack_data; /**< The data used by callbacks. */

    MsnMsgErrorType error; /**< The error of the message. */

    MsnSlpHeader msnslp_header;
    MsnSlpFooter msnslp_footer;
};

#endif /* MSN_TYPES_H */
