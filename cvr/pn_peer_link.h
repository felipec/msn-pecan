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

#ifndef PN_PEERLINK_H
#define PN_PEERLINK_H

#include <glib.h>

struct pn_peer_msg;
struct pn_peer_call;
struct pn_msnobj;

struct MsnSession;
struct MsnMessage;

struct _PurpleXfer;

typedef void (*MsnSlpCb) (struct pn_peer_call *call, const guchar *data, gsize size);
typedef void (*MsnSlpEndCb) (struct pn_peer_call *call, struct MsnSession *session);

struct pn_peer_link *pn_peer_link_new(struct MsnSession *session,
                                      const char *username);
void pn_peer_link_free(struct pn_peer_link *link);
struct pn_peer_link *pn_peer_link_ref(struct pn_peer_link *link);
struct pn_peer_link *pn_peer_link_unref(struct pn_peer_link *link);

const char *pn_peer_link_get_passport(const struct pn_peer_link *link);
struct MsnSession *pn_peer_link_get_session(const struct pn_peer_link *link);

void pn_peer_link_add_call(struct pn_peer_link *link,
                           struct pn_peer_call *call);
void pn_peer_link_remove_call(struct pn_peer_link *link,
                              struct pn_peer_call *call);
struct pn_peer_call *pn_peer_link_find_slp_call(struct pn_peer_link *link,
                                                const char *id);
void pn_peer_link_queue_msg(struct pn_peer_link *link,
                            struct pn_peer_msg *peer_msg);
void pn_peer_link_send_msg(struct pn_peer_link *link,
                           struct pn_peer_msg *peer_msg);
void pn_peer_link_unleash(struct pn_peer_link *link);
void pn_peer_link_process_msg(struct pn_peer_link *link,
                              struct MsnMessage *msg,
                              int type,
                              void *user_data);

void pn_peer_link_request_object(struct pn_peer_link *link,
                                 const char *info,
                                 MsnSlpCb cb,
                                 MsnSlpEndCb end_cb,
                                 const struct pn_msnobj *obj);

struct pn_peer_link *msn_session_find_peer_link(struct MsnSession *session,
                                                const char *who);
struct pn_peer_link *msn_session_get_peer_link(struct MsnSession *session,
                                               const char *username);

struct pn_direct_conn *pn_peer_link_get_directconn(const struct pn_peer_link *link);
void pn_peer_link_set_directconn(struct pn_peer_link *link,
                                 struct pn_direct_conn *direct_conn);

#endif /* PN_PEERLINK_H */
