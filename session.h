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

#ifndef MSN_SESSION_H
#define MSN_SESSION_H

typedef struct MsnSession MsnSession;

#include "ab/pn_contact.h"

struct MsnSwitchBoard;
struct _PurpleAccount;

typedef enum
{
    PN_PERM_DENY,
    PN_PERM_ALLOW
} PnPermission;

/**
 * Types of errors.
 */
typedef enum
{
    MSN_ERROR_SERVCONN,
    MSN_ERROR_UNSUPPORTED_PROTOCOL,
    MSN_ERROR_HTTP_MALFORMED,
    MSN_ERROR_AUTH,
    MSN_ERROR_BAD_BLIST,
    MSN_ERROR_SIGN_OTHER,
    MSN_ERROR_SERV_DOWN,
    MSN_ERROR_SERV_UNAVAILABLE
} MsnErrorType;

#include "switchboard.h"

MsnSession *
msn_session_new (const gchar *username,
                 const gchar *password,
                 gboolean http_method);

/**
 * Destroys an MSN session.
 *
 * @param session The MSN session.
 */
void
msn_session_destroy (MsnSession *session);

void
msn_session_set_username (MsnSession *session, const gchar *value);
const gchar *
msn_session_get_username (MsnSession *session);
void
msn_session_set_password (MsnSession *session, const gchar *value);
const gchar *
msn_session_get_password (MsnSession *session);

/**
 * Retrieves the session contact.
 *
 * @param The MSN session.
 *
 * @return The contact.
 */
struct pn_contact *
msn_session_get_contact (MsnSession *session);

void
msn_session_set_user_data (MsnSession *session,
                           void *user_data);

void *
msn_session_get_user_data (MsnSession *session);

void *
msn_session_get_user_name (MsnSession *session);

/**
 * Connects to and initiates an MSN session.
 *
 * @param session The MSN session.
 * @param host The dispatch server host.
 * @param port The dispatch server port.
 *
 * @return @c TRUE on success, @c FALSE on failure.
 */
gboolean
msn_session_connect (MsnSession *session,
                     const gchar *host,
                     gint port);

/**
 * Disconnects from an MSN session.
 *
 * @param session The MSN session.
 */
void
msn_session_disconnect (MsnSession *session);

 /**
 * Finds a switchboard with the given username.
 *
 * @param session The MSN session.
 * @param username The username to search for.
 *
 * @return The switchboard, if found.
 */
struct MsnSwitchBoard *
msn_session_find_swboard (const MsnSession *session,
                          const gchar *username);

 /**
 * Finds a switchboard with the given conversation.
 *
 * @param session The MSN session.
 * @param conv The conversation to search for.
 *
 * @return The switchboard, if found.
 */
struct MsnSwitchBoard *
msn_session_find_swboard_with_conv (const MsnSession *session,
                                    const struct _PurpleConversation *conv);

/**
 * Finds a switchboard with the given chat ID.
 *
 * @param session The MSN session.
 * @param chat_id The chat ID to search for.
 *
 * @return The switchboard, if found.
 */
struct MsnSwitchBoard *
msn_session_find_swboard_with_id (const MsnSession *session,
                                  gint chat_id);

/**
 * Returns a switchboard to communicate with certain username.
 *
 * @param session The MSN session.
 * @param username The username to search for.
 *
 * @return The switchboard.
 */
struct MsnSwitchBoard *
msn_session_get_swboard (MsnSession *session,
                         const gchar *username);

/**
 * Displays a non fatal error.
 *
 * @param session The MSN session.
 * @param msg The message to display.
 */
void
msn_session_warning (MsnSession *session,
                     const gchar *fmt,
                     ...);

/**
 * Sets an error for the MSN session.
 *
 * @param session The MSN session.
 * @param error The error.
 * @param info Extra information.
 */
void
msn_session_set_error (MsnSession *session,
                       MsnErrorType error,
                       const gchar *info);

/**
 * Finish the login proccess.
 *
 * @param session The MSN session.
 */
void
msn_session_finish_login (MsnSession *session);

void
msn_session_set_bool (MsnSession *session,
                      const gchar *fieldname,
                      gboolean value);

gboolean
msn_session_get_bool (const MsnSession *session,
                      const gchar *fieldname);


void
msn_session_set_prp (MsnSession *session,
                     const gchar *key,
                     const gchar *value);

void
msn_session_set_public_alias (MsnSession *session,
                              const gchar *value);

#endif /* MSN_SESSION_H */
