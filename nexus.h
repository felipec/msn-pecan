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

#ifndef MSN_NEXUS_H
#define MSN_NEXUS_H

#include <glib.h>

typedef struct MsnNexus MsnNexus;

#include "session.h"
#include "io/pn_parser.h"

struct MsnNexus {
    MsnSession *session;

    char *login_host;
    char *login_path;
    GHashTable *challenge_data;

    PnParser *parser;
    guint parser_state;
    PnNode *conn;
    gulong open_handler, error_handler;
    GString *header;
};

void msn_nexus_connect(MsnNexus *nexus);
MsnNexus *msn_nexus_new(MsnSession *session);
void msn_nexus_destroy(MsnNexus *nexus);

#endif /* MSN_NEXUS_H */
