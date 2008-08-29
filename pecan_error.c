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

#include "pecan_error.h"
#include "pecan_log.h"
#include "pecan_locale.h"

#include <glib.h>

char *
pecan_error_to_string (guint id)
{
    char *msg;

    switch (id)
    {
        case 0:
            msg = g_strdup (_("Unable to parse message"));
            break;
        case 200:
            msg = g_strdup (_("Syntax Error (probably a client bug)"));
            break;
        case 201:
            msg = g_strdup (_("Invalid e-mail address"));
            break;
        case 205:
            msg = g_strdup (_("User does not exist"));
            break;
        case 206:
            msg = g_strdup (_("Fully qualified domain name missing"));
            break;
        case 207:
            msg = g_strdup (_("Already logged in"));
            break;
        case 208:
            msg = g_strdup (_("Invalid screen name"));
            break;
        case 209:
            msg = g_strdup (_("Invalid friendly name"));
            break;
        case 210:
            msg = g_strdup (_("List full"));
            break;
        case 215:
            msg = g_strdup (_("Already there"));
            break;
        case 216:
            msg = g_strdup (_("Not on list"));
            break;
        case 217:
            msg = g_strdup (_("User is offline"));
            break;
        case 218:
            msg = g_strdup (_("Already in the mode"));
            break;
        case 219:
            msg = g_strdup (_("Already in opposite list"));
            break;
        case 223:
            msg = g_strdup (_("Too many groups"));
            break;
        case 224:
            msg = g_strdup (_("Invalid group"));
            break;
        case 225:
            msg = g_strdup (_("User not in group"));
            break;
        case 229:
            msg = g_strdup (_("Group name too long"));
            break;
        case 230:
            msg = g_strdup (_("Cannot remove group zero"));
            break;
        case 231:
            msg = g_strdup (_("Tried to add a user to a group that doesn't exist"));
            break;
        case 280:
            msg = g_strdup (_("Switchboard failed"));
            break;
        case 281:
            msg = g_strdup (_("Notify transfer failed"));
            break;
        case 300:
            msg = g_strdup (_("Required fields missing"));
            break;
        case 301:
            msg = g_strdup (_("Too many hits to a FND"));
            break;
        case 302:
            msg = g_strdup (_("Not logged in"));
            break;
        case 500:
            msg = g_strdup (_("Service temporarily unavailable"));
            break;
        case 501:
            msg = g_strdup (_("Database server error"));
            break;
        case 502:
            msg = g_strdup (_("Command disabled"));
            break;
        case 510:
            msg = g_strdup (_("File operation error"));
            break;
        case 520:
            msg = g_strdup (_("Memory allocation error"));
            break;
        case 540:
            msg = g_strdup (_("Wrong CHL value sent to server"));
            break;
        case 600:
            msg = g_strdup (_("Server busy"));
            break;
        case 601:
            msg = g_strdup (_("Server unavailable"));
            break;
        case 602:
            msg = g_strdup (_("Peer notification server down"));
            break;
        case 603:
            msg = g_strdup (_("Database connect error"));
            break;
        case 604:
            msg = g_strdup (_("Server is going down (abandon ship)"));
            break;
        case 605:
            msg = g_strdup (_("Server unavailable"));
            break;
        case 707:
            msg = g_strdup (_("Error creating connection"));
            break;
        case 710:
            msg = g_strdup (_("CVR parameters are either unknown or not allowed"));
            break;
        case 711:
            msg = g_strdup (_("Unable to write"));
            break;
        case 712:
            msg = g_strdup (_("Session overload"));
            break;
        case 713:
            msg = g_strdup (_("User is too active"));
            break;
        case 714:
            msg = g_strdup (_("Too many sessions"));
            break;
        case 715:
            msg = g_strdup (_("Passport not verified"));
            break;
        case 717:
            msg = g_strdup (_("Bad friend file"));
            break;
        case 731:
            msg = g_strdup (_("Not expected"));
            break;
        case 800:
            msg = g_strdup (_("Friendly name changes too rapidly"));
            break;
        case 910:
        case 912:
        case 918:
        case 919:
        case 921:
        case 922:
            msg = g_strdup (_("Server too busy"));
            break;
        case 911:
        case 917:
            msg = g_strdup (_("Authentication failed"));
            break;
        case 913:
            msg = g_strdup (_("Not allowed when hiding"));
            break;
        case 914:
        case 915:
        case 916:
            msg = g_strdup (_("Server unavailable"));
            break;
        case 920:
            msg = g_strdup (_("Not accepting new users"));
            break;
        case 923:
            msg = g_strdup (_("Kids Passport without parental consent"));
            break;
        case 924:
            msg = g_strdup (_("Passport account not yet verified"));
            break;
        case 928:
            msg = g_strdup (_("Bad ticket"));
            break;
        default:
            msg = g_strdup_printf (_("Unknown Error Code %u"), id);
            break;
    }

    return msg;
}
