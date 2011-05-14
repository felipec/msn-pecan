/**
 * Copyright (C) 2011 Felipe Contreras
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

#ifndef PN_AUTH_PRIVATE_H
#define PN_AUTH_PRIVATE_H

struct AuthRequest;

struct PnAuth
{
    MsnSession *session;
    struct
    {
        gchar *messenger_msn_com_t;
        gchar *messenger_msn_com_p;

        gchar *messengersecure_live_com;
    } security_token;

    struct
    {
        time_t messenger_msn_com;
        time_t messengersecure_live_com;
    } expiration_time;

    PnAuthCb cb;
    void *cb_data;

    struct AuthRequest *pending_req;
};

#endif /* PN_AUTH_PRIVATE_H */
