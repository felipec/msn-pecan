/*
 * Copyright (C) 2006-2008 Felipe Contreras.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "pecan_socket.h"
#include "pecan_log.h"

#include <stdbool.h>

#define __USE_GNU
#include <netdb.h>
#include <string.h> /* for memcpy */

#define SOCKET_ERROR -1

void
pecan_socket_connect (const gchar *hostname,
		      guint port,
		      PecanSocketCb connect_cb,
		      gpointer user_data)
{
    int fd;
    struct hostent* host;
    struct sockaddr_in address;
    long host_address;
    gboolean success;

    fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd == SOCKET_ERROR)
    {
        pecan_error ("could not create socket");
        goto leave;
    }

    host = gethostbyname (hostname);

    if (!host)
    {
        pecan_error ("bad hostname: %s", hostname);
        goto leave;
    }

    memcpy (&host_address, host->h_addr, host->h_length);

    address.sin_addr.s_addr = host_address;
    address.sin_port = htons (port);
    address.sin_family = AF_INET;

    pecan_info ("connecting to %s on port %d", hostname, port);

    if (connect (fd, (struct sockaddr*) & address, sizeof (address)) == SOCKET_ERROR)
    {
        pecan_error ("could not connect to host");
        goto leave;
    }

    pecan_info ("connected");

    success = true;

leave:
    {
	PecanSocket *sock;
	sock = g_new0 (PecanSocket, 1);
	sock->fd = fd;
	connect_cb (sock, success, user_data);
	g_free (sock);
    }
}
