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

#ifndef PECAN_GLOBAL_H
#define PECAN_GLOBAL_H

#define PECAN_MAX_MESSAGE_LENGTH 1564
#define BUDDY_ALIAS_MAXLEN 387

typedef enum {
    MSN_CLIENT_CAP_WIN_MOBILE = 0x000001,
    MSN_CLIENT_CAP_UNKNOWN_1 = 0x000002,
    MSN_CLIENT_CAP_INK_GIF = 0x000004,
    MSN_CLIENT_CAP_INK_ISF = 0x000008,
    MSN_CLIENT_CAP_VIDEO_CHAT = 0x000010,
    MSN_CLIENT_CAP_BASE = 0x000020,
    MSN_CLIENT_CAP_MSNMOBILE = 0x000040,
    MSN_CLIENT_CAP_MSNDIRECT = 0x000080,
    /* MSN_CLIENT_CAP_WEBMSGR    = 0x000200, */
    /* 0x000200 doesn't work with WLM >= 8.5 */
    MSN_CLIENT_CAP_TGW = 0x000800,
    MSN_CLIENT_CAP_SPACE = 0x001000,
    MSN_CLIENT_CAP_MCE = 0x002000,
    MSN_CLIENT_CAP_DIRECTIM = 0x004000,
    MSN_CLIENT_CAP_WINKS = 0x008000,
    MSN_CLIENT_CAP_SEARCH = 0x010000,
    /* MSN_CLIENT_CAP_BOT = 0x020000, */
    /* 0x020000 doesn't work with WLM >= 8.5 */
    MSN_CLIENT_CAP_VOICE_CLIP = 0x040000,
    MSN_CLIENT_CAP_SCHANNEL = 0x080000,
    MSN_CLIENT_CAP_SIP_INVITE = 0x100000,
    MSN_CLIENT_CAP_SDRIVE = 0x400000,
} MsnClientCaps;

typedef enum {
    MSN_CLIENT_VER_5_0 = 0x00,
    MSN_CLIENT_VER_6_0 = 0x10,
    MSN_CLIENT_VER_6_1 = 0x20,
    MSN_CLIENT_VER_6_2 = 0x30,
    MSN_CLIENT_VER_7_0 = 0x40,
    MSN_CLIENT_VER_7_5 = 0x50,
} MsnClientVerId;

#endif /* PECAN_GLOBAL_H */
