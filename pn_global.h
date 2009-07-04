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

#ifndef PN_GLOBAL_H
#define PN_GLOBAL_H

#define PN_BUF_LEN 8192
#define PN_MAX_MESSAGE_LENGTH 1564

#define BUDDY_ALIAS_MAXLEN 387 /** @todo why is this needed? */

typedef enum {
    PN_CLIENT_CAP_WIN_MOBILE = 0x000001,
    PN_CLIENT_CAP_UNKNOWN_1 = 0x000002,
    PN_CLIENT_CAP_INK_GIF = 0x000004,
    PN_CLIENT_CAP_INK_ISF = 0x000008,
    PN_CLIENT_CAP_VIDEO_CHAT = 0x000010,
    PN_CLIENT_CAP_BASE = 0x000020,
    PN_CLIENT_CAP_MSNMOBILE = 0x000040,
    PN_CLIENT_CAP_MSNDIRECT = 0x000080,
    /* PN_CLIENT_CAP_WEBMSGR = 0x000200, */
    /* 0x000200 doesn't work with WLM >= 8.5 */
    PN_CLIENT_CAP_TGW = 0x000800,
    PN_CLIENT_CAP_SPACE = 0x001000,
    PN_CLIENT_CAP_MCE = 0x002000,
    PN_CLIENT_CAP_DIRECTIM = 0x004000,
    PN_CLIENT_CAP_WINKS = 0x008000,
    PN_CLIENT_CAP_SEARCH = 0x010000,
    /* PN_CLIENT_CAP_BOT = 0x020000, */
    /* 0x020000 doesn't work with WLM >= 8.5 */
    PN_CLIENT_CAP_VOICE_CLIP = 0x040000,
    PN_CLIENT_CAP_SCHANNEL = 0x080000,
    PN_CLIENT_CAP_SIP_INVITE = 0x100000,
    PN_CLIENT_CAP_SDRIVE = 0x400000,
} PnClientCaps;

typedef enum {
    PN_CLIENT_VER_5_0 = 0x00,
    PN_CLIENT_VER_6_0 = 0x10,
    PN_CLIENT_VER_6_1 = 0x20,
    PN_CLIENT_VER_6_2 = 0x30,
    PN_CLIENT_VER_7_0 = 0x40,
    PN_CLIENT_VER_7_5 = 0x50,
} PnClientVerId;

#endif /* PN_GLOBAL_H */
