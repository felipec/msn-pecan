/**
 * Copyright (C) 2007-2008 Felipe Contreras
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

#include "msn.h"
#include "fix_purple.h"

#include <string.h> /* for strcmp. */

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <connection.h>

#if !GLIB_CHECK_VERSION(2,16,0)
int
g_strcmp0 (const char *str1,
           const char *str2)
{
    if (!str1)
        return -(str1 != str2);
    if (!str2)
        return str1 != str2;
    return strcmp (str1, str2);
}
#endif /* !GLIB_CHECK_VERSION(2,16,0) */

/*
 * Copyright 2004 Tor Lillqvist
 *
 * This code is licenced under LGPLv2+
 */
#if !GLIB_CHECK_VERSION(2,6,0)

#define G_STDIO_NO_WRAP_ON_UNIX

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef G_OS_WIN32
#include <windows.h>
#include <errno.h>
#include <wchar.h>
#include <direct.h>
#include <io.h>
#endif

#include <glib/gstdio.h>

int
g_open (const gchar *filename,
        int flags,
        int mode)
{
#ifdef G_OS_WIN32
    wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
    int retval;
    int save_errno;

    if (wfilename == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    retval = _wopen (wfilename, flags, mode);
    save_errno = errno;

    g_free (wfilename);

    errno = save_errno;
    return retval;
#else
    return open (filename, flags, mode);
#endif
}

int
g_stat (const gchar *filename,
        struct stat *buf)
{
#ifdef G_OS_WIN32
    wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
    int retval;
    int save_errno;
    int len;

    if (wfilename == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    len = wcslen (wfilename);
    while (len > 0 && G_IS_DIR_SEPARATOR (wfilename[len-1]))
        len--;
    if (len > 0 &&
        (!g_path_is_absolute (filename) || len > g_path_skip_root (filename) - filename))
        wfilename[len] = '\0';

    retval = _wstat (wfilename, (struct _stat *) buf);
    save_errno = errno;

    g_free (wfilename);

    errno = save_errno;
    return retval;
#else
    return stat (filename, buf);
#endif
}

FILE *
g_fopen (const gchar *filename,
         const gchar *mode)
{
#ifdef G_OS_WIN32
    wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
    wchar_t *wmode;
    FILE *retval;
    int save_errno;

    if (wfilename == NULL)
    {
        errno = EINVAL;
        return NULL;
    }

    wmode = g_utf8_to_utf16 (mode, -1, NULL, NULL, NULL);

    if (wmode == NULL)
    {
        g_free (wfilename);
        errno = EINVAL;
        return NULL;
    }

    retval = _wfopen (wfilename, wmode);
    save_errno = errno;

    g_free (wfilename);
    g_free (wmode);

    errno = save_errno;
    return retval;
#else
    return fopen (filename, mode);
#endif
}

#endif /* !GLIB_CHECK_VERSION(2,6,0) */

void
purple_buddy_set_displayname (PurpleConnection *gc,
                              const gchar *who,
                              const gchar *value)
{
    PurpleAccount *account = purple_connection_get_account (gc);
    GSList *buddies = purple_find_buddies (account, who);
    PurpleBuddy *b;

    while (buddies != NULL)
    {
        b = buddies->data;
        buddies = g_slist_delete_link (buddies, buddies);

        if ((b->alias == NULL && value == NULL) ||
            (b->alias && value && !strcmp (b->alias, value)))
        {
            continue;
        }

        purple_blist_alias_buddy (b, value);
    }
}

void
purple_buddy_set_nickname (PurpleConnection *gc,
                           const gchar *who,
                           const gchar *value)
{
    PurpleAccount *account = purple_connection_get_account (gc);
    GSList *buddies = purple_find_buddies (account, who);
    PurpleBuddy *b;

    while (buddies != NULL)
    {
        b = buddies->data;
        buddies = g_slist_delete_link (buddies, buddies);

        if ((b->server_alias == NULL && value == NULL) ||
            (b->server_alias && value && !strcmp (b->server_alias, value)))
        {
            continue;
        }

        purple_blist_server_alias_buddy (b, value);
    }
}
