#ifndef G_LIB_H
#define G_LIB_H

#include_next <glib.h>

#if !GLIB_CHECK_VERSION(2,16,0)
int g_strcmp0 (const char *str1, const char *str2);
#endif /* !GLIB_CHECK_VERSION(2,16,0) */

#if !GLIB_CHECK_VERSION(2,14,0)
#define g_timeout_add_seconds(seconds, callback, user_data) \
    g_timeout_add(seconds * 1000, callback, user_data)
#define g_once_init_enter(value) (G_UNLIKELY (*(value) == 0))
#define g_once_init_leave(value,init_value) (*(value) = init_value)
#endif /* !GLIB_CHECK_VERSION(2,14,0) */

#endif
