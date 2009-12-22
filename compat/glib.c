#include <glib.h>
#include <string.h>

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
