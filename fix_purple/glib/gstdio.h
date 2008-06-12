#ifndef G_STDIO_H
#define G_STDIO_H

#include <stdio.h>
#include <stdarg.h>

#include <sys/stat.h>

G_BEGIN_DECLS

#if defined(G_OS_UNIX) && !defined(G_STDIO_NO_WRAP_ON_UNIX)

#define g_open open
#define g_stat stat
#define g_fopen fopen

#else

int g_open (const gchar *filename,
            int flags,
            int mode);

int g_stat (const gchar *filename,
            struct stat *buf);

FILE *g_fopen (const gchar *filename,
               const gchar *mode);

#endif

G_END_DECLS

#endif /* G_STDIO_H */
