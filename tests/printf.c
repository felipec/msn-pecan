#include <glib.h>
#include "pecan_printf.h"

void
pecan_printf (const gchar *expect,
              const gchar *format,
              ...)
{
    gchar *buffer;
    va_list args;

    va_start (args, format);
    buffer = pecan_strdup_vprintf (format, args);
    va_end (args);

    g_printf ("[%s] %s\n", buffer, (strcmp (expect, buffer) == 0) ? "OK" : "fail" );

    g_free (buffer);
}

int
main (int argc,
      char *argv[])
{
    g_type_init ();

    pecan_printf ("hello world!", "hello world!");
    pecan_printf ("hello world!", "hello %s!", "world");
    pecan_printf ("3", "%d", 3);
    pecan_printf ("3", "%i", 3);
    pecan_printf ("-3", "%d", -3);
    pecan_printf ("0xd", "%p", 13);
    pecan_printf ("(nil)", "%p", NULL);
    pecan_printf ("3", "%u", 3);
    pecan_printf ("4294967293", "%u", -3);
    pecan_printf ("3", "%lu", 3);
    pecan_printf ("4294967293", "%lu", -3);
    pecan_printf ("a", "%c", 'a');
    pecan_printf ("D", "%X", 13);
    pecan_printf ("   D", "%4X", 13);
    pecan_printf ("000D", "%.4X", 13);
    pecan_printf ("000D", "%04X", 13);

    return 0;
}
