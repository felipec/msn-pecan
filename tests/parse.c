#include <glib.h>
#include "io/pecan_cmd_server.h"

#include <string.h>

void
run_simple_test (const gchar *str,
                 gsize buf_size)
{
    PecanCmdServer *cmdserv;
    gchar *buf;

    buf = g_malloc (buf_size);

    if (str)
        strcpy (buf, str);

    cmdserv = pecan_cmd_server_new ("foo", 0);
    pecan_node_parse (PECAN_NODE (cmdserv), buf, buf_size - 1);
    pecan_cmd_server_free (cmdserv);

    g_free (buf);
}

int
main (int argc,
      char *argv[])
{
    g_type_init ();

    run_simple_test (NULL, 0x400);
    run_simple_test ("MSN 1 foo\r\n", 0x400);
    run_simple_test ("do", 0x400);
    run_simple_test ("1a1", 0x400);
    run_simple_test ("averylongword", 0x400);
    run_simple_test ("©€®¥$\0foo", 0x400);
    run_simple_test ("MSN 1 foo\r\nbar\nzoo\rbar\n\r", 0x400);
    run_simple_test ("123", 0x400);
    run_simple_test ("123 1", 0x400);
    run_simple_test ("ego", 0x400);

    return 0;
}
