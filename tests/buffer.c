#include <glib.h>
#include "io/pecan_buffer.h"

#include <string.h>

static void
basic_tests (void)
{
    PecanBuffer *buf;

    buf = pecan_buffer_new ();
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    pecan_buffer_free (buf);

    buf = pecan_buffer_new ();
    pecan_buffer_resize (buf, PECAN_BUF_SIZE);
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    pecan_buffer_resize (buf, 2 * PECAN_BUF_SIZE);
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    pecan_buffer_prepare (buf, 2 * PECAN_BUF_SIZE);
    pecan_buffer_free (buf);
}

static void
prepare_tests (guint times,
               gboolean write)
{
    PecanBuffer *buf;
    guint i;

    buf = pecan_buffer_new ();
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * PECAN_BUF_SIZE);
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);

    buf = pecan_buffer_new ();
    pecan_buffer_resize (buf, PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * PECAN_BUF_SIZE);
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * g_random_double ());
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);

    buf = pecan_buffer_new ();
    pecan_buffer_resize (buf, PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * g_random_double ());
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);
}

int
main (int argc,
      char *argv[])
{
    basic_tests ();
    prepare_tests (0x10, FALSE);
    prepare_tests (0x10, TRUE);

    return 0;
}
