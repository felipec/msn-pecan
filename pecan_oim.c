#include "pecan_oim_private.h"
#include "io/pecan_ssl_conn.h"

PecanOimSession *
pecan_oim_session_new (MsnSession *session)
{
    PecanOimSession *oim_session;

    oim_session = g_new0 (PecanOimSession, 1);
    oim_session->session = session;
    oim_session->request_queue = g_queue_new ();

    return oim_session;
}

void
pecan_oim_session_free (PecanOimSession *oim_session)
{
    if (!oim_session)
        return;

    g_queue_free (oim_session->request_queue);
    g_free (oim_session);
}
