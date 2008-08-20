#include "pecan_oim_private.h"
#include "io/pecan_ssl_conn.h"

typedef struct OimRequest OimRequest;

struct OimRequest
{
    gchar *passport;
    gchar *message_id;
};

static inline OimRequest *
oim_request_new (const gchar *passport,
                 const gchar *message_id)
{
    OimRequest *oim_request;

    oim_request = g_new0 (OimRequest, 1);
    oim_request->passport = g_strdup (passport);
    oim_request->message_id = g_strdup (message_id);

    return oim_request;
}

static inline void
oim_request_free (OimRequest *oim_request)
{
    g_free (oim_request->passport);
    g_free (oim_request->message_id);
    g_free (oim_request);
}

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

    {
        OimRequest *oim_request;
        while ((oim_request = g_queue_pop_tail (oim_session->request_queue)))
        {
            oim_request_free (oim_request);
        }
    }
    g_queue_free (oim_session->request_queue);

    g_free (oim_session);
}

void
pecan_oim_session_request (PecanOimSession *oim_session,
                           const gchar *passport,
                           const gchar *message_id)
{
    g_queue_push_tail (oim_session->request_queue,
                       oim_request_new (passport, message_id));
}
