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

#include "xfer.h"
#include "slp.h"
#include "pn_peer_call.h"
#include "pn_peer_link.h"
#include "slpmsg.h"
#include "session.h"

#include "pn_log.h"

#include <string.h> /* for memcpy, memset */

#include <ft.h>

static void
xfer_init(PurpleXfer *xfer)
{
    PnPeerCall *call;
    char *content;

    pn_info("xfer_init");

    call = xfer->data;

    /* Send Ok */
    content = g_strdup_printf("SessionID: %lu\r\n\r\n",
                              call->session_id);

    msn_slp_sip_send_ok(call, call->branch,
                        "application/x-msnmsgr-sessionreqbody",
                        content);

    g_free(content);
    pn_peer_link_unleash(call->link);
}

static void
xfer_cancel(PurpleXfer *xfer)
{
    PnPeerCall *call;
    char *content;

    call = xfer->data;

    if (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL) {
        if (call->started)
            pn_peer_call_close(call);
        else {
            content = g_strdup_printf("SessionID: %lu\r\n\r\n",
                                      call->session_id);

            msn_slp_sip_send_decline(call, call->branch,
                                     "application/x-msnmsgr-sessionreqbody",
                                     content);

            g_free(content);
            pn_peer_link_unleash(call->link);

            pn_peer_call_destroy(call);
        }
    }
}

static void
xfer_progress_cb(PnPeerCall *call,
                 gsize total_length,
                 gsize len,
                 gsize offset)
{
    PurpleXfer *xfer;

    xfer = call->xfer;

    xfer->bytes_sent = (offset + len);
    xfer->bytes_remaining = total_length - (offset + len);

    purple_xfer_update_progress(xfer);
}

static void
xfer_end_cb(PnPeerCall *call,
            MsnSession *session)
{
    if ((purple_xfer_get_status(call->xfer) != PURPLE_XFER_STATUS_DONE) &&
        (purple_xfer_get_status(call->xfer) != PURPLE_XFER_STATUS_CANCEL_REMOTE) &&
        (purple_xfer_get_status(call->xfer) != PURPLE_XFER_STATUS_CANCEL_LOCAL))
    {
        purple_xfer_cancel_remote(call->xfer);
    }
}

static void
xfer_completed_cb(PnPeerCall *call,
                  const guchar *body,
                  gsize size)
{
    PurpleXfer *xfer = call->xfer;
    purple_xfer_set_completed(xfer, TRUE);
    purple_xfer_end(xfer);
}

static void
send_file_cb(PnPeerCall *call)
{
    MsnSlpMessage *slpmsg;
    struct stat st;
    PurpleXfer *xfer;

    slpmsg = msn_slpmsg_new(call->link);
    slpmsg->call = call;
    slpmsg->flags = 0x1000030;
#ifdef PECAN_DEBUG_SLP
    slpmsg->info = "SLP FILE";
#endif
    xfer = (PurpleXfer *) call->xfer;
    purple_xfer_start(call->xfer, 0, NULL, 0);
    slpmsg->fp = xfer->dest_fp;
    if (g_stat(purple_xfer_get_local_filename(xfer), &st) == 0)
        slpmsg->size = st.st_size;
    xfer->dest_fp = NULL; /* Disable double fclose() */

    pn_peer_link_send_slpmsg(call->link, slpmsg);
}

typedef struct
{
    guint32 length;
    guint32 unk1;
    guint32 file_size;
    guint32 unk2;
    guint32 unk3;
} MsnContextHeader;

#define MAX_FILE_NAME_LEN 0x226

static gchar *
gen_context(const char *file_name,
            const char *file_path)
{
    struct stat st;
    gsize size = 0;
    MsnContextHeader header;
    gchar *u8 = NULL;
    guchar *base;
    guchar *n;
    gchar *ret;
    gunichar2 *uni = NULL;
    glong currentChar = 0;
    glong uni_len = 0;
    gsize len;

    if (g_stat(file_path, &st) == 0)
        size = st.st_size;

    if(!file_name) {
        u8 = purple_utf8_try_convert(g_basename(file_path));
        file_name = u8;
    }

    uni = g_utf8_to_utf16(file_name, -1, NULL, &uni_len, NULL);

    if(u8) {
        g_free(u8);
        file_name = NULL;
        u8 = NULL;
    }

    len = sizeof(MsnContextHeader) + MAX_FILE_NAME_LEN + 4;

    header.length = GUINT32_TO_LE(len);
    header.unk1 = GUINT32_TO_LE(2);
    header.file_size = GUINT32_TO_LE(size);
    header.unk2 = GUINT32_TO_LE(0);
    header.unk3 = GUINT32_TO_LE(0);

    base = g_malloc(len + 1);
    n = base;

    memcpy(n, &header, sizeof(MsnContextHeader));
    n += sizeof(MsnContextHeader);

    memset(n, 0x00, MAX_FILE_NAME_LEN);
    for(currentChar = 0; currentChar < uni_len; currentChar++) {
        *((gunichar2 *)n + currentChar) = GUINT16_TO_LE(uni[currentChar]);
    }
    n += MAX_FILE_NAME_LEN;

    memset(n, 0xFF, 4);
    n += 4;

    g_free(uni);
    ret = purple_base64_encode(base, len);
    g_free(base);
    return ret;
}

void
msn_xfer_invite(PurpleXfer *xfer)
{
    PnPeerLink *link;
    PnPeerCall *call;
    char *context;
    const char *fn;
    const char *fp;

    fn = purple_xfer_get_filename(xfer);
    fp = purple_xfer_get_local_filename(xfer);

    link = xfer->data;
    call = pn_peer_call_new(link);
    pn_peer_call_init(call, PN_PEER_CALL_DC);

    call->init_cb = send_file_cb;
    call->end_cb = xfer_end_cb;
    call->progress_cb = xfer_progress_cb;
    call->cb = xfer_completed_cb;
    call->xfer = xfer;
    purple_xfer_ref(call->xfer);

    call->pending = TRUE;

    purple_xfer_set_cancel_send_fnc(xfer, xfer_cancel);

    xfer->data = call;

    context = gen_context(fn, fp);

    pn_peer_call_invite(call, "5D3E02AB-6190-11D3-BBBB-00C04F795683", 2,
                        context);

    g_free(context);
}

void
msn_xfer_got_invite(PnPeerCall *call,
                    const char *branch,
                    const char *context)
{
    PurpleAccount *account;
    PurpleXfer *xfer;
    char *bin;
    gsize bin_len;
    guint32 file_size;
    char *file_name;
    gunichar2 *uni_name;

    account = msn_session_get_user_data (call->link->session);

    call->cb = xfer_completed_cb;
    call->end_cb = xfer_end_cb;
    call->progress_cb = xfer_progress_cb;
    call->branch = g_strdup(branch);

    call->pending = TRUE;

    xfer = purple_xfer_new(account, PURPLE_XFER_RECEIVE,
                           call->link->remote_user);
    if (xfer)
    {
        bin = (char *)purple_base64_decode(context, &bin_len);
        file_size = GUINT32_FROM_LE(*(gsize *)(bin + 8));

        uni_name = (gunichar2 *)(bin + 20);
        while(*uni_name != 0 && ((char *)uni_name - (bin + 20)) < MAX_FILE_NAME_LEN) {
            *uni_name = GUINT16_FROM_LE(*uni_name);
            uni_name++;
        }

        file_name = g_utf16_to_utf8((const gunichar2 *)(bin + 20), -1,
                                    NULL, NULL, NULL);

        g_free(bin);

        purple_xfer_set_filename(xfer, file_name);
        purple_xfer_set_size(xfer, file_size);
        purple_xfer_set_init_fnc(xfer, xfer_init);
        purple_xfer_set_request_denied_fnc(xfer, xfer_cancel);
        purple_xfer_set_cancel_recv_fnc(xfer, xfer_cancel);

        call->xfer = xfer;
        purple_xfer_ref(call->xfer);

        xfer->data = call;

        purple_xfer_request(xfer);
    }
}
