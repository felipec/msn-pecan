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
#include "slpcall.h"
#include "slplink.h"
#include "slpmsg.h"
#include "session.h"

#include "pecan_log.h"

#include <string.h> /* for memcpy, memset */

#include <ft.h>

static void
xfer_init(PurpleXfer *xfer)
{
    MsnSlpCall *slpcall;
    /* MsnSlpLink *slplink; */
    char *content;

    pecan_info("xfer_init");

    slpcall = xfer->data;

    /* Send Ok */
    content = g_strdup_printf("SessionID: %lu\r\n\r\n",
                              slpcall->session_id);

    msn_slp_sip_send_ok(slpcall, slpcall->branch,
                        "application/x-msnmsgr-sessionreqbody",
                        content);

    g_free(content);
    msn_slplink_unleash(slpcall->slplink);
}

static void
xfer_cancel(PurpleXfer *xfer)
{
    MsnSlpCall *slpcall;
    char *content;

    slpcall = xfer->data;

    if (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL) {
        if (slpcall->started)
            msn_slp_call_close(slpcall);
        else {
            content = g_strdup_printf("SessionID: %lu\r\n\r\n",
                                      slpcall->session_id);

            msn_slp_sip_send_decline(slpcall, slpcall->branch,
                                     "application/x-msnmsgr-sessionreqbody",
                                     content);

            g_free(content);
            msn_slplink_unleash(slpcall->slplink);

            msn_slp_call_destroy(slpcall);
        }
    }
}

static void
xfer_progress_cb(MsnSlpCall *slpcall,
                 gsize total_length,
                 gsize len,
                 gsize offset)
{
    PurpleXfer *xfer;

    xfer = slpcall->xfer;

    xfer->bytes_sent = (offset + len);
    xfer->bytes_remaining = total_length - (offset + len);

    purple_xfer_update_progress(xfer);
}

static void
xfer_end_cb(MsnSlpCall *slpcall,
            MsnSession *session)
{
    if ((purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_DONE) &&
        (purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_CANCEL_REMOTE) &&
        (purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_CANCEL_LOCAL))
    {
        purple_xfer_cancel_remote(slpcall->xfer);
    }
}

static void
xfer_completed_cb(MsnSlpCall *slpcall,
                  const guchar *body,
                  gsize size)
{
    PurpleXfer *xfer = slpcall->xfer;
    purple_xfer_set_completed(xfer, TRUE);
    purple_xfer_end(xfer);
}

static void
send_file_cb(MsnSlpCall *slpcall)
{
    MsnSlpMessage *slpmsg;
    struct stat st;
    PurpleXfer *xfer;

    slpmsg = msn_slpmsg_new(slpcall->slplink);
    slpmsg->slpcall = slpcall;
    slpmsg->flags = 0x1000030;
#ifdef PECAN_DEBUG_SLP
    slpmsg->info = "SLP FILE";
#endif
    xfer = (PurpleXfer *)slpcall->xfer;
    purple_xfer_start(slpcall->xfer, 0, NULL, 0);
    slpmsg->fp = xfer->dest_fp;
    if (g_stat(purple_xfer_get_local_filename(xfer), &st) == 0)
        slpmsg->size = st.st_size;
    xfer->dest_fp = NULL; /* Disable double fclose() */

    msn_slplink_send_slpmsg(slpcall->slplink, slpmsg);
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
    MsnSlpCall *slpcall;
    char *context;
    const char *fn;
    const char *fp;

    fn = purple_xfer_get_filename(xfer);
    fp = purple_xfer_get_local_filename(xfer);

    slpcall = msn_slp_call_new(xfer->data);
    msn_slp_call_init(slpcall, MSN_SLPCALL_DC);

    slpcall->init_cb = send_file_cb;
    slpcall->end_cb = xfer_end_cb;
    slpcall->progress_cb = xfer_progress_cb;
    slpcall->cb = xfer_completed_cb;
    slpcall->xfer = xfer;
    purple_xfer_ref(slpcall->xfer);

    slpcall->pending = TRUE;

    purple_xfer_set_cancel_send_fnc(xfer, xfer_cancel);

    xfer->data = slpcall;

    context = gen_context(fn, fp);

    msn_slp_call_invite(slpcall, "5D3E02AB-6190-11D3-BBBB-00C04F795683", 2,
                        context);

    g_free(context);
}

void
msn_xfer_got_invite(MsnSlpCall *slpcall,
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

    account = msn_session_get_user_data (slpcall->slplink->session);

    slpcall->cb = xfer_completed_cb;
    slpcall->end_cb = xfer_end_cb;
    slpcall->progress_cb = xfer_progress_cb;
    slpcall->branch = g_strdup(branch);

    slpcall->pending = TRUE;

    xfer = purple_xfer_new(account, PURPLE_XFER_RECEIVE,
                           slpcall->slplink->remote_user);
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

        slpcall->xfer = xfer;
        purple_xfer_ref(slpcall->xfer);

        xfer->data = slpcall;

        purple_xfer_request(xfer);
    }
}
