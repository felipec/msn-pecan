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

#include <glib.h>

#include "page.h"
#include "session.h"
#include "pn_global.h"
#include "pn_util.h"
#include "pn_log.h"
#include "pn_locale.h"
#include "pn_status.h"
#include "pn_buffer.h"

#include "switchboard.h"
#include "notification.h"
#include "sync.h"

#include "session_private.h"

#include "cmd/msg.h"

#include "ab/pn_contact_priv.h"

#include <string.h> /* For strcmp, strstr, strlen */

#if defined(PECAN_CVR)
#include "cvr/pn_peer_link.h"
#include "libpurple/xfer.h"
#endif /* defined(PECAN_CVR) */

/* libpurple stuff. */
#include <debug.h>
#include <privacy.h>
#include <request.h>
#include <accountopt.h>
#include <pluginpref.h>
#include <cmds.h>
#include <version.h>
#include <core.h>
#include <prpl.h>
#include <util.h>
#include <prefs.h>

#if defined(PECAN_CVR)
#if PURPLE_VERSION_CHECK(2,5,0)
#include <smiley.h>
#endif /* PURPLE_VERSION_CHECK(2,5,0) */
#endif /* defined(PECAN_CVR) */

#ifndef ADIUM
#define PLUGIN_ID "prpl-msn-pecan"
#else
#define PLUGIN_ID "prpl-msn_pecan"
#endif

#ifndef STATIC_PECAN
#define PURPLE_MODULE_EXPORT G_MODULE_EXPORT
#define PURPLE_MODULE_NAME(module, x) x
#else
#define PURPLE_MODULE_EXPORT
#define PURPLE_MODULE_NAME(module, x) module ## _ ## x
#endif

typedef struct
{
    PurpleConnection *gc;
    const char *passport;

} MsnMobileData;

#if PURPLE_VERSION_CHECK(2,5,0)
typedef struct
{
    char *smile;
    PurpleSmiley *ps;
    struct pn_msnobj *obj;
} MsnEmoticon;
#endif /* PURPLE_VERSION_CHECK(2,5,0) */

#if !PURPLE_VERSION_CHECK(2,7,0)
void PURPLE_MODULE_NAME(msn_pecan, set_alias) (PurpleConnection *gc,
                                               const gchar *value);
#endif

static void msn_set_prp(PurpleConnection *gc, const char *type, const char *entry);

static gboolean
contact_is_account_quick (MsnSession *session,
                          const gchar *passport)
{
    gchar *normalized_passport;

    normalized_passport = pn_normalize (passport);

    if (strcmp (msn_session_get_username (session), normalized_passport) == 0)
    {
        g_free (normalized_passport);
        return TRUE;
    }

    g_free (normalized_passport);
    return FALSE;
}

/** @todo remove this crap */
static const gchar *
normalize (const PurpleAccount *account,
           const gchar *str)
{
    static gchar buf[0x800];
    gchar *tmp;
    tmp = pn_normalize (str);
    strncpy (buf, tmp, sizeof (buf));
    g_free (tmp);
    return buf;
}

static gboolean
msn_send_attention(PurpleConnection *gc, const char *username, guint type)
{
    MsnMessage *msg;
    MsnSession *session;
    MsnSwitchBoard *swboard;

    msg = msn_message_new_nudge();
    session = gc->proto_data;
    swboard = msn_session_get_swboard(session, username);

    if (swboard == NULL)
        return FALSE;

    msn_switchboard_send_msg(swboard, msg, TRUE);
    msn_message_unref(msg);

    return TRUE;
}

static GList *
msn_attention_types(PurpleAccount *account)
{
    PurpleAttentionType *attn;
    static GList *list = NULL;

    if (!list) {
        attn = g_new0(PurpleAttentionType, 1);
        attn->name = _("Nudge");
        attn->incoming_description = _("%s has nudged you!");
        attn->outgoing_description = _("Nudging %s...");
        list = g_list_append(list, attn);
    }

    return list;
}


static PurpleCmdRet
msn_cmd_nudge(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
    PurpleAccount *account = purple_conversation_get_account(conv);
    PurpleConnection *gc = purple_account_get_connection(account);
    const gchar *username;

    username = purple_conversation_get_name(conv);

    serv_send_attention(gc, username, 0);

    return PURPLE_CMD_RET_OK;
}

static void
set_friendly_name (PurpleConnection *gc,
                   const gchar *entry)
{
    /*
     * The server doesn't seem to store the friendly name anymore, so let's do
     * that ourselves.
     */
    purple_account_set_string (gc->account, "friendly_name", entry);

    msn_session_set_public_alias (gc->proto_data, entry);
}

#if PURPLE_VERSION_CHECK(2,7,0)
static void
set_alias(PurpleConnection *pc, const char *alias,
          PurpleSetPublicAliasSuccessCallback success_cb,
          PurpleSetPublicAliasFailureCallback failure_cb)
{
    PurpleAccount *account;
    account = purple_connection_get_account(pc);
    set_friendly_name(pc, alias);
    success_cb(account, alias);
}
#else
PURPLE_MODULE_EXPORT void
PURPLE_MODULE_NAME(msn_pecan, set_alias) (PurpleConnection *gc,
                                          const gchar *value)
{
    set_friendly_name (gc, value);
}
#endif

/* TODO do we really need to check for the entry to be empty? */
static void
msn_set_prp(PurpleConnection *gc, const char *type, const char *entry)
{
    if (entry && *entry == '\0')
	entry = NULL;

    msn_session_set_prp (gc->proto_data, type, entry);
}

#ifndef PECAN_USE_PSM
static void
msn_set_personal_message_cb (PurpleConnection *gc, const gchar *entry)
{
    MsnSession *session;

    session = gc->proto_data;
    purple_account_set_string(session->user_data, "personal_message", entry);

    pn_update_personal_message (session);
}
#endif /* PECAN_USE_PSM */

static void
msn_set_home_phone_cb(PurpleConnection *gc, const char *entry)
{
    msn_set_prp(gc, "PHH", entry);
}

static void
msn_set_work_phone_cb(PurpleConnection *gc, const char *entry)
{
    msn_set_prp(gc, "PHW", entry);
}

static void
msn_set_mobile_phone_cb(PurpleConnection *gc, const char *entry)
{
    msn_set_prp(gc, "PHM", entry);
}

static void
enable_msn_pages_cb(PurpleConnection *gc)
{
    msn_set_prp(gc, "MOB", "Y");
}

static void
disable_msn_pages_cb(PurpleConnection *gc)
{
    msn_set_prp(gc, "MOB", "N");
}

static void
send_to_mobile(PurpleConnection *gc, const char *who, const char *entry)
{
    MsnTransaction *trans;
    MsnSession *session;
    MsnCmdProc *cmdproc;
    MsnPage *page;
    char *payload;
    size_t payload_len;

    session = gc->proto_data;
    cmdproc = session->notification->cmdproc;

    page = msn_page_new();
    msn_page_set_body(page, entry);

    payload = msn_page_gen_payload(page, &payload_len);

    trans = msn_transaction_new(cmdproc, "PGD", "%s 1 %d", who, payload_len);

    msn_transaction_set_payload(trans, payload, payload_len);

    msn_page_destroy(page);

    msn_cmdproc_send_trans(cmdproc, trans);
}

static void
send_to_mobile_cb(MsnMobileData *data, const char *entry)
{
    send_to_mobile(data->gc, data->passport, entry);
    g_free(data);
}

static void
close_mobile_page_cb(MsnMobileData *data, const char *entry)
{
    g_free(data);
}

/* -- */

static void
msn_show_set_friendly_name(PurplePluginAction *action)
{
    PurpleConnection *gc;

    gc = (PurpleConnection *) action->context;

    purple_request_input(gc, NULL, _("Set your friendly name."),
                         _("This is the name that other MSN buddies will "
                           "see you as."),
                         purple_connection_get_display_name(gc), FALSE, FALSE, NULL,
                         _("OK"), G_CALLBACK(set_friendly_name),
                         _("Cancel"), NULL,
                         purple_connection_get_account(gc), NULL, NULL,
                         gc);
}

#ifndef PECAN_USE_PSM
static void
msn_show_set_personal_message (PurplePluginAction *action)
{
    PurpleConnection *gc;
    MsnSession *session;

    gc = (PurpleConnection *) action->context;
    session = gc->proto_data;

    purple_request_input(gc, NULL, _("Set your personal message."),
                         _("This is the message that other MSN buddies will "
                           "see under your name."),
                         purple_account_get_string (session->user_data, "personal_message", ""),
                         FALSE, FALSE, NULL,
                         _("OK"), G_CALLBACK(msn_set_personal_message_cb),
                         _("Cancel"), NULL,
                         purple_connection_get_account(gc), NULL, NULL,
                         gc);
}
#endif /* PECAN_USE_PSM */

static void
msn_show_set_home_phone(PurplePluginAction *action)
{
    PurpleConnection *gc;
    MsnSession *session;

    gc = (PurpleConnection *) action->context;
    session = gc->proto_data;

    purple_request_input(gc, NULL, _("Set your home phone number."), NULL,
                         pn_contact_get_home_phone(msn_session_get_contact (session)), FALSE, FALSE, NULL,
                         _("OK"), G_CALLBACK(msn_set_home_phone_cb),
                         _("Cancel"), NULL,
                         purple_connection_get_account(gc), NULL, NULL,
                         gc);
}

static void
msn_show_set_work_phone(PurplePluginAction *action)
{
    PurpleConnection *gc;
    MsnSession *session;

    gc = (PurpleConnection *) action->context;
    session = gc->proto_data;

    purple_request_input(gc, NULL, _("Set your work phone number."), NULL,
                         pn_contact_get_work_phone(msn_session_get_contact (session)), FALSE, FALSE, NULL,
                         _("OK"), G_CALLBACK(msn_set_work_phone_cb),
                         _("Cancel"), NULL,
                         purple_connection_get_account(gc), NULL, NULL,
                         gc);
}

static void
msn_show_set_mobile_phone(PurplePluginAction *action)
{
    PurpleConnection *gc;
    MsnSession *session;

    gc = (PurpleConnection *) action->context;
    session = gc->proto_data;

    purple_request_input(gc, NULL, _("Set your mobile phone number."), NULL,
                         pn_contact_get_mobile_phone(msn_session_get_contact (session)), FALSE, FALSE, NULL,
                         _("OK"), G_CALLBACK(msn_set_mobile_phone_cb),
                         _("Cancel"), NULL,
                         purple_connection_get_account(gc), NULL, NULL,
                         gc);
}

static void
msn_show_set_mobile_pages(PurplePluginAction *action)
{
    PurpleConnection *gc;

    gc = (PurpleConnection *) action->context;

    purple_request_action(gc, NULL, _("Allow MSN Mobile pages?"),
                          _("Do you want to allow or disallow people on "
                            "your buddy list to send you MSN Mobile pages "
                            "to your cell phone or other mobile device?"),
                          -1,
                          purple_connection_get_account(gc), NULL, NULL,
                          gc, 3,
                          _("Allow"), G_CALLBACK(enable_msn_pages_cb),
                          _("Disallow"), G_CALLBACK(disable_msn_pages_cb),
                          _("Cancel"), NULL);
}

static void
show_hotmail_inbox (PurplePluginAction *action)
{
    PurpleConnection *gc;
    MsnSession *session;

    gc = (PurpleConnection *) action->context;
    session = gc->proto_data;

    if (session->passport_info.email_enabled != 1)
    {
        purple_notify_error (gc, NULL,  _("This account's email is not enabled."), NULL);
        return;
    }

    /** apparently the correct value is 777 */
    if (time (NULL) - session->passport_info.mail_url_timestamp >= 750)
    {
        MsnTransaction *trans;
        MsnCmdProc *cmdproc;

        cmdproc = session->notification->cmdproc;

        trans = msn_transaction_new (cmdproc, "URL", "%s", "INBOX");
        msn_transaction_set_data (trans, GUINT_TO_POINTER (TRUE));

        msn_cmdproc_send_trans (cmdproc, trans);

        pn_debug ("mail_url update");

        return;
    }

    purple_notify_uri (gc, session->passport_info.mail_url);
}

static void
show_send_to_mobile_cb(PurpleBlistNode *node, gpointer ignored)
{
    PurpleBuddy *buddy;
    PurpleConnection *gc;
    MsnMobileData *data;

    g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

    buddy = (PurpleBuddy *) node;
    gc = purple_account_get_connection(buddy->account);

    data = g_new0(MsnMobileData, 1);
    data->gc = gc;
    data->passport = buddy->name;

    purple_request_input(gc, NULL, _("Send a mobile message."), NULL,
                         NULL, TRUE, FALSE, NULL,
                         _("Page"), G_CALLBACK(send_to_mobile_cb),
                         _("Close"), G_CALLBACK(close_mobile_page_cb),
                         purple_connection_get_account(gc), purple_buddy_get_name(buddy), NULL,
                         data);
}

static gboolean
msn_offline_message(const PurpleBuddy *buddy) {
    return TRUE;
}

static inline MsnSwitchBoard *
new_chat (MsnSession *session,
          gint id)
{
    MsnSwitchBoard *swboard;
    swboard = msn_switchboard_new (session);
    swboard->chat_id = id;

    /* we should not leave chats on timeouts */
    pn_timer_free(swboard->timer);
    swboard->timer = NULL;

    g_hash_table_insert (session->chats, GINT_TO_POINTER (id), swboard);
    msn_switchboard_request (swboard);

    return swboard;
}

static const char *get_my_alias(MsnSession *session)
{
    const char *alias;
    PurpleAccount *account = msn_session_get_user_data(session);
    alias = purple_account_get_alias(account);
    if (!alias)
        alias = purple_connection_get_display_name(account->gc);
    if (!alias)
        alias = msn_session_get_username(session);
    return alias;
}

static void
initiate_chat_cb(PurpleBlistNode *node, gpointer data)
{
    PurpleBuddy *buddy;
    PurpleConnection *gc;

    MsnSession *session;
    MsnSwitchBoard *swboard;

    g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

    buddy = (PurpleBuddy *) node;
    gc = purple_account_get_connection(buddy->account);

    session = gc->proto_data;
    swboard = new_chat (session, session->conv_seq++);

    msn_switchboard_request_add_user(swboard, buddy->name);

    /* TODO: This might move somewhere else, after USR might be */
    swboard->conv = serv_got_joined_chat(gc, swboard->chat_id, "MSN Chat");

    purple_conv_chat_add_user(PURPLE_CONV_CHAT(swboard->conv),
                              get_my_alias(session), NULL, PURPLE_CBFLAGS_NONE, TRUE);
}

#if defined(PECAN_CVR)
static PurpleXfer*
msn_new_xfer(PurpleConnection *gc, const char *who)
{
    MsnSession *session;
    PurpleXfer *xfer;

    session = gc->proto_data;

    xfer = purple_xfer_new(gc->account, PURPLE_XFER_SEND, who);
    if (!xfer)
        return NULL;

    xfer->data = msn_session_get_peer_link(session, who); /* temporary */
    purple_xfer_set_init_fnc(xfer, purple_pn_xfer_invite);

    return xfer;
}

static void
msn_send_file(PurpleConnection *gc, const char *who, const char *file)
{
    PurpleXfer *xfer = msn_new_xfer(gc, who);

    if (file)
        purple_xfer_request_accepted(xfer, file);
    else
        purple_xfer_request(xfer);
}

static gboolean
msn_can_receive_file(PurpleConnection *gc, const char *who)
{
    MsnSession *session;
    gchar *normal_who;
    gboolean ret;

    session = gc->proto_data;

    g_return_val_if_fail (session, FALSE);

    normal_who = pn_normalize (who);

    ret = strcmp(normal_who, msn_session_get_username (session));

    g_free (normal_who);

    return ret;
}
#endif /* defined(PECAN_CVR) */

/**************************************************************************
 * Protocol Plugin ops
 **************************************************************************/

static const gchar *
list_icon (PurpleAccount *a,
           PurpleBuddy *b)
{
    return "msn";
}

static const char *
list_emblems (PurpleBuddy *b)
{
    struct pn_contact *contact;

    contact = b->proto_data;

    if (contact && contact->mobile)
        return "mobile";

    return NULL;
}

static gchar *
status_text (PurpleBuddy *buddy)
{
    struct pn_contact *contact;

    contact = buddy->proto_data;

    if (!contact)
       goto fallback;

    if (contact->media.title)
    {
        switch (contact->media.type)
        {
            case CURRENT_MEDIA_MUSIC:
                {
                    const gchar *title, *artist, *album;

                    title = contact->media.title;
                    artist = contact->media.artist;
                    album = contact->media.album;

#ifdef ADIUM
                    return g_strdup_printf ("♫ %s", purple_util_format_song_info (title, artist, album, NULL));
#else
                    return purple_util_format_song_info (title, artist, album, NULL);
#endif /* ADIUM */
                }
            case CURRENT_MEDIA_GAMES:
                return g_strdup_printf (_("Playing %s"), contact->media.title);
            case CURRENT_MEDIA_OFFICE:
                return g_strdup_printf (_("Editing %s"), contact->media.title);
            default:
                break;
        }
    }

    {
        const gchar *personal_message;
        personal_message = pn_contact_get_personal_message (contact);
        if (personal_message)
            return g_strdup (personal_message);
    }

fallback:

#ifndef ADIUM
    {
        PurplePresence *presence;
        presence = purple_buddy_get_presence (buddy);
        if (!purple_presence_is_available (presence) &&
            !purple_presence_is_idle (presence))
        {
            PurpleStatus *status;
            status = purple_presence_get_active_status (presence);
            return g_strdup (purple_status_get_name (status));
        }
    }
#endif /* ADIUM */

    return NULL;
}

static void
tooltip_text (PurpleBuddy *buddy,
              PurpleNotifyUserInfo *user_info,
              gboolean full)
{
    struct pn_contact *user;
    PurplePresence *presence;
    PurpleStatus *status;

    if (!buddy)
        return;

    presence = purple_buddy_get_presence (buddy);
    status = purple_presence_get_active_status (presence);
    user = buddy->proto_data;

    if (purple_presence_is_online (presence))
    {
        purple_notify_user_info_add_pair (user_info, _("Status"),
                                          (purple_presence_is_idle (presence) ? _("Idle") : purple_status_get_name (status)));
    }

    if (!user)
        return;

    if (full)
    {
        if (pn_contact_get_personal_message (user))
        {
            purple_notify_user_info_add_pair (user_info, _("Personal Message"),
                                              pn_contact_get_personal_message (user));
        }

        if (user->media.title)
        {
            if (user->media.type == CURRENT_MEDIA_MUSIC)
            {
#ifndef ADIUM
                const gchar *title, *artist, *album;
                gchar *tmp;

                title = user->media.title;
                artist = user->media.artist;
                album = user->media.album;
                tmp = purple_util_format_song_info (title, artist, album, NULL);

                purple_notify_user_info_add_pair (user_info, _("Now Listening"), tmp);
                g_free(tmp);
#endif /* ADIUM */
            }
            else if (user->media.type == CURRENT_MEDIA_GAMES)
            {
                purple_notify_user_info_add_pair (user_info, _("Playing a game"), user->media.title);
            }
            else if (user->media.type == CURRENT_MEDIA_OFFICE)
            {
                purple_notify_user_info_add_pair (user_info, _("Working"), user->media.title);
            }
        }
    }

    purple_notify_user_info_add_pair (user_info, _("Blocked"),
                                      (pn_contact_is_blocked (user) ? _("Yes") : _("No")));

    if (pn_contact_get_client_name (user))
    {
        purple_notify_user_info_add_pair (user_info, _("Client"),
                                          pn_contact_get_client_name (user));
    }
}

static inline PurpleStatusType *
util_gen_state (PurpleStatusPrimitive primitive,
                const gchar *id,
                const gchar *name)
{
#ifdef PECAN_USE_PSM
    return purple_status_type_new_with_attrs (primitive,
                                              id, name, TRUE, TRUE, FALSE,
                                              "message", _("Message"), purple_value_new (PURPLE_TYPE_STRING),
                                              NULL);
#else
    return purple_status_type_new_full (primitive, id, name, TRUE, TRUE, FALSE);
#endif /* PECAN_USE_PSM */
}

static GList *
status_types (PurpleAccount *account)
{
    GList *types = NULL;

    /* visible states */
    types = g_list_append (types, util_gen_state (PURPLE_STATUS_AVAILABLE, NULL, NULL));
    types = g_list_append (types, util_gen_state (PURPLE_STATUS_AWAY, NULL, NULL));
    types = g_list_append (types, util_gen_state (PURPLE_STATUS_AWAY, "brb", _("Be Right Back")));
    types = g_list_append (types, util_gen_state (PURPLE_STATUS_UNAVAILABLE, "busy", _("Busy")));
    types = g_list_append (types, util_gen_state (PURPLE_STATUS_UNAVAILABLE, "phone", _("On the Phone")));
    types = g_list_append (types, util_gen_state (PURPLE_STATUS_AWAY, "lunch", _("Out to Lunch")));

    {
        PurpleStatusType *status;

        /* non-visible states */

        status = purple_status_type_new_full (PURPLE_STATUS_INVISIBLE, NULL, NULL, TRUE, TRUE, FALSE);
        types = g_list_append (types, status);

        status = purple_status_type_new_full (PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
        types = g_list_append (types, status);

        /** @todo when do we use this? */
        status = purple_status_type_new_full (PURPLE_STATUS_MOBILE, "mobile", NULL, FALSE, FALSE, TRUE);
        types = g_list_append (types, status);

        status = purple_status_type_new_with_attrs(PURPLE_STATUS_TUNE, "tune", NULL, FALSE, TRUE, TRUE,
                                                   PURPLE_TUNE_TITLE, _("Song Title"), purple_value_new (PURPLE_TYPE_STRING),
                                                   PURPLE_TUNE_ARTIST, _("Song Artist"), purple_value_new (PURPLE_TYPE_STRING),
                                                   PURPLE_TUNE_ALBUM, _("Song Album"), purple_value_new (PURPLE_TYPE_STRING),
                                                   "game", _("Game Name"), purple_value_new (PURPLE_TYPE_STRING),
                                                   "office", _("Office App Name"), purple_value_new (PURPLE_TYPE_STRING),
                                                   NULL);
        types = g_list_append(types, status);
    }

    return types;
}

static GList *
msn_actions(PurplePlugin *plugin, gpointer context)
{
    PurpleConnection *gc = (PurpleConnection *)context;
    MsnSession *session;
    const char *user;

    GList *m = NULL;
    PurplePluginAction *act;

    session = gc->proto_data;

    act = purple_plugin_action_new(_("Set Friendly Name..."),
                                   msn_show_set_friendly_name);
    m = g_list_append(m, act);

#ifndef PECAN_USE_PSM
    act = purple_plugin_action_new(_("Set Personal Message..."),
                                   msn_show_set_personal_message);
    m = g_list_append(m, act);
#endif /* PECAN_USE_PSM */

    m = g_list_append(m, NULL);

    act = purple_plugin_action_new(_("Set Home Phone Number..."),
                                   msn_show_set_home_phone);
    m = g_list_append(m, act);

    act = purple_plugin_action_new(_("Set Work Phone Number..."),
                                   msn_show_set_work_phone);
    m = g_list_append(m, act);

    act = purple_plugin_action_new(_("Set Mobile Phone Number..."),
                                   msn_show_set_mobile_phone);
    m = g_list_append(m, act);
    m = g_list_append(m, NULL);

#if 0
    act = purple_plugin_action_new(_("Enable/Disable Mobile Devices..."),
                                   msn_show_set_mobile_support);
    m = g_list_append(m, act);
#endif

    act = purple_plugin_action_new(_("Allow/Disallow Mobile Pages..."),
                                   msn_show_set_mobile_pages);
    m = g_list_append(m, act);

    user = msn_session_get_username(session);

    if ((strstr(user, "@hotmail.") != NULL) ||
        (strstr(user, "@msn.com") != NULL))
    {
        m = g_list_append(m, NULL);
        act = purple_plugin_action_new (_("Open Hotmail Inbox"), show_hotmail_inbox);
        m = g_list_append(m, act);
    }

    return m;
}

static GList *
blist_node_menu (PurpleBlistNode *node)
{
    if (!PURPLE_BLIST_NODE_IS_BUDDY (node))
        return NULL;

    {
        PurpleBuddy *buddy;
        GList *m = NULL;
        PurpleMenuAction *act;

        buddy = (PurpleBuddy *) node;

        {
            struct pn_contact *user;

            user = buddy->proto_data;

            if (user)
            {
                if (user->mobile)
                {
                    /** @todo why is there a special way to do this? */
                    act = purple_menu_action_new (_("Send to Mobile"),
                                                  PURPLE_CALLBACK (show_send_to_mobile_cb),
                                                  NULL, NULL);
                    m = g_list_append (m, act);
                }

                if (!pn_contact_is_account (user))
                {
                    act = purple_menu_action_new (_("Initiate _Chat"),
                                                  PURPLE_CALLBACK (initiate_chat_cb),
                                                  NULL, NULL);
                    m = g_list_append(m, act);
                }
            }
        }

        return m;
    }
}

static void
login (PurpleAccount *account)
{
    PurpleConnection *gc;
    MsnSession *session;
    const char *host;
    int port;

    gc = purple_account_get_connection (account);

    if (!purple_ssl_is_supported ())
    {
#if PURPLE_VERSION_CHECK(2,3,0)
        purple_connection_error_reason (gc,
                PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
                _("SSL support is needed for MSN. Please install a supported "
                    "SSL library."));
#else
        purple_connection_error (gc,
                _("SSL support is needed for MSN. Please install a supported "
                    "SSL library."));
#endif
        return;
    }

    host = purple_account_get_string (account, "server", "messenger.hotmail.com");
    port = purple_account_get_int (account, "port", 1863);

    session = msn_session_new (purple_account_get_username (account),
                               purple_account_get_password (account),
                               purple_account_get_bool (account, "http_method", FALSE));

    gc->proto_data = session;
    gc->flags |= PURPLE_CONNECTION_HTML | \
                 PURPLE_CONNECTION_FORMATTING_WBFO | \
                 PURPLE_CONNECTION_NO_BGCOLOR | \
                 PURPLE_CONNECTION_NO_FONTSIZE | \
                 PURPLE_CONNECTION_NO_URLDESC;

#if PURPLE_VERSION_CHECK(2,5,0)
    gc->flags |= PURPLE_CONNECTION_ALLOW_CUSTOM_SMILEY;
#endif /* PURPLE_VERSION_CHECK(2,5,0) */

    session->user_data = account;
    msn_session_set_bool (session, "use_server_alias",
                          purple_account_get_bool (account, "use_server_alias", FALSE));
#ifdef MSN_DIRECTCONN
    msn_session_set_bool (session, "use_direct_conn",
                          purple_account_get_bool (account, "use_direct_conn", FALSE));
#endif
    msn_session_set_bool (session, "use_userdisplay",
                          purple_account_get_bool (account, "use_userdisplay", TRUE));

    session->xfer_invite_cb = purple_pn_xfer_got_invite;

    purple_connection_update_progress (gc, _("Connecting"), 1, 2);

    if (!msn_session_connect (session, host, port))
        purple_connection_error (gc, _("Failed to connect to server."));
}

static void
logout (PurpleConnection *gc)
{
    MsnSession *session;

    session = gc->proto_data;

    g_return_if_fail (session);

    msn_session_destroy (session);

    gc->proto_data = NULL;
}

#if defined(PECAN_CVR)
#if PURPLE_VERSION_CHECK(2,5,0)
static GString*
msn_msg_emoticon_add(GString *current, MsnEmoticon *emoticon)
{
    struct pn_msnobj *obj;
    char *strobj;

    if (emoticon == NULL)
        return current;

    obj = emoticon->obj;

    if (!obj)
        return current;

    strobj = pn_msnobj_to_string(obj);

    if (current)
    {
        g_string_append_printf(current, "\t%s\t%s", emoticon->smile, strobj);
    }
    else
    {
        current = g_string_new("");
        g_string_printf(current,"%s\t%s", emoticon->smile, strobj);
    }

    g_free(strobj);

    return current;
}

static void
msn_send_emoticons(MsnSwitchBoard *swboard, GString *body)
{
    MsnMessage *msg;

    g_return_if_fail(body != NULL);

    msg = msn_message_new(MSN_MSG_SLP);
    msn_message_set_content_type(msg, "text/x-mms-emoticon");
    msn_message_set_flag(msg, 'N');
    msn_message_set_bin_data(msg, body->str, body->len);

    msn_switchboard_send_msg(swboard, msg, TRUE);
    msn_message_unref(msg);
}

static void
msn_emoticon_destroy(MsnEmoticon *emoticon)
{
    if (emoticon->obj)
        pn_msnobj_free(emoticon->obj);
    g_free(emoticon->smile);
    g_free(emoticon);
}

static GSList *
grab_emoticons(MsnSession *session,
               const char *msg)
{
    GSList *list;
    GList *smileys;
    PurpleSmiley *smiley;
    PurpleStoredImage *image;
    char *ptr;
    MsnEmoticon *emoticon;
    int length;
    const char *username;

    list = NULL;
    smileys = purple_smileys_get_all();
    length = strlen(msg);
    username = msn_session_get_username (session);

    for (; smileys; smileys = g_list_delete_link(smileys, smileys))
    {
        struct pn_buffer *buffer;
        smiley = smileys->data;

        ptr = g_strstr_len(msg, length, purple_smiley_get_shortcut(smiley));

        if (!ptr)
            continue;

        image = purple_smiley_get_stored_image(smiley);
        buffer = pn_buffer_new_memdup ((const gpointer) purple_imgstore_get_data (image),
                                       purple_imgstore_get_size (image));

        emoticon = g_new0(MsnEmoticon, 1);
        emoticon->smile = g_strdup(purple_smiley_get_shortcut(smiley));
        emoticon->ps = smiley;
        emoticon->obj = pn_msnobj_new_from_image(buffer,
                                                 purple_imgstore_get_filename(image),
                                                 username, PN_MSNOBJ_EMOTICON);

        purple_imgstore_unref(image);
        list = g_slist_prepend(list, emoticon);
    }

    return list;
}
#endif /* PURPLE_VERSION_CHECK(2,5,0) */
#endif /* defined(PECAN_CVR) */

static gint
send_im (PurpleConnection *gc,
         const gchar *who,
         const gchar *message,
         PurpleMessageFlags flags)
{
    MsnSession *session;
    gchar *msgformat;
    gchar *msgtext;

    session = gc->proto_data;

    /** @todo don't call libpurple functions */
    {
        PurpleBuddy *buddy;
        PurplePresence *presence;

        buddy = purple_find_buddy (gc->account, who);

        if (buddy) {
            presence = purple_buddy_get_presence (buddy);

            if (purple_presence_is_status_primitive_active (presence, PURPLE_STATUS_MOBILE)) {
                gchar *text;
                text = purple_markup_strip_html (message);
                send_to_mobile (gc, who, text);
                g_free (text);
                return 1;
            }
        }
    }

    msn_import_html (message, &msgformat, &msgtext);

    /** @todo don't call strlen all the time */
    if (strlen (msgtext) + strlen (msgformat) + strlen (VERSION) > PN_MAX_MESSAGE_LENGTH)
    {
        g_free (msgformat);
        g_free (msgtext);

        return -7; /* E2BIG */
    }

    {
        struct pn_contact *contact;
        MsnSwitchBoard *swboard;
        gboolean offline = FALSE;
        struct pn_contact *user;

        contact = pn_contactlist_find_contact (session->contactlist, who);
        swboard = msn_session_find_swboard (session, who);
        user = msn_session_get_contact (session);

        if (contact && contact->status == PN_STATUS_OFFLINE && !swboard)
            offline = TRUE;

        if (user->status == PN_STATUS_HIDDEN)
            offline = TRUE;

        if (offline)
        {
            pn_oim_session_request (session->oim_session,
                                    who,
                                    NULL,
                                    msgtext,
                                    PN_SEND_OIM);
            return 1;
        }
    }

    /* a message to ourselves? */
    if (contact_is_account_quick (session, who))
        return -1;

    {
        MsnMessage *msg;
        MsnSwitchBoard *swboard;

        msg = msn_message_new_plain (msgtext);
        msn_message_set_attr (msg, "X-MMS-IM-Format", msgformat);

        g_free (msgformat);
        g_free (msgtext);

        swboard = msn_session_get_swboard (session, who);

#if defined(PECAN_CVR)
#if PURPLE_VERSION_CHECK(2,5,0)
        MsnEmoticon *smile;
        GSList *smileys;
        GString *emoticons = NULL;

        pn_debug ("send via switchboard");
        smileys = grab_emoticons(session, message);

        while (smileys) {
            smile = (MsnEmoticon *) smileys->data;
            emoticons = msn_msg_emoticon_add(emoticons, smile);
            msn_emoticon_destroy(smile);
            smileys = g_slist_delete_link(smileys, smileys);
        }

        if (emoticons) {
            msn_send_emoticons(swboard, emoticons);
            g_string_free(emoticons, TRUE);
        }
#endif /* PURPLE_VERSION_CHECK(2,5,0) */
#endif /* defined(PECAN_CVR) */

        if (flags & PURPLE_MESSAGE_AUTO_RESP)
            msn_message_set_flag (msg, 'U');

        msn_switchboard_send_msg (swboard, msg, TRUE);

        msn_message_unref (msg);
    }

    return 1;
}

static guint
send_typing (PurpleConnection *gc,
             const gchar *who,
             PurpleTypingState state)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;

    session = gc->proto_data;

    if (state != PURPLE_TYPING)
        return 0;

    /* a message to ourselves? */
    if (contact_is_account_quick (session, who))
        goto leave;

    swboard = msn_session_find_swboard (session, who);

    if (!swboard || !msn_switchboard_can_send (swboard))
        return 0;

    {
        MsnMessage *msg;

        msg = msn_message_new (MSN_MSG_TYPING);
        msn_message_set_content_type (msg, "text/x-msmsgscontrol");
        msn_message_set_flag (msg, 'U');
        msn_message_set_attr (msg, "TypingUser", msn_session_get_username (session));
        msn_message_set_bin_data (msg, "\r\n", 2);

        msn_switchboard_send_msg (swboard, msg, FALSE);

        msn_message_unref (msg);
    }

leave:
    /* timeout */
    return 4;
}

static void
set_status (PurpleAccount *account,
            PurpleStatus *status)
{
    PurpleConnection *gc;
    MsnSession *session;

    gc = purple_account_get_connection (account);

    if (gc)
    {
        session = gc->proto_data;
        pn_update_status (session);
#ifdef PECAN_USE_PSM
        pn_update_personal_message (session);
#endif /* PECAN_USE_PSM */
    }
}

static void
set_idle (PurpleConnection *gc,
          gint idle)
{
    MsnSession *session;

    session = gc->proto_data;

    pn_update_status (session);
}

/*
 * Contact list stuff
 */

static void
add_buddy (PurpleConnection *gc,
           PurpleBuddy *buddy,
           PurpleGroup *group)
{
    MsnSession *session;
    struct pn_contact_list *contactlist;

    session = gc->proto_data;
    contactlist = session->contactlist;

    if (!session->logged_in)
    {
        pn_error ("not connected");
        return;
    }

    pn_contactlist_add_buddy_helper (contactlist, buddy, group);
}

static void
rem_buddy (PurpleConnection *gc,
           PurpleBuddy *buddy,
           PurpleGroup *group)
{
    MsnSession *session;
    struct pn_contact_list *contactlist;
    const gchar *group_name;

    session = gc->proto_data;
    contactlist = session->contactlist;
    group_name = group->name;

    if (!session->logged_in)
    {
        pn_error ("not connected");
        return;
    }

    /* Are we going to remove him completely? */
    if (group_name)
    {
        struct pn_contact *user;

        user = pn_contactlist_find_contact (contactlist, buddy->name);

        if (user && pn_contact_get_group_count (user) <= 1)
            group_name = NULL;
    }

    pn_contactlist_rem_buddy (contactlist, buddy->name, MSN_LIST_FL, group_name);
}

static void
alias_buddy (PurpleConnection *gc,
             const gchar *name,
             const gchar *alias)
{
    MsnSession *session;
    MsnCmdProc *cmdproc;
    struct pn_contact *contact;

    session = gc->proto_data;
    cmdproc = session->notification->cmdproc;
    contact = pn_contactlist_find_contact (session->contactlist, name);

    if (!msn_session_get_bool (session, "use_server_alias"))
        return;

    if (alias && strlen (alias))
        alias = purple_url_encode (alias);
    else
        alias = pn_contact_get_passport (contact);

    msn_cmdproc_send (cmdproc, "SBP", "%s %s %s", pn_contact_get_guid (contact), "MFN", alias);
}

static void
group_buddy (PurpleConnection *gc,
             const gchar *who,
             const gchar *old_group_name,
             const gchar *new_group_name)
{
    MsnSession *session;
    struct pn_contact_list *contactlist;

    session = gc->proto_data;
    contactlist = session->contactlist;

    pn_contactlist_move_buddy (contactlist, who, old_group_name, new_group_name);
}

static void
rename_group( PurpleConnection *gc,
              const gchar *old_name,
              PurpleGroup *group,
              GList *moved_buddies)
{
    MsnSession *session;
    MsnCmdProc *cmdproc;
    const gchar *old_group_guid;
    const gchar *enc_new_group_name;

    session = gc->proto_data;
    cmdproc = session->notification->cmdproc;
    enc_new_group_name = purple_url_encode (group->name);

    old_group_guid = pn_contactlist_find_group_id (session->contactlist, old_name);

    g_return_if_fail (old_group_guid);
    msn_cmdproc_send (cmdproc, "REG", "%s %s", old_group_guid, enc_new_group_name);
}

static void
remove_group (PurpleConnection *gc,
              PurpleGroup *group)
{
    MsnSession *session;
    MsnCmdProc *cmdproc;
    const gchar *group_guid;

    session = gc->proto_data;
    cmdproc = session->notification->cmdproc;

    /* The server automatically removes the contacts and sends
     * notifications back. */
    if ((group_guid = pn_contactlist_find_group_id (session->contactlist, group->name)))
    {
        msn_cmdproc_send (cmdproc, "RMG", "%s", group_guid);
    }
}

/*
 * Permission stuff
 */

static void
add_permit (PurpleConnection *gc,
            const gchar *who)
{
    MsnSession *session;
    struct pn_contact_list *contactlist;
    struct pn_contact *user;

    session = gc->proto_data;
    contactlist = session->contactlist;
    user = pn_contactlist_find_contact (contactlist, who);

    if (!session->logged_in)
    {
        pn_error ("not connected");
        g_return_if_reached ();
    }

    if (user && user->list_op & MSN_LIST_BL_OP)
        pn_contactlist_rem_buddy (contactlist, who, MSN_LIST_BL, NULL);

    pn_contactlist_add_buddy (contactlist, who, MSN_LIST_AL, NULL);
}

static void
add_deny (PurpleConnection *gc,
          const gchar *who)
{
    MsnSession *session;
    struct pn_contact_list *contactlist;
    struct pn_contact *user;

    session = gc->proto_data;
    contactlist = session->contactlist;
    user = pn_contactlist_find_contact (contactlist, who);

    if (!session->logged_in)
    {
        pn_error ("not connected");
        g_return_if_reached ();
    }

    if (user && user->list_op & MSN_LIST_AL_OP)
        pn_contactlist_rem_buddy (contactlist, who, MSN_LIST_AL, NULL);

    pn_contactlist_add_buddy (contactlist, who, MSN_LIST_BL, NULL);
}

static void
rem_permit (PurpleConnection *gc,
            const gchar *who)
{
    MsnSession *session;
    struct pn_contact_list *contactlist;

    session = gc->proto_data;
    contactlist = session->contactlist;

    if (!session->logged_in)
    {
        pn_error ("not connected");
        g_return_if_reached ();
    }

    pn_contactlist_rem_buddy (contactlist, who, MSN_LIST_AL, NULL);
    pn_contactlist_add_buddy (contactlist, who, MSN_LIST_BL, NULL);
}

static void
rem_deny (PurpleConnection *gc,
          const gchar *who)
{
    MsnSession *session;
    struct pn_contact_list *contactlist;

    session = gc->proto_data;
    contactlist = session->contactlist;

    if (!session->logged_in)
    {
        pn_error ("not connected");
        g_return_if_reached ();
    }

    pn_contactlist_rem_buddy (contactlist, who, MSN_LIST_BL, NULL);
    pn_contactlist_add_buddy (contactlist, who, MSN_LIST_AL, NULL);
}

static void
set_permit_deny (PurpleConnection *gc)
{
    PurpleAccount *account;
    MsnSession *session;
    MsnCmdProc *cmdproc;

    account = purple_connection_get_account (gc);
    session = gc->proto_data;
    cmdproc = session->notification->cmdproc;

    if (account->perm_deny == PURPLE_PRIVACY_ALLOW_ALL ||
        account->perm_deny == PURPLE_PRIVACY_DENY_USERS)
    {
        msn_cmdproc_send (cmdproc, "BLP", "%s", "AL");
    }
    else
    {
        msn_cmdproc_send (cmdproc, "BLP", "%s", "BL");
    }
}

/*
 * Chat stuff
 */

static void
chat_invite (PurpleConnection *gc,
             gint id,
             const gchar *msg,
             const gchar *who)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;

    session = gc->proto_data;

    swboard = msn_session_find_swboard_with_id (session, id);

    /* if we have no switchboard, everyone else left the chat already */
    if (!swboard)
    {
        swboard = new_chat (session, id);
        swboard->conv = purple_find_chat (gc, id);
    }

    msn_switchboard_request_add_user (swboard, who);
}

static void
chat_leave (PurpleConnection *gc,
            gint id)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;

    session = gc->proto_data;

    swboard = msn_session_find_swboard_with_id (session, id);

    /* if swboard is NULL we were the only person left anyway */
    if (!swboard)
        return;

    swboard->conv = NULL;
}

static gint
chat_send (PurpleConnection *gc,
           gint id,
           const gchar *message,
           PurpleMessageFlags flags)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;
    MsnMessage *msg;
    char *msgformat;
    char *msgtext;

    session = gc->proto_data;
    swboard = msn_session_find_swboard_with_id (session, id);

    if (!swboard)
        return -22; /* EINVAL */

    if (!swboard->ready) {
        pn_error ("not ready?");
        return 0;
    }

    msn_import_html (message, &msgformat, &msgtext);

    /** @todo don't call strlen all the time */
    if (strlen (msgtext) + strlen (msgformat) + strlen (VERSION) > PN_MAX_MESSAGE_LENGTH)
    {
        g_free (msgformat);
        g_free (msgtext);

        return -7; /* E2BIG */
    }

    msg = msn_message_new_plain (msgtext);
    msn_message_set_attr (msg, "X-MMS-IM-Format", msgformat);

#if defined(PECAN_CVR)
#if PURPLE_VERSION_CHECK(2,5,0)
    MsnEmoticon *smile;
    GSList *smileys;
    GString *emoticons = NULL;

    smileys = grab_emoticons (session, message);
    while (smileys)
    {
        smile = (MsnEmoticon *) smileys->data;
        emoticons = msn_msg_emoticon_add (emoticons, smile);
        if (purple_conv_custom_smiley_add (swboard->conv, smile->smile,
                                           "sha1", purple_smiley_get_checksum (smile->ps),
                                           FALSE))
        {
            gconstpointer data;
            size_t len;
            data = purple_smiley_get_data (smile->ps, &len);
            purple_conv_custom_smiley_write (swboard->conv, smile->smile, data, len);
            purple_conv_custom_smiley_close (swboard->conv, smile->smile);
        }
        msn_emoticon_destroy (smile);
        smileys = g_slist_delete_link (smileys, smileys);
    }

    if (emoticons)
    {
        msn_send_emoticons (swboard, emoticons);
        g_string_free (emoticons, TRUE);
    }
#endif /* PURPLE_VERSION_CHECK(2,5,0) */
#endif /* defined(PECAN_CVR) */
    msn_switchboard_send_msg (swboard, msg, FALSE);
    msn_message_unref (msg);

    g_free (msgformat);
    g_free (msgtext);

    serv_got_chat_in (gc, id, msn_session_get_username (session), flags, message, time (NULL));

    return 0;
}

static void
convo_closed (PurpleConnection *gc,
              const gchar *who)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;

    session = gc->proto_data;

    swboard = msn_session_find_swboard (session, who);

    if (!swboard)
        return;

    swboard->conv = NULL;
}

static void
set_buddy_icon (PurpleConnection *gc,
                PurpleStoredImage *img)
{
    MsnSession *session;
    struct pn_contact *user;

    session = gc->proto_data;
    user = msn_session_get_contact (session);

    {
        struct pn_buffer *image;
        if (img)
            image = pn_buffer_new_memdup ((const gpointer) purple_imgstore_get_data (img),
                                          purple_imgstore_get_size (img));
        else
            image = NULL;
        pn_contact_set_buddy_icon (user, image);
    }

    pn_update_status (session);
}

static void
get_info (PurpleConnection *gc,
          const char *name)
{
    PurpleNotifyUserInfo *user_info;
    struct pn_contact *user;
    PurpleBuddy *buddy;

    user_info = purple_notify_user_info_new ();
    purple_notify_user_info_add_pair (user_info, _("Username"), name);

    buddy = purple_find_buddy (purple_connection_get_account (gc), name);
    user = (buddy ? buddy->proto_data : NULL);

    if (user)
    {
        const gchar *friendly_name;
        friendly_name = pn_contact_get_friendly_name (user);
        if (friendly_name && strcmp (friendly_name, name) != 0)
            purple_notify_user_info_add_pair (user_info, _("Friendly Name"), friendly_name);
    }

    tooltip_text (buddy, user_info, /* full? */ TRUE);

    if (user)
    {
        const gchar *home_phone;
        const gchar *mobile_phone;
        const gchar *work_phone;

        home_phone = pn_contact_get_home_phone (user);
        mobile_phone = pn_contact_get_mobile_phone (user);
        work_phone = pn_contact_get_work_phone (user);

        if (home_phone)
            purple_notify_user_info_add_pair (user_info, _("Home Phone"), home_phone);

        if (mobile_phone)
            purple_notify_user_info_add_pair (user_info, _("Mobile Phone"), mobile_phone);

        if (work_phone)
            purple_notify_user_info_add_pair (user_info, _("Work Phone"), work_phone);

        purple_notify_user_info_add_pair (user_info, _("Has Space"),
                                          ((user->client_id & PN_CLIENT_CAP_SPACE) ? _("Yes") : _("No")));
    }

    {
        gchar *tmp;
        static char *profile_url = "http://spaces.live.com/profile.aspx?mem=";
        tmp = g_strdup_printf ("<a href=\"%s%s\">%s%s</a>",
                               profile_url, name, profile_url, name);
        purple_notify_user_info_add_pair (user_info, _("Profile URL"), tmp);
        g_free (tmp);
    }

    purple_notify_userinfo (gc, name, user_info, NULL, NULL);
    purple_notify_user_info_destroy (user_info);
}

static gboolean
load (PurplePlugin *plugin)
{
    msn_notification_init ();
    msn_switchboard_init ();
    msn_sync_init ();

    return TRUE;
}

static gboolean
unload (PurplePlugin *plugin)
{
    msn_notification_end ();
    msn_switchboard_end ();
    msn_sync_end ();

    return TRUE;
}

/*
 * Plugin information
 */

static PurplePluginProtocolInfo prpl_info =
{
    OPT_PROTO_MAIL_CHECK,
    NULL, /* user_splits */
    NULL, /* protocol_options */
    {"png,gif", 0, 0, 96, 96, 0, PURPLE_ICON_SCALE_SEND}, /* icon_spec */
    list_icon, /* list_icon */
    list_emblems, /* list_emblems */
    status_text, /* status_text */
    tooltip_text, /* tooltip_text */
    status_types, /* away_states */
    blist_node_menu, /* blist_node_menu */
    NULL, /* chat_info */
    NULL, /* chat_info_defaults */
    login, /* login */
    logout, /* close */
    send_im, /* send_im */
    NULL, /* set_info */
    send_typing, /* send_typing */
    get_info, /* get_info */
    set_status, /* set_away */
    set_idle, /* set_idle */
    NULL, /* change_passwd */
    add_buddy, /* add_buddy */
    NULL, /* add_buddies */
    rem_buddy, /* remove_buddy */
    NULL, /* remove_buddies */
    add_permit, /* add_permit */
    add_deny, /* add_deny */
    rem_permit, /* rem_permit */
    rem_deny, /* rem_deny */
    set_permit_deny, /* set_permit_deny */
    NULL, /* join_chat */
    NULL, /* reject chat invite */
    NULL, /* get_chat_name */
    chat_invite, /* chat_invite */
    chat_leave, /* chat_leave */
    NULL, /* chat_whisper */
    chat_send, /* chat_send */
    NULL, /* keepalive */
    NULL, /* register_user */
    NULL, /* get_cb_info */
    NULL, /* get_cb_away */
    alias_buddy, /* alias_buddy */
    group_buddy, /* group_buddy */
    rename_group, /* rename_group */
    NULL, /* buddy_free */
    convo_closed, /* convo_closed */
    normalize, /* normalize */
    set_buddy_icon, /* set_buddy_icon */
    remove_group, /* remove_group */
    NULL, /* get_cb_real_name */
    NULL, /* set_chat_topic */
    NULL, /* find_blist_chat */
    NULL, /* roomlist_get_list */
    NULL, /* roomlist_cancel */
    NULL, /* roomlist_expand_category */
#if defined(PECAN_CVR)
    msn_can_receive_file, /* can_receive_file */
    msn_send_file, /* send_file */
    msn_new_xfer, /* new_xfer */
#else
    NULL, /* can_receive_file */
    NULL, /* send_file */
    NULL, /* new_xfer */
#endif /* defined(PECAN_CVR) */
    msn_offline_message, /* offline_message */
    NULL, /* whiteboard_prpl_ops */
    NULL, /* send_raw */
    NULL, /* roomlist_room_serialize */
    NULL, /* unregister_user */
    msn_send_attention, /* send_attention */
    msn_attention_types, /* attention_types */
#if PURPLE_VERSION_CHECK(2,5,0)
    sizeof (PurplePluginProtocolInfo), /* struct_size */
    NULL, /* get_account_text_table */
    NULL, /* initiate_media */
    NULL, /* get_media_caps */
#if PURPLE_VERSION_CHECK(2,7,0)
    NULL, /* get_moods */
    set_alias, /* set_public_alias */
    NULL, /* get_public_alias */
#endif
#endif /* PURPLE_VERSION_CHECK(2,5,0) */
};

static PurplePluginInfo info =
{
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_PROTOCOL, /**< type */
    NULL, /**< ui_requirement */
    0, /**< flags */
    NULL, /**< dependencies */
    PURPLE_PRIORITY_DEFAULT, /**< priority */

    PLUGIN_ID, /**< id */
    "WLM", /**< name */
    VERSION, /**< version */
    N_("WLM Protocol Plugin"), /**< summary */
    N_("WLM Protocol Plugin"), /**< description */
    "Felipe Contreras <felipe.contreras@gmail.com>", /**< author */
    "http://code.google.com/p/msn-pecan/", /**< homepage */

    load, /**< load */
    unload, /**< unload */
    NULL, /**< destroy */

    NULL, /**< ui_info */
    &prpl_info, /**< extra_info */
    NULL, /**< prefs_info */
    msn_actions,

    /* padding */
    NULL,
    NULL,
    NULL,
    NULL
};

#if defined(G_OS_WIN32) && defined(ENABLE_NLS)
const char *wpurple_locale_dir(void);
#endif

static void
init_plugin (PurplePlugin *plugin)
{
#if defined(G_OS_WIN32) && defined(ENABLE_NLS)
    bindtextdomain("libmsn-pecan", wpurple_locale_dir());
    bind_textdomain_codeset("libmsn-pecan", "UTF-8");
#endif

    {
        PurpleAccountOption *option;

        option = purple_account_option_string_new (_("Server"), "server", "messenger.hotmail.com");
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);

        option = purple_account_option_int_new (_("Port"), "port", 1863);
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);

        option = purple_account_option_bool_new (_("Use HTTP Method"), "http_method", FALSE);
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);

        option = purple_account_option_bool_new (_("Show custom smileys"), "custom_smileys", TRUE);
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);

        option = purple_account_option_bool_new (_("Use server-side alias"), "use_server_alias", FALSE);
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);

#ifdef MSN_DIRECTCONN
        option = purple_account_option_bool_new (_("Use direct connections"), "use_direct_conn", FALSE);
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);
#endif

        option = purple_account_option_bool_new (_("Use user displays"), "use_userdisplay", TRUE);
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);

        option = purple_account_option_bool_new (_("Don't show Messenger Plus! tags"), "hide_msgplus_tags", TRUE);
        prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, option);
    }

    purple_cmd_register ("nudge", "", PURPLE_CMD_P_PRPL,
                         PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
                         PLUGIN_ID, msn_cmd_nudge,
                         _("nudge: nudge a user to get their attention"), NULL);

    purple_prefs_remove ("/plugins/prpl/msn");
}

#ifndef STATIC_PECAN
G_MODULE_EXPORT gboolean
purple_init_plugin(PurplePlugin *plugin);
G_MODULE_EXPORT gboolean
purple_init_plugin(PurplePlugin *plugin)
{
    plugin->info = &info;
    init_plugin(plugin);
    return purple_plugin_register(plugin);
}
#else
gboolean
purple_init_msn_pecan_plugin(void);
gboolean
purple_init_msn_pecan_plugin(void)
{
    PurplePlugin *plugin = purple_plugin_new(TRUE, NULL);
    plugin->info = &info;
    init_plugin(plugin);
    purple_plugin_load(plugin);
    return purple_plugin_register(plugin);
}
#endif
