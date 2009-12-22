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

#include "session.h"
#include "sync.h"

#include "pn_log.h"

#include "session_private.h"

#include "cmd/command_private.h"
#include "cmd/cmdproc_private.h"

#include "ab/pn_group.h"
#include "ab/pn_contact_priv.h"

#include <string.h>

#include "pn_util.h"

/* libpurple stuff. */
#include <account.h>
#include <privacy.h>

static MsnTable *cbs_table;

static void
blp_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session;
    PurpleAccount *account;
    const char *list_name;

    list_name = cmd->params[0];
    session = cmdproc->session;
    account = msn_session_get_user_data (session);

    if (g_ascii_strcasecmp (list_name, "AL") == 0)
    {
        /*
         * If the current setting is AL, messages from users who
         * are not in BL will be delivered.
         *
         * In other words, deny some.
         */
        account->perm_deny = PURPLE_PRIVACY_DENY_USERS;

        session->default_permission = PN_PERM_ALLOW;
    }
    else
    {
        /* If the current setting is BL, only messages from people
         * who are in the AL will be delivered.
         *
         * In other words, permit some.
         */
        account->perm_deny = PURPLE_PRIVACY_ALLOW_USERS;

        session->default_permission = PN_PERM_DENY;
    }
}

static void
prp_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session = cmdproc->session;
    const gchar *type, *value;
    struct pn_contact *user;

    type  = cmd->params[0];
    value = cmd->params[1];
    user = msn_session_get_contact (session);

    if (cmd->param_count == 2)
    {
        gchar *tmp;
        tmp = pn_url_decode (value);
        if (strcmp (type, "PHH") == 0)
            pn_contact_set_home_phone (user, tmp);
        else if (strcmp (type, "PHW") == 0)
            pn_contact_set_work_phone (user, tmp);
        else if (strcmp (type, "PHM") == 0)
            pn_contact_set_mobile_phone (user, tmp);
        else if (strcmp (type, "MFN") == 0)
        {
            PurpleAccount *account;
            PurpleConnection *connection;
            const gchar* friendly_name;
            account = msn_session_get_user_data (session);
            connection = purple_account_get_connection (account);

            friendly_name = purple_account_get_string (account, "friendly_name", NULL);

            /*
             * The server doesn't seem to store the friendly name anymore,
             * store it in account opts.
             */
            if (friendly_name)
                msn_session_set_public_alias (session, friendly_name);
            else
                purple_account_set_string (account, "friendly_name", tmp);

            purple_connection_set_display_name (connection, friendly_name);
        }
        g_free (tmp);
    }
    else
    {
        if (strcmp (type, "PHH") == 0)
            pn_contact_set_home_phone (user, NULL);
        else if (strcmp (type, "PHW") == 0)
            pn_contact_set_work_phone (user, NULL);
        else if (strcmp (type, "PHM") == 0)
            pn_contact_set_mobile_phone (user, NULL);
    }
}

static void
lsg_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session = cmdproc->session;
    char *name;
    const gchar *group_guid;

    name = pn_url_decode (cmd->params[0]);
    group_guid = cmd->params[1];

    pn_group_new (session->contactlist, name, group_guid);

    if (!purple_find_group (name))
    {
        PurpleGroup *g = purple_group_new (name);
        purple_blist_add_group (g, NULL);
    }

    g_free (name);

    /* Group of ungroupped buddies */
    if (!group_guid)
    {
        if (session->sync->total_users == 0)
        {
            cmdproc->cbs_table = session->sync->old_cbs_table;

            msn_session_finish_login (session);

            msn_sync_destroy (session->sync);
            session->sync = NULL;
        }
        return;
    }
}

static void
lst_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session = cmdproc->session;
    const gchar *passport = NULL;
    struct pn_contact *user;
    gchar *friendly = NULL;
    const gchar *user_guid = NULL;
    int list_op = -1;
    gint type;
    guint i;

    for (i = 0; i < cmd->param_count; i++)
    {
        const char *chopped_str;

        chopped_str = cmd->params[i] + 2;

        /* Check for Name/email. */
        if (strncmp (cmd->params[i], "N=", 2) == 0)
            passport = chopped_str;
        /* Check for Friendlyname. */
        else if (strncmp (cmd->params[i], "F=", 2) == 0)
            friendly = pn_url_decode (chopped_str);
        /* Check for Contact GUID. */
        else if (strncmp (cmd->params[i], "C=", 2) == 0)
            user_guid = chopped_str;
        else
            break;
    }

    list_op = g_ascii_strtod (cmd->params[i++], NULL);
    type = g_ascii_strtod (cmd->params[i++], NULL);

    user = pn_contact_new (session->contactlist);
    pn_contact_set_passport (user, passport);
    pn_contact_set_guid (user, user_guid);

    session->sync->last_user = user;

    /* TODO: This can be improved */

    if (list_op & MSN_LIST_FL_OP)
    {
        if (cmd->params[i])
        {
            gchar **c;
            gchar **tokens;
            const gchar *group_guids;
            GSList *group_ids;

            group_guids = cmd->params[i];

            group_ids = NULL;

            tokens = g_strsplit (group_guids, ",", -1);

            for (c = tokens; *c; c++)
            {
                group_ids = g_slist_append (group_ids, g_strdup (*c));
            }

            g_strfreev (tokens);

            msn_got_lst_contact (session, user, friendly, list_op, group_ids);

            g_slist_foreach (group_ids, (GFunc) g_free, NULL);
            g_slist_free (group_ids);
        }
        else
        {
            msn_got_lst_contact (session, user, friendly, list_op, NULL);
        }
    }
    else
    {
        msn_got_lst_contact (session, user, friendly, list_op, NULL);
    }

    g_free (friendly);

    session->sync->num_users++;

    if (session->sync->num_users == session->sync->total_users)
    {
        cmdproc->cbs_table = session->sync->old_cbs_table;

        msn_session_finish_login (session);

        msn_sync_destroy (session->sync);
        session->sync = NULL;
    }
}

static void
bpr_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSync *sync = cmdproc->session->sync;
    const char *type, *value;
    struct pn_contact *user;

    user = sync->last_user;

    g_return_if_fail (user);

    type = cmd->params[0];
    value = cmd->params[1];

    if (value)
    {
        if (strcmp(type, "MOB") == 0)
        {
            if (strcmp (value, "Y") == 0)
                user->mobile = TRUE;
        }
        else
        {
            gchar *tmp;
            tmp = pn_url_decode (value);
            if (strcmp(type, "PHH") == 0)
                pn_contact_set_home_phone (user, tmp);
            else if (strcmp(type, "PHW") == 0)
                pn_contact_set_work_phone (user, tmp);
            else if (strcmp (type, "PHM") == 0)
                pn_contact_set_mobile_phone (user, tmp);
            g_free (tmp);
        }
    }
}

static void
not_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
    pn_info ("incoming notification: [%s]", payload);
}

static void
not_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    cmd->payload_len = atoi(cmd->params[0]);
    cmdproc->last_cmd->payload_cb = not_cmd_post;
}

void
msn_sync_init (void)
{
    /* TODO: check prp, blp, bpr */

    cbs_table = msn_table_new ();

    /* Syncing */
    msn_table_add_cmd (cbs_table, NULL, "GTC", NULL);
    msn_table_add_cmd (cbs_table, NULL, "BLP", blp_cmd);
    msn_table_add_cmd (cbs_table, NULL, "PRP", prp_cmd);
    msn_table_add_cmd (cbs_table, NULL, "LSG", lsg_cmd);
    msn_table_add_cmd (cbs_table, NULL, "LST", lst_cmd);
    msn_table_add_cmd (cbs_table, NULL, "BPR", bpr_cmd);
    msn_table_add_cmd (cbs_table, NULL, "NOT", not_cmd);
}

void
msn_sync_end (void)
{
    msn_table_destroy (cbs_table);
}

MsnSync *
msn_sync_new (MsnSession *session)
{
    MsnSync *sync;

    sync = g_new0 (MsnSync, 1);

    sync->session = session;
    sync->cbs_table = cbs_table;

    return sync;
}

void
msn_sync_destroy (MsnSync *sync)
{
    g_free (sync);
}
