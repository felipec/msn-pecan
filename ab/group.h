/**
 * Copyright (C) 2008 Felipe Contreras
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#ifndef MSN_GROUP_H
#define MSN_GROUP_H

typedef struct MsnGroup  MsnGroup;

#include "userlist.h"

MsnGroup *msn_group_new (MsnUserList *userlist, const gchar *guid, const gchar *name);
void msn_group_destroy (MsnGroup *group);
void msn_group_set_id (MsnGroup *group, const gchar *guid);
void msn_group_set_name (MsnGroup *group, const gchar *name);
const gchar *msn_group_get_id (const MsnGroup *group);
const gchar *msn_group_get_name (const MsnGroup *group);

#endif /* MSN_GROUP_H */
