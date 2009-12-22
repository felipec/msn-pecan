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

#ifndef PN_UTIL_H
#define PN_UTIL_H

#include <glib.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

gchar *remove_plus_tags_from_str (const gchar *str);

gchar *pn_friendly_name_encode (const gchar *value);

gchar *pn_url_decode (const gchar *url);

/**
 * Parses the MSN message formatting into a format compatible with Purple.
 *
 * @param mime     The mime header with the formatting.
 * @param pre_ret  The returned prefix string.
 * @param post_ret The returned postfix string.
 *
 * @return The new message.
 */
void msn_parse_format(const char *mime, char **pre_ret, char **post_ret);

/**
 * Parses the Purple message formatting (html) into the MSN format.
 *
 * @param html			The html message to format.
 * @param attributes	The returned attributes string.
 * @param message		The returned message string.
 *
 * @return The new message.
 */
void msn_import_html(const char *html, char **attributes, char **message);

void
pn_handle_challenge (const gchar *input,
                     const gchar *product_id,
                     const gchar *product_key,
                     gchar *output);

void msn_parse_socket(const char *str, char **ret_host, int *ret_port);
gchar *pn_normalize (const gchar *str);

gpointer g_hash_table_peek_first (GHashTable *hash_table);
gboolean g_ascii_strcase_equal (gconstpointer v1, gconstpointer v2);
guint g_ascii_strcase_hash (gconstpointer v);

gchar *pn_get_xml_field (const gchar *tag, const gchar *start, const gchar *end);
char *pn_html_unescape(const char *str);

char *pn_rand_guid(void);
time_t pn_parse_date(const char *str);

#endif /* PN_UTIL_H */
