/*
 * Copyright (C) 2008-2009 Felipe Contreras.
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

#ifndef PN_PARSER_H
#define PN_PARSER_H

typedef struct PnParser PnParser;

#include "io/pn_node.h"

PnParser *pn_parser_new (PnNode *node);
void pn_parser_free (PnParser *parser);
void pn_parser_reset (PnParser *parser);
GIOStatus pn_parser_read_line (PnParser *parser,
                               gchar **str_return,
                               gsize *length,
                               gsize *terminator_pos,
                               GError **error);
GIOStatus pn_parser_read (PnParser *parser,
                          gchar **buf_return,
                          gsize length,
                          GError **error);

#endif /* PN_PARSER_H */
