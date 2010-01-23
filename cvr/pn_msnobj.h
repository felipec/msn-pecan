/**
 * Copyright (C) 2008-2009 Felipe Contreras.
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

#ifndef PN_MSNOBJ_H
#define PN_MSNOBJ_H

#include <glib.h>

struct pn_buffer;

enum {
    PN_MSNOBJ_UNKNOWN, /**< Unknown object */
    PN_MSNOBJ_RESERVED1, /**< Reserved */
    PN_MSNOBJ_EMOTICON, /**< Custom Emoticon */
    PN_MSNOBJ_USERTILE, /**< UserTile (buddy icon) */
    PN_MSNOBJ_RESERVED2, /**< Reserved */
    PN_MSNOBJ_BACKGROUND, /**< Background */
};

/**
 * Creates a msnobj structure.
 *
 * @return A new msnobj structure.
 */
struct pn_msnobj *pn_msnobj_new(void);

/**
 * Creates a msnobj structure from a string.
 *
 * @param str The string.
 *
 * @return The new msnobj structure.
 */
struct pn_msnobj *pn_msnobj_new_from_string(const gchar *str);

/**
 * Creates a msnobj structure from a stored image
 *
 * @param image The image associated to object
 * @param location The object location as stored in msnobj
 * @param creator The creator of the object
 * @param type The type of the object
 *
 * @return A new msnobj structure
 */
struct pn_msnobj *pn_msnobj_new_from_image(struct pn_buffer *image,
                                           const char *location,
                                           const char *creator,
                                           int type);

/**
 * Frees an msnobj structure.
 *
 * @param obj The object structure.
 */
void pn_msnobj_free(struct pn_msnobj *obj);

/**
 * Outputs a string representation of an msnobj.
 *
 * @param obj The object.
 *
 * @return The string representation. This must be freed.
 */
gchar *pn_msnobj_to_string(const struct pn_msnobj *obj);

/**
 * Returns a msnobj's type.
 *
 * @param obj The object.
 *
 * @return The object type.
 */
int pn_msnobj_get_type(const struct pn_msnobj *obj);

/**
 * Returns a msnobj's location value.
 *
 * @param obj The object.
 *
 * @return The location value.
 */
const gchar *pn_msnobj_get_location(const struct pn_msnobj *obj);

/**
 * Returns a msnobj's SHA1C value if it exists, otherwise SHA1D.
 *
 * @param obj The object.
 *
 * @return The SHA1C value.
 */
const gchar *pn_msnobj_get_sha1(const struct pn_msnobj *obj);

gboolean pn_msnobj_equal(const struct pn_msnobj *a,
                         const struct pn_msnobj *b);

/**
 * Associates an image with an msnobj.
 *
 * @param obj The object.
 * @param buffer The image to associate.
 */
void pn_msnobj_set_image(struct pn_msnobj *obj, struct pn_buffer *buffer);

/**
 * Returns the image associated with the msnobj.
 *
 * @param obj The object.
 *
 * @return The associated image.
 */
struct pn_buffer *pn_msnobj_get_image(const struct pn_msnobj *obj);

#endif /* PN_MSNOBJ_H */
