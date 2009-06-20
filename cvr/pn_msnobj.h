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

typedef struct PnMsnObj PnMsnObj;

#include "io/pn_buffer.h"

typedef enum
{
    PN_MSNOBJ_UNKNOWN, /**< Unknown object */
    PN_MSNOBJ_RESERVED1, /**< Reserved */
    PN_MSNOBJ_EMOTICON, /**< Custom Emoticon */
    PN_MSNOBJ_USERTILE, /**< UserTile (buddy icon) */
    PN_MSNOBJ_RESERVED2, /**< Reserved */
    PN_MSNOBJ_BACKGROUND, /**< Background */
} PnMsnObjType;

/**
 * Creates a PnMsnObj structure.
 *
 * @return A new PnMsnObj structure.
 */
PnMsnObj *pn_msnobj_new(void);

/**
 * Creates a PnMsnObj structure from a string.
 *
 * @param str The string.
 *
 * @return The new PnMsnObj structure.
 */
PnMsnObj *pn_msnobj_new_from_string(const gchar *str);

/**
 * Creates a PnMsnObj structure from a stored image
 *
 * @param image The image associated to object
 * @param location The object location as stored in PnMsnObj
 * @param creator The creator of the object
 * @param type The type of the object
 *
 * @return A new PnMsnObj structure
 */
PnMsnObj *pn_msnobj_new_from_image(PnBuffer *image,
                                   const char *location,
                                   const char *creator,
                                   PnMsnObjType type);

/**
 * Frees an PnMsnObj structure.
 *
 * @param obj The object structure.
 */
void pn_msnobj_free(PnMsnObj *obj);

/**
 * Outputs a string representation of an PnMsnObj.
 *
 * @param obj The object.
 *
 * @return The string representation. This must be freed.
 */
gchar *pn_msnobj_to_string(const PnMsnObj *obj);

/**
 * Returns a PnMsnObj's creator value.
 *
 * @param obj The object.
 *
 * @return The creator value.
 */
const gchar *pn_msnobj_get_creator(const PnMsnObj *obj);

/**
 * Returns a PnMsnObj's type.
 *
 * @param obj The object.
 *
 * @return The object type.
 */
PnMsnObjType pn_msnobj_get_type(const PnMsnObj *obj);

/**
 * Returns a PnMsnObj's location value.
 *
 * @param obj The object.
 *
 * @return The location value.
 */
const gchar *pn_msnobj_get_location(const PnMsnObj *obj);

/**
 * Returns a PnMsnObj's SHA1C value if it exists, otherwise SHA1D.
 *
 * @param obj The object.
 *
 * @return The SHA1C value.
 */
const gchar *pn_msnobj_get_sha1(const PnMsnObj *obj);

/**
 * Associates an image with an PnMsnObj.
 *
 * @param obj The object.
 * @param buffer The image to associate.
 */
void pn_msnobj_set_image(PnMsnObj *obj, PnBuffer *buffer);

/**
 * Returns the image associated with the PnMsnObj.
 *
 * @param obj The object.
 *
 * @return The associated image.
 */
PnBuffer *pn_msnobj_get_image(const PnMsnObj *obj);

#endif /* PN_MSNOBJ_H */
