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

#ifndef PECAN_SLP_OBJECT_H
#define PECAN_SLP_OBJECT_H

#include <glib.h>

typedef struct MsnObject MsnObject;

#include "io/pecan_buffer.h"

typedef enum
{
    MSN_OBJECT_UNKNOWN, /**< Unknown object */
    MSN_OBJECT_RESERVED1, /**< Reserved */
    MSN_OBJECT_EMOTICON, /**< Custom Emoticon */
    MSN_OBJECT_USERTILE, /**< UserTile (buddy icon) */
    MSN_OBJECT_RESERVED2, /**< Reserved */
    MSN_OBJECT_BACKGROUND, /**< Background */
} MsnObjectType;

/**
 * Creates a MsnObject structure.
 *
 * @return A new MsnObject structure.
 */
MsnObject *msn_object_new(void);

/**
 * Creates a MsnObject structure from a string.
 *
 * @param str The string.
 *
 * @return The new MsnObject structure.
 */
MsnObject *msn_object_new_from_string(const gchar *str);

/**
 * Creates a MsnObject structure from a stored image
 *
 * @param image The image associated to object
 * @param location The object location as stored in MsnObject
 * @param creator The creator of the object
 * @param type The type of the object
 *
 * @return A new MsnObject structure
 */
MsnObject *msn_object_new_from_image(PecanBuffer *image,
                                     const char *location,
                                     const char *creator,
                                     MsnObjectType type);

/**
 * Frees an MsnObject structure.
 *
 * @param obj The object structure.
 */
void msn_object_free(MsnObject *obj);

/**
 * Outputs a string representation of an MsnObject.
 *
 * @param obj The object.
 *
 * @return The string representation. This must be freed.
 */
gchar *msn_object_to_string(const MsnObject *obj);

/**
 * Returns a MsnObject's creator value.
 *
 * @param obj The object.
 *
 * @return The creator value.
 */
const gchar *msn_object_get_creator(const MsnObject *obj);

/**
 * Returns a MsnObject's type.
 *
 * @param obj The object.
 *
 * @return The object type.
 */
MsnObjectType msn_object_get_type(const MsnObject *obj);

/**
 * Returns a MsnObject's location value.
 *
 * @param obj The object.
 *
 * @return The location value.
 */
const gchar *msn_object_get_location(const MsnObject *obj);

/**
 * Returns a MsnObject's SHA1C value if it exists, otherwise SHA1D.
 *
 * @param obj The object.
 *
 * @return The SHA1C value.
 */
const gchar *msn_object_get_sha1(const MsnObject *obj);

/**
 * Associates an image with an MsnObject.
 *
 * @param obj The object.
 * @param buffer The image to associate.
 */
void msn_object_set_image(MsnObject *obj, PecanBuffer *buffer);

/**
 * Returns the image associated with the MsnObject.
 *
 * @param obj The object.
 *
 * @return The associated image.
 */
PecanBuffer *msn_object_get_image(const MsnObject *obj);

#endif /* PECAN_SLP_OBJECT_H */
