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

#include "cvr/pn_msnobj.h"
#include "pn_log.h"

#include "io/pn_buffer.h"

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_LIBPURPLE
#include "fix_purple.h"

/* libpurple stuff. */
#include <imgstore.h>
/* for custom emoticon sending */
#include <cipher.h>
#include <util.h>
#endif /* HAVE_LIBPURPLE */

struct PnMsnObj
{
    gboolean local;

    gchar *creator;
    gsize size;
    PnMsnObjType type;
    gchar *location;
    gchar *friendly;
    gchar *sha1d;
    gchar *sha1c;

    PnBuffer *image;
};

#define GET_STRING_TAG(field, id) \
    if ((tag = strstr(str, id "=\"")) != NULL) \
{ \
    tag += strlen(id "=\""); \
    c = strchr(tag, '"'); \
    if (c != NULL) \
    { \
        if (obj->field != NULL) \
        g_free(obj->field); \
        obj->field = g_strndup(tag, c - tag); \
    } \
}

#define GET_INT_TAG(field, id) \
    if ((tag = strstr(str, id "=\"")) != NULL) \
{ \
    gchar buf[16]; \
    gsize offset; \
    tag += strlen(id "=\""); \
    c = strchr(tag, '"'); \
    if (c != NULL) \
    { \
        memset(buf, 0, sizeof(buf)); \
        offset = c - tag; \
        if (offset >= sizeof(buf)) \
        offset = sizeof(buf) - 1; \
        strncpy(buf, tag, offset); \
        obj->field = atoi(buf); \
    } \
}

static GList *local_objs;

PnMsnObj *
pn_msnobj_new(void)
{
    PnMsnObj *obj;

    obj = g_new0(PnMsnObj, 1);

    return obj;
}

PnMsnObj *
pn_msnobj_new_from_string(const gchar *str)
{
    PnMsnObj *obj;
    gchar *tag, *c;

    if (strncmp(str, "<msnobj ", 8))
        return NULL;

    obj = pn_msnobj_new();

    GET_INT_TAG(size,        "Size");
    GET_INT_TAG(type,        "Type");
    GET_STRING_TAG(location, "Location");
    GET_STRING_TAG(sha1d,    "SHA1D");
    GET_STRING_TAG(sha1c,    "SHA1C");

    /* check required fields */
    if (!obj->type || !obj->location || !obj->sha1d)
    {
        pn_error("discarding: str=[%s]", str);
        pn_msnobj_free(obj);
        obj = NULL;
    }

    return obj;
}

PnMsnObj *
pn_msnobj_new_from_image(PnBuffer *image,
                         const char *location,
                         const char *creator,
                         PnMsnObjType type)
{
    PnMsnObj *obj = NULL;
    PurpleCipherContext *ctx;
    char *buf;
    char *base64;
    unsigned char digest[20];

    if (!image)
        return obj;

    obj = pn_msnobj_new();
    obj->local = TRUE;
    obj->type = type;
    obj->location = g_strdup(location);
    obj->creator = g_strdup(creator);
    obj->friendly = g_strdup("AAA=");

    local_objs = g_list_append(local_objs, obj);
    pn_msnobj_set_image(obj, image);

    /* Compute the SHA1D field. */
    memset(digest, 0, sizeof(digest));

    ctx = purple_cipher_context_new_by_name("sha1", NULL);
    purple_cipher_context_append(ctx, (const gpointer) image->data, image->len);
    purple_cipher_context_digest(ctx, sizeof(digest), digest, NULL);

    base64 = purple_base64_encode(digest, sizeof(digest));
    obj->sha1d = base64;

    obj->size = image->len;

    /* Compute the SHA1C field. */
    buf = g_strdup_printf("Creator%sSize%dType%dLocation%sFriendly%sSHA1D%s",
                          obj->creator,
                          obj->size,
                          obj->type,
                          obj->location,
                          obj->friendly,
                          obj->sha1d);

    memset(digest, 0, sizeof(digest));

    purple_cipher_context_reset(ctx, NULL);
    purple_cipher_context_append(ctx, (const guchar *) buf, strlen(buf));
    purple_cipher_context_digest(ctx, sizeof(digest), digest, NULL);
    purple_cipher_context_destroy(ctx);
    g_free(buf);

    base64 = purple_base64_encode(digest, sizeof(digest));
    obj->sha1c = base64;

    return obj;
}

void
pn_msnobj_free(PnMsnObj *obj)
{
    if (!obj)
        return;

    g_free(obj->creator);
    g_free(obj->location);
    g_free(obj->friendly);
    g_free(obj->sha1d);
    g_free(obj->sha1c);

    pn_buffer_free(obj->image);

    if (obj->local)
        local_objs = g_list_remove(local_objs, obj);

    g_free(obj);
}

gchar *
pn_msnobj_to_string(const PnMsnObj *obj)
{
    gchar *str;
    const gchar *sha1c;

    sha1c = obj->sha1c;

    str = g_strdup_printf("<msnobj Creator=\"%s\" Size=\"%d\" Type=\"%d\" "
                          "Location=\"%s\" Friendly=\"%s\" SHA1D=\"%s\""
                          "%s%s%s/>",
                          obj->creator,
                          obj->size,
                          obj->type,
                          obj->location,
                          obj->friendly,
                          obj->sha1d,
                          sha1c ? " SHA1C=\"" : "",
                          sha1c ? sha1c : "",
                          sha1c ? "\"" : "");

    return str;
}

PnMsnObjType
pn_msnobj_get_type(const PnMsnObj *obj)
{
    return obj->type;
}

const gchar *
pn_msnobj_get_location(const PnMsnObj *obj)
{
    return obj->location;
}

const gchar *
pn_msnobj_get_sha1(const PnMsnObj *obj)
{
    return (obj->sha1c) ? obj->sha1c : obj->sha1d;
}

void
pn_msnobj_set_image(PnMsnObj *obj,
                    PnBuffer *buffer)
{
    pn_buffer_free(obj->image);
    obj->image = buffer;
}

static PnMsnObj *
find_local(const gchar *sha1)
{
    GList *l;

    for (l = local_objs; l; l = l->next) {
        PnMsnObj *local_obj = l->data;

        if (strcmp(pn_msnobj_get_sha1(local_obj), sha1) == 0)
            return local_obj;
    }

    return NULL;
}

PnBuffer *
pn_msnobj_get_image(const PnMsnObj *obj)
{
    PnMsnObj *local_obj;

    local_obj = find_local(pn_msnobj_get_sha1(obj));

    if (!local_obj)
        return NULL;

    return local_obj->image;
}
