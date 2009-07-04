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

#include "cvr/pecan_slp_object.h"
#include "pn_log.h"

#include "io/pecan_buffer.h"

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

struct MsnObject
{
    gboolean local;

    gchar *creator;
    gsize size;
    MsnObjectType type;
    gchar *location;
    gchar *friendly;
    gchar *sha1d;
    gchar *sha1c;

    PecanBuffer *image;
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

MsnObject *
msn_object_new(void)
{
    MsnObject *obj;

    obj = g_new0(MsnObject, 1);

    return obj;
}

MsnObject *
msn_object_new_from_string(const gchar *str)
{
    MsnObject *obj;
    gchar *tag, *c;

    if (strncmp(str, "<msnobj ", 8))
        return NULL;

    obj = msn_object_new();

    GET_STRING_TAG(creator,  "Creator");
    GET_INT_TAG(size,        "Size");
    GET_INT_TAG(type,        "Type");
    GET_STRING_TAG(location, "Location");
    GET_STRING_TAG(friendly, "Friendly");
    GET_STRING_TAG(sha1d,    "SHA1D");
    GET_STRING_TAG(sha1c,    "SHA1C");

    /* check required fields */
    if (!obj->creator || !obj->size || !obj->type ||
        !obj->location || !obj->friendly || !obj->sha1d)
    {
        pn_error("discarding: str=[%s]", str);
        msn_object_free(obj);
        obj = NULL;
    }

    return obj;
}

MsnObject *
msn_object_new_from_image(PecanBuffer *image,
                          const char *location,
                          const char *creator,
                          MsnObjectType type)
{
    MsnObject *obj = NULL;
    PurpleCipherContext *ctx;
    char *buf;
    char *base64;
    unsigned char digest[20];

    if (!image)
        return obj;

    obj = msn_object_new();
    obj->local = TRUE;
    obj->type = type;
    obj->location = g_strdup(location);
    obj->creator = g_strdup(creator);
    obj->friendly = g_strdup("AAA=");

    local_objs = g_list_append(local_objs, obj);
    msn_object_set_image(obj, image);

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
msn_object_free(MsnObject *obj)
{
    if (!obj)
        return;

    g_free(obj->creator);
    g_free(obj->location);
    g_free(obj->friendly);
    g_free(obj->sha1d);
    g_free(obj->sha1c);

    pecan_buffer_free(obj->image);

    if (obj->local)
        local_objs = g_list_remove(local_objs, obj);

    g_free(obj);
}

gchar *
msn_object_to_string(const MsnObject *obj)
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

const gchar *
msn_object_get_creator(const MsnObject *obj)
{
    return obj->creator;
}

MsnObjectType
msn_object_get_type(const MsnObject *obj)
{
    return obj->type;
}

const gchar *
msn_object_get_location(const MsnObject *obj)
{
    return obj->location;
}

const gchar *
msn_object_get_sha1(const MsnObject *obj)
{
    return (obj->sha1c) ? obj->sha1c : obj->sha1d;
}

void
msn_object_set_image(MsnObject *obj,
                     PecanBuffer *buffer)
{
    pecan_buffer_free(obj->image);
    obj->image = buffer;
}

static MsnObject *
find_local(const gchar *sha1)
{
    GList *l;

    for (l = local_objs; l; l = l->next) {
        MsnObject *local_obj = l->data;

        if (strcmp(msn_object_get_sha1(local_obj), sha1) == 0)
            return local_obj;
    }

    return NULL;
}

PecanBuffer *
msn_object_get_image(const MsnObject *obj)
{
    MsnObject *local_obj;

    local_obj = find_local(msn_object_get_sha1(obj));

    if (!local_obj)
        return NULL;

    return local_obj->image;
}
