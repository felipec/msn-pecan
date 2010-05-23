/**
 * Copyright (C) 2007-2009 Felipe Contreras
 * Copyright (C) 2008-2009 Devid Antonio Filoni
 * Copyright (C) 2005 Sanoi <sanoix@gmail.com>
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

#include "pn_util.h"
#include "pn_global.h"

#include <string.h>
#include <stdlib.h> /* for calloc, free */
#include <stdio.h> /* for sscanf */

#include <glib.h>

#ifdef HAVE_LIBPURPLE
#include <util.h>
#include <cipher.h>

#define BUFSIZE 256
#endif /* HAVE_LIBPURPLE */

struct PlusTag
{
    char *code;
    int len;
};

gboolean
check_if_first_char_str_is_number (const gchar* str)
{
    if (strncmp (str, "0", 1) == 0 || strncmp (str, "1", 1) == 0 ||
        strncmp (str, "2", 1) == 0 || strncmp (str, "3", 1) == 0 ||
        strncmp (str, "4", 1) == 0 || strncmp (str, "5", 1) == 0 ||
        strncmp (str, "6", 1) == 0 || strncmp (str, "7", 1) == 0 ||
        strncmp (str, "8", 1) == 0 || strncmp (str, "9", 1) == 0)
        return TRUE;
    else
        return FALSE;
}

gchar *
remove_plus_tags_from_str (const gchar* str)
{
    gchar *next_code, *final_str = NULL;
    int code_number;
    struct PlusTag codes[] = {
        { "[c=", -1 },
        { "[/c", -1 },
        { "[b]", 3 },
        { "[/b]", 4 },
        { "[i]", 3 },
        { "[/i]", 4 },
        { "[u]", 3 },
        { "[/u]", 4 },
        { "[s]", 3 },
        { "[/s]", 4 },
        { "[a=", -1 },
        { "[/a", -1 },
        { "·$", -1 },
        { "·#", 3 },
        { "·&", 3 },
        { "·@", 3 },
        { "·'", 3 },
        { "·0", 3 },
        { "&#x5B;c&#x3D;", -1 },
        { "&#x5B;/c", -1 },
        { "&#x5B;b&#x5D;", 13 },
        { "&#x5B;/b&#x5D;", 14 },
        { "&#x5B;i&#x5D;", 13 },
        { "&#x5B;/i&#x5D;", 14 },
        { "&#x5B;u&#x5D;", 13 },
        { "&#x5B;/u&#x5D;", 14 },
        { "&#x5B;s&#x5D;", 13 },
        { "&#x5B;/s&#x5D;", 14 },
        { "&#x5B;a&#x3D;", -1 },
        { "&#x5B;/a", -1 },
        { NULL, -1 }
    };

    final_str = g_strdup (str);

    for (code_number = 0; codes[code_number].code; code_number++)
    {
        int occurences = 0;
        char *parsed_str = NULL;

        parsed_str = calloc (strlen (final_str) + 1, 1);

        next_code = strstr (final_str, codes[code_number].code);
        while (next_code)
        {
            if (code_number == 0 || code_number == 1 || code_number == 10 || code_number == 11)
            {
                if (strstr (next_code, "]"))
                    codes[code_number].len = strlen (next_code) -
                        strlen (strstr (next_code, "]")) + 1;
                else
                    codes[code_number].len = 0;
            }
            else if (code_number == 12)
            {
                if (strlen (next_code) == 3)
                    codes[12].len = 3;
                else if (strncmp (next_code + 3, "#", 1) == 0)
                    codes[12].len = 10;
                else if (strncmp (next_code + 3, "(", 1) == 0 && strncmp (next_code + 15, ")", 1) == 0)
                {
                    if (strncmp (next_code + 16, ",", 1) == 0)
                    {
                        codes[12].len = 18;

                        if (check_if_first_char_str_is_number (next_code + codes[12].len))
                            codes[12].len++;
                    }
                    else
                        codes[12].len = 16;
                }
                else
                {
                    if (strstr (next_code, ","))
                    {
                        if (strlen (next_code) - 4 == strlen (strstr (next_code, ",")))
                            codes[12].len = 6;
                        else if (strlen (next_code) - 5 == strlen (strstr (next_code, ",")) &&
                                 check_if_first_char_str_is_number (next_code + 4))
                            codes[12].len = 7;
                        else
                            codes[12].len = 4;
                    }
                    else
                        codes[12].len = 4;

                    if (check_if_first_char_str_is_number (next_code + codes[12].len))
                        codes[12].len++;
                }
            }
            else if (code_number == 18 || code_number == 19 || code_number == 28 || code_number == 29)
            {
                if (strstr (next_code, "&#x5D;"))
                    codes[code_number].len = strlen (next_code) -
                        strlen (strstr (next_code, "&#x5D;")) + 6;
                else
                    codes[code_number].len = 0;
            }

            if (codes[code_number].len != 0)
            {
                strncat (parsed_str, final_str + occurences + strlen (parsed_str),
                     strlen (final_str) -
                     strlen (parsed_str) -
                     strlen (next_code) - occurences);
                occurences += codes[code_number].len;

                if (next_code + codes[code_number].len)
                    next_code = strstr (next_code + codes[code_number].len, codes[code_number].code);
                else
                    next_code = NULL;
            }
            else
                if (next_code + 1)
                    next_code = strstr (next_code + 1, codes[code_number].code);
                else
                    next_code = NULL;
        }
        strcat (parsed_str, final_str + occurences + strlen (parsed_str));

        memcpy (final_str, parsed_str, strlen (parsed_str) + 1);
        free (parsed_str);
    }

    return final_str;
}

gchar *
pn_friendly_name_encode (const gchar *value)
{
    const gchar *cur, *b;
    GString *string;

    string = g_string_new_len(NULL, strlen(value));

    cur = value;
    do {
        b = strpbrk(cur, "% ");
        if (!b) {
            g_string_append(string, cur);
            break;
        }
        g_string_append_len(string, cur, b - cur);
        g_string_append_printf(string, "%%%02x", *b);
        cur = b + 1;
    } while(*cur);
    return g_string_free(string, FALSE);
}

gchar *
pn_url_decode (const gchar *url)
{
    gchar *new;
    const gchar *src;
    gchar *dest;

    /* RFC 1738:
     *
     * Thus, only alphanumerics, the special characters "$-_.+!*'(),", and
     * reserved characters used for their reserved purposes may be used
     * unencoded within a URL.
     */

    dest = new = g_malloc (strlen (url) + 1);
    src = url;

    while (*src != '\0')
    {
        if (*src == '%')
        {
            gint v1;
            gint v2;

            v1 = g_ascii_xdigit_value (src[1]);
            v2 = g_ascii_xdigit_value (src[2]);

            if ((v1 >= 0) && (v2 >= 0))
            {
                *dest = (v1 * 16) + v2;
            }
            else
            {
                /* Malformed */
                g_free (new);
                return NULL;
            }
            src += 3;
        }
        else
        {
            *dest = *src;
            src++;
        }
        dest++;
    }

    *dest = '\0';

    return new;
}

#ifdef HAVE_LIBPURPLE
void
msn_parse_format(const char *mime, char **pre_ret, char **post_ret)
{
    char *cur;
    GString *pre  = g_string_new(NULL);
    GString *post = g_string_new(NULL);
    unsigned int colors[3];

    if (pre_ret  != NULL) *pre_ret  = NULL;
    if (post_ret != NULL) *post_ret = NULL;

    cur = strstr(mime, "FN=");

    if (cur && (*(cur = cur + 3) != ';'))
    {
        pre = g_string_append(pre, "<FONT FACE=\"");

        while (*cur && *cur != ';')
        {
            pre = g_string_append_c(pre, *cur);
            cur++;
        }

        pre = g_string_append(pre, "\">");
        post = g_string_prepend(post, "</FONT>");
    }

    cur = strstr(mime, "EF=");

    if (cur && (*(cur = cur + 3) != ';'))
    {
        while (*cur && *cur != ';')
        {
            pre = g_string_append_c(pre, '<');
            pre = g_string_append_c(pre, *cur);
            pre = g_string_append_c(pre, '>');
            post = g_string_prepend_c(post, '>');
            post = g_string_prepend_c(post, *cur);
            post = g_string_prepend_c(post, '/');
            post = g_string_prepend_c(post, '<');
            cur++;
        }
    }

    cur = strstr(mime, "CO=");

    if (cur && (*(cur = cur + 3) != ';'))
    {
        int i;

        i = sscanf(cur, "%02x%02x%02x;", &colors[0], &colors[1], &colors[2]);

        if (i > 0)
        {
            char tag[64];

            if (i == 1)
            {
                colors[1] = 0;
                colors[2] = 0;
            }
            else if (i == 2)
            {
                unsigned int temp = colors[0];

                colors[0] = colors[1];
                colors[1] = temp;
                colors[2] = 0;
            }
            else if (i == 3)
            {
                unsigned int temp = colors[2];

                colors[2] = colors[0];
                colors[0] = temp;
            }

            g_snprintf(tag, sizeof(tag),
                       "<FONT COLOR=\"#%02hx%02hx%02hx\">",
                       colors[0], colors[1], colors[2]);

            pre = g_string_append(pre, tag);
            post = g_string_prepend(post, "</FONT>");
        }
    }

    cur = strstr(mime, "RL=");

    if (cur && (*(cur = cur + 3) != ';'))
    {
        if (*cur == '1')
        {
            /* RTL text was received */
            pre = g_string_append(pre, "<SPAN style=\"direction:rtl;text-align:right;\">");
            post = g_string_prepend(post, "</SPAN>");
        }
    }

    cur = g_strdup(purple_url_decode(pre->str));
    g_string_free(pre, TRUE);

    if (pre_ret != NULL)
        *pre_ret = cur;
    else
        g_free(cur);

    cur = g_strdup(purple_url_decode(post->str));
    g_string_free(post, TRUE);

    if (post_ret != NULL)
        *post_ret = cur;
    else
        g_free(cur);
}

/*
 * We need this because we're only supposed to encode spaces in the font
 * names. purple_url_encode() isn't acceptable.
 */
static const char *
encode_spaces(const char *str)
{
    static char buf[PN_BUF_LEN];
    const char *c;
    char *d;

    g_return_val_if_fail(str != NULL, NULL);

    for (c = str, d = buf; *c != '\0'; c++)
    {
        if (*c == ' ')
        {
            *d++ = '%';
            *d++ = '2';
            *d++ = '0';
        }
        else
            *d++ = *c;
    }

    return buf;
}

/*
 * Taken from the zephyr plugin.
 * This parses HTML formatting (put out by one of the gtkimhtml widgets
 * and converts it to msn formatting. It doesn't deal with the tag closing,
 * but gtkimhtml widgets give valid html.
 * It currently deals properly with <b>, <u>, <i>, <font face=...>,
 * <font color=...>, <span dir=...>, <span style="direction: ...">.
 * It ignores <font back=...> and <font size=...>
 */
void
msn_import_html(const char *html, char **attributes, char **message)
{
    int len, retcount = 0;
    const char *c;
    char *msg;
    char *fontface = NULL;
    char fonteffect[5];
    char fontcolor[7];
    char direction = '0';

    gboolean has_bold = FALSE;
    gboolean has_italic = FALSE;
    gboolean has_underline = FALSE;
    gboolean has_strikethrough = FALSE;

    g_return_if_fail(html       != NULL);
    g_return_if_fail(attributes != NULL);
    g_return_if_fail(message    != NULL);

    len = strlen(html);
    msg = g_malloc0(len + 1);

    memset(fontcolor, 0, sizeof(fontcolor));
    strcat(fontcolor, "0");
    memset(fonteffect, 0, sizeof(fonteffect));

    for (c = html; *c != '\0';)
    {
        if (*c == '<')
        {
            if (!g_ascii_strncasecmp(c + 1, "br>", 3))
            {
                msg[retcount++] = '\r';
                msg[retcount++] = '\n';
                c += 4;
            }
            else if (!g_ascii_strncasecmp(c + 1, "i>", 2))
            {
                if (!has_italic)
                {
                    strcat(fonteffect, "I");
                    has_italic = TRUE;
                }
                c += 3;
            }
            else if (!g_ascii_strncasecmp(c + 1, "b>", 2))
            {
                if (!has_bold)
                {
                    strcat(fonteffect, "B");
                    has_bold = TRUE;
                }
                c += 3;
            }
            else if (!g_ascii_strncasecmp(c + 1, "u>", 2))
            {
                if (!has_underline)
                {
                    strcat(fonteffect, "U");
                    has_underline = TRUE;
                }
                c += 3;
            }
            else if (!g_ascii_strncasecmp(c + 1, "s>", 2))
            {
                if (!has_strikethrough)
                {
                    strcat(fonteffect, "S");
                    has_strikethrough = TRUE;
                }
                c += 3;
            }
            else if (!g_ascii_strncasecmp(c + 1, "a href=\"", 8))
            {
                c += 9;

                if (!g_ascii_strncasecmp(c, "mailto:", 7))
                    c += 7;

                while ((*c != '\0') && g_ascii_strncasecmp(c, "\">", 2))
                    msg[retcount++] = *c++;

                if (*c != '\0')
                    c += 2;

                /* ignore descriptive string */
                while ((*c != '\0') && g_ascii_strncasecmp(c, "</a>", 4))
                    c++;

                if (*c != '\0')
                    c += 4;
            }
            else if (!g_ascii_strncasecmp(c + 1, "span", 4))
            {
                /* Bi-directional text support using CSS properties in span tags */
                c += 5;

                while (*c != '\0' && *c != '>')
                {
                    while (*c == ' ')
                        c++;
                    if (!g_ascii_strncasecmp(c, "dir=\"rtl\"", 9))
                    {
                        c += 9;
                        direction = '1';
                    }
                    else if (!g_ascii_strncasecmp(c, "style=\"", 7))
                    {
                        /* Parse inline CSS attributes */
                        char *css_attributes;
                        int attr_len = 0;
                        c += 7;
                        while (*(c + attr_len) != '\0' && *(c + attr_len) != '"')
                            attr_len++;
                        if (*(c + attr_len) == '"')
                        {
                            char *attr_dir;
                            css_attributes = g_strndup(c, attr_len);
                            attr_dir = purple_markup_get_css_property(css_attributes, "direction");
                            if (attr_dir && (!g_ascii_strncasecmp(attr_dir, "RTL", 3)))
                                direction = '1';
                            g_free(attr_dir);
                            g_free(css_attributes);
                        }

                    }
                    else
                    {
                        c++;
                    }
                }
                if (*c == '>')
                    c++;
            }
            else if (!g_ascii_strncasecmp(c + 1, "font", 4))
            {
                c += 5;

                while ((*c != '\0') && !g_ascii_strncasecmp(c, " ", 1))
                    c++;

                if (!g_ascii_strncasecmp(c, "color=\"#", 7))
                {
                    c += 8;

                    fontcolor[0] = *(c + 4);
                    fontcolor[1] = *(c + 5);
                    fontcolor[2] = *(c + 2);
                    fontcolor[3] = *(c + 3);
                    fontcolor[4] = *c;
                    fontcolor[5] = *(c + 1);

                    c += 8;
                }
                else if (!g_ascii_strncasecmp(c, "face=\"", 6))
                {
                    const char *end = NULL;
                    const char *comma = NULL;
                    unsigned int namelen = 0;

                    c += 6;
                    end = strchr(c, '\"');
                    comma = strchr(c, ',');

                    if (comma == NULL || comma > end)
                        namelen = (unsigned int)(end - c);
                    else
                        namelen = (unsigned int)(comma - c);

                    fontface = g_strndup(c, namelen);
                    c = end + 2;
                }
                else
                {
                    /* Drop all unrecognized/misparsed font tags */
                    while ((*c != '\0') && g_ascii_strncasecmp(c, "\">", 2))
                        c++;

                    if (*c != '\0')
                        c += 2;
                }
            }
            else
            {
                while ((*c != '\0') && (*c != '>'))
                    c++;
                if (*c != '\0')
                    c++;
            }
        }
        else if (*c == '&')
        {
            if (!g_ascii_strncasecmp(c, "&lt;", 4))
            {
                msg[retcount++] = '<';
                c += 4;
            }
            else if (!g_ascii_strncasecmp(c, "&gt;", 4))
            {
                msg[retcount++] = '>';
                c += 4;
            }
            else if (!g_ascii_strncasecmp(c, "&nbsp;", 6))
            {
                msg[retcount++] = ' ';
                c += 6;
            }
            else if (!g_ascii_strncasecmp(c, "&quot;", 6))
            {
                msg[retcount++] = '"';
                c += 6;
            }
            else if (!g_ascii_strncasecmp(c, "&amp;", 5))
            {
                msg[retcount++] = '&';
                c += 5;
            }
            else if (!g_ascii_strncasecmp(c, "&apos;", 6))
            {
                msg[retcount++] = '\'';
                c += 6;
            }
            else
                msg[retcount++] = *c++;
        }
        else
            msg[retcount++] = *c++;
    }

    if (fontface == NULL)
        fontface = g_strdup("MS Sans Serif");

    *attributes = g_strdup_printf("FN=%s; EF=%s; CO=%s; PF=0; RL=%c",
                                  encode_spaces(fontface),
                                  fonteffect, fontcolor, direction);
    *message = msg;

    g_free(fontface);
}

void
pn_handle_challenge (const gchar *input,
                     const gchar *product_id,
                     const gchar *product_key,
                     gchar *output)
{
    const gchar *hexChars = "0123456789abcdef";
    char buf[BUFSIZE];
    unsigned char md5Hash[16], *newHash;
    unsigned int *md5Parts, *chlStringParts, newHashParts[5];

    long long nHigh = 0;
    long long nLow = 0;

    guint i;

    /* Create the MD5 hash */
    {
        PurpleCipher *cipher;
        PurpleCipherContext *context;

        cipher = purple_ciphers_find_cipher ("md5");
        context = purple_cipher_context_new (cipher, NULL);

        purple_cipher_context_append (context, (const guchar *) input, strlen (input));
        purple_cipher_context_append (context, (const guchar *) product_key, strlen (product_key));

        purple_cipher_context_digest (context, sizeof (md5Hash), md5Hash, NULL);
        purple_cipher_context_destroy (context);
    }

    /* Split it into four integers */
    md5Parts = (unsigned int *) md5Hash;
    for (i = 0; i < 4; i++)
    {
        /* check for endianess */
        md5Parts[i] = GINT_TO_LE (md5Parts[i]);

        /* & each integer with 0x7FFFFFFF          */
        /* and save one unmodified array for later */
        newHashParts[i] = md5Parts[i];
        md5Parts[i] &= 0x7FFFFFFF;
    }

    /* make a new string and pad with '0' */
    g_snprintf (buf, BUFSIZE - 5, "%s%s", input, product_id);
    i = strlen (buf);
    memset (&buf[i], '0', 8 - (i % 8));
    buf[i + (8 - (i % 8))] = '\0';

    /* split into integers */
    chlStringParts = (unsigned int *) buf;

    /* this is magic */
    for (i = 0; i < (strlen (buf) / 4) - 1; i += 2)
    {
        long long temp;

        chlStringParts[i] = GINT_TO_LE (chlStringParts[i]);
        chlStringParts[i + 1] = GINT_TO_LE (chlStringParts[i + 1]);

        temp = (md5Parts[0] * (((0x0E79A9C1 * (long long) chlStringParts[i]) % 0x7FFFFFFF) + nHigh) + md5Parts[1]) % 0x7FFFFFFF;
        nHigh = (md5Parts[2] * (((long long) chlStringParts[i + 1] + temp) % 0x7FFFFFFF) + md5Parts[3]) % 0x7FFFFFFF;
        nLow = nLow + nHigh + temp;
    }
    nHigh = (nHigh + md5Parts[1]) % 0x7FFFFFFF;
    nLow = (nLow + md5Parts[3]) % 0x7FFFFFFF;

    newHashParts[0] ^= nHigh;
    newHashParts[1] ^= nLow;
    newHashParts[2] ^= nHigh;
    newHashParts[3] ^= nLow;

    /* swap more bytes if big endian */
    for (i = 0; i < 4; i++)
        newHashParts[i] = GINT_TO_LE (newHashParts[i]);

    /* make a string of the parts */
    newHash = (unsigned char *) newHashParts;

    /* convert to hexadecimal */
    for (i = 0; i < 16; i++)
    {
        output[i * 2] = hexChars[(newHash[i] >> 4) & 0xF];
        output[(i * 2) + 1] = hexChars[newHash[i] & 0xF];
    }
}
#endif /* HAVE_LIBPURPLE */

void
msn_parse_socket(const char *str, char **ret_host, int *ret_port)
{
    char *host;
    char *c;
    int port;

    host = g_strdup(str);

    if ((c = strchr(host, ':')) != NULL)
    {
        *c = '\0';
        port = atoi(c + 1);
    }
    else
        port = 1863;

    *ret_host = host;
    *ret_port = port;
}

/** @todo remove this crap */
gchar *
pn_normalize (const gchar *str)
{
    gchar *new;
    gchar *tmp;

    g_return_val_if_fail(str != NULL, NULL);

    if (strchr (str, '@'))
        return g_strdup (str);

    tmp = g_utf8_strdown (str, -1);
    new = g_strconcat (tmp, "@hotmail.com", NULL);
    g_free (tmp);

    return new;
}

static gboolean
true_predicate (gpointer key,
                gpointer value,
                gpointer user_data)
{
    return TRUE;
}

gpointer
g_hash_table_peek_first (GHashTable *hash_table)
{
    g_return_val_if_fail (hash_table, NULL);

    return g_hash_table_find (hash_table, true_predicate, NULL);
}

gboolean
g_ascii_strcase_equal (gconstpointer v1,
                       gconstpointer v2)
{
    const gchar *string1 = v1;
    const gchar *string2 = v2;

    return g_ascii_strcasecmp (string1, string2) == 0;
}

guint
g_ascii_strcase_hash (gconstpointer v)
{
    /* 31 bit hash function */
    const signed char *p = v;
    guint32 h = *p;

    if (h)
        for (p += 1; *p != '\0'; p++)
            h = (h << 5) - h + g_ascii_tolower (*p);

    return h;
}

/** @todo make this more efficient. */
gchar *
pn_get_xml_field (const gchar *tag,
                  const gchar *start,
                  const gchar *end)
{
    const gchar *field_start;
    const gchar *field_end;
    gchar *field = NULL;
    gchar *tag_start;
    gchar *tag_end;

    tag_start = g_strconcat ("<", tag, ">", NULL);
    tag_end = g_strconcat ("</", tag, ">", NULL);

    field_start = g_strstr_len (start, end - start, tag_start);
    if (field_start)
    {
        field_start += strlen (tag_start);
        field_end = g_strstr_len (field_start, field_start - end, tag_end);

        if (field_end > field_start)
        {
            field = g_strndup (field_start, field_end - field_start);
        }
    }

    g_free (tag_start);
    g_free (tag_end);

    return field;
}

struct ref {
    const char *name;
    const char *value;
};

char *
pn_html_unescape (const char *url)
{
    GString *dest;
    const char *src;

    dest = g_string_new ("");
    src = url;

    while (*src != '\0') {
        if (*src == '&') {
            const char *end;
            end = strchr (src, ';');
            src++;

            if (!end)
                goto malformed;

            if (src[0] == '#') {
                int id, n;

                src++;

                if (src[0] == 'x')
                    n = sscanf (src + 1, "%x", &id);
                else
                    n = sscanf (src, "%u", &id);
                if (n != 1)
                    goto malformed;

                dest = g_string_append_unichar (dest, id);
            }
            else {
                struct ref refs[] = {
                    { "amp", "&" },
                    { "lt", "<" },
                    { "gt", ">" },
                    { "nbsp", " " },
                    { "copy", "©" },
                    { "quot", "\"" },
                    { "reg", "®" },
                    { "apos", "'" },
                };
                int i;
                for (i = 0; i < ARRAY_SIZE(refs); i++) {
                    struct ref ref = refs[i];
                    int len = strlen(ref.name);
                    if (strncmp (src, ref.name, len) == 0) {
                        dest = g_string_append (dest, ref.value);
                        src += len;
                        break;
                    }
                }
            }

            src = end + 1;
        }
        else {
            dest = g_string_append_c (dest, *src);
            src++;
        }
    }

    return g_string_free (dest, FALSE);

malformed:
    return g_string_free (dest, TRUE);
}

char *
pn_rand_guid(void)
{
    return g_strdup_printf("%4X%4X-%4X-%4X-%4X-%4X%4X%4X",
                           rand() % 0xAAFF + 0x1111,
                           rand() % 0xAAFF + 0x1111,
                           rand() % 0xAAFF + 0x1111,
                           rand() % 0xAAFF + 0x1111,
                           rand() % 0xAAFF + 0x1111,
                           rand() % 0xAAFF + 0x1111,
                           rand() % 0xAAFF + 0x1111,
                           rand() % 0xAAFF + 0x1111);
}

time_t
pn_parse_date(const char *str)
{
    gchar month[4], *months[13] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    int d, m, y, hour, min, sec, tz;
    struct tm tm;

    sscanf (str, "%d %3s %d %d:%d:%d %d",
            &d, month, &y, &hour, &min, &sec, &tz);

    for (m = 0; strncmp (month, months[m], 3) != 0; m++);

    hour -= tz / 100;

    memset(&tm, 0, sizeof(tm));
    tm.tm_sec = sec;
    tm.tm_min = min;
    tm.tm_hour = hour;
    tm.tm_mday = d;
    tm.tm_mon = m;
    tm.tm_year = y - 1900;
    tm.tm_isdst = 0;

    return mktime (&tm) - timezone;
}
