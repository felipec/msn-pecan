/**
 * Copyright (C) 2008 Felipe Contreras
 * Copyright (C) 2005 Sanoi <sanoix@gmail.com>
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

#include <glib.h>

#include <string.h>

#include <cipher.h>

#define BUFSIZE 256

void
msn_handle_challenge (const gchar *input,
                      const gchar *product_id,
                      gchar *output)
{
    const gchar *productKey = "CFHUR$52U_{VIX5T";
    const gchar *hexChars = "0123456789abcdef";
    char buf[BUFSIZE];
    unsigned char md5Hash[16], *newHash;
    unsigned int *md5Parts, *chlStringParts, newHashParts[5];

    long long nHigh = 0;
    long long nLow = 0;

    int i;

    /* Create the MD5 hash */
    {
        PurpleCipher *cipher;
        PurpleCipherContext *context;
        guchar digest[16];

        cipher = purple_ciphers_find_cipher ("md5");
        context = purple_cipher_context_new (cipher, NULL);

        purple_cipher_context_append (context, input, strlen (input));
        purple_cipher_context_append (context, productKey, strlen (productKey));

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
    snprintf (buf, BUFSIZE - 5, "%s%s", input, product_id);
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
