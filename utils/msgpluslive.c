/**
 * Copyright (C) 2008-2009 Devid Antonio Filoni
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include <stdlib.h>

struct PlusTag
{
    char *code;
    int len;
};

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

char* remove_plus_tags_from_str (const char* str)
{
    char *next_code, *final_str = NULL;
    int code_number;

    final_str = strdup (str);

    for (code_number = 0; codes[code_number].code; code_number++)
    {
        int occurences = 0;
        char *parsed_str = NULL;

        parsed_str = calloc (strlen (final_str)+1, 1);

        next_code = strstr (final_str, codes[code_number].code);
        while (next_code)
        {
            if (code_number == 0 || code_number == 1 || code_number == 10 || code_number == 11)
            {
                if (strstr (next_code, "]"))
                    codes[code_number].len = strlen (next_code)-strlen (strstr (next_code, "]"))+1;
                else
                    codes[code_number].len = 0;
            }
            else if (code_number == 12)
            {
                if (strlen (next_code) == 3)
                    codes[12].len = 3;
                else if (strncmp (next_code+3, "#", 1) == 0)
                    codes[12].len = 10;
                else
                {
                    if (strstr (next_code, ","))
                    {
                        if (strlen (next_code)-4 == strlen (strstr (next_code, ",")))
                            codes[12].len = 6;
                        else if (strlen (next_code)-5 == strlen (strstr (next_code, ",")) &&
                                 strncmp (next_code+3, "1", 1) == 0 && (strncmp (next_code+4, "0", 1) == 0 ||
                                 strncmp (next_code+4, "1", 1) == 0 || strncmp (next_code+4, "2", 1) == 0 ||
                                 strncmp (next_code+4, "3", 1) == 0 || strncmp (next_code+4, "4", 1) == 0 ||
                                 strncmp (next_code+4, "5", 1) == 0))
                            codes[12].len = 7;
                        else
                            codes[12].len = 4;
                    }
                    else
                        codes[12].len = 4;

                    if (strncmp (next_code+codes[code_number].len-1, "1", 1) == 0 &&
                        (strncmp (next_code+codes[code_number].len, "0", 1) == 0 ||
                         strncmp (next_code+codes[code_number].len, "1", 1) == 0 ||
                         strncmp (next_code+codes[code_number].len, "2", 1) == 0 ||
                         strncmp (next_code+codes[code_number].len, "3", 1) == 0 ||
                         strncmp (next_code+codes[code_number].len, "4", 1) == 0 ||
                         strncmp (next_code+codes[code_number].len, "5", 1) == 0))
                        codes[12].len++;
                }
            }
            else if (code_number == 18 || code_number == 19 || code_number == 28 || code_number == 29)
            {
                if (strstr (next_code, "&#x5D;"))
                    codes[code_number].len = strlen (next_code)-strlen (strstr (next_code, "&#x5D;"))+6;
                else
                    codes[code_number].len = 0;
            }

            if (codes[code_number].len != 0)
            {
                strncat (parsed_str, final_str+occurences+strlen (parsed_str),
                     strlen (final_str)-strlen (parsed_str)-strlen (next_code)-occurences);
                occurences += codes[code_number].len;

                if (next_code+codes[code_number].len)
                    next_code = strstr (next_code+codes[code_number].len, codes[code_number].code);
                else
                    next_code = NULL;
            }
            else
                if (next_code+1)
                    next_code = strstr (next_code+1, codes[code_number].code);
                else
                    next_code = NULL;
        }
        strcat (parsed_str, final_str+occurences+strlen (parsed_str));

        memcpy (final_str, parsed_str, strlen (parsed_str)+1);
        free (parsed_str);
    }

    return final_str;
}
