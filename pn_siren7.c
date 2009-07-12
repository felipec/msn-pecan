/**
 * Copyright (C) 2008-2009 Felipe Contreras
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

/**
 * This file was originally written by Youness Alaoui <kakaroto@kakaroto.homelinux.net>
 * in order to create a simple test program for libsiren. The original file is
 * available at:
 * https://amsn.svn.sourceforge.net/svnroot/amsn/trunk/amsn/utils/tcl_siren/src/siren_test.c
 */

#include <stdio.h>
#include "ext/libsiren/siren7.h"

#define RIFF_ID 0x46464952
#define WAVE_ID 0x45564157
#define FMT_ID 0x20746d66
#define DATA_ID 0x61746164
#define FACT_ID 0x74636166

typedef struct
{
    unsigned int chunk_id;
    unsigned int chunk_size;
} wav_data;

typedef struct
{
    unsigned int chunk_id;
    unsigned int chunk_size;
    unsigned int type_id;
} riff_data;

typedef struct
{
    unsigned short format;
    unsigned short channels;
    unsigned int sample_rate;
    unsigned int byte_rate;
    unsigned short block_align;
    unsigned short bits_per_sample;
} fmt_chunk;

typedef struct
{
    fmt_chunk fmt;
    unsigned short extra_size;
    unsigned char *extra_content;
} fmt_chunk_ex;

#define IDX(val, i) ((unsigned int) ((unsigned char *) &val)[i])

#define GUINT16_FROM_LE(val) ((unsigned short) (IDX (val, 0) + (unsigned short) IDX (val, 1) * 256))
#define GUINT32_FROM_LE(val) ((unsigned int) (IDX (val, 0) + IDX (val, 1) * 256 + \
                                              IDX (val, 2) * 65536 + IDX (val, 3) * 16777216))

void
pn_siren7_decode_file (const char *input_file, const char *output_file)
{
    FILE * input;
    FILE * output;
    riff_data riff_header;
    wav_data current_chunk;
    fmt_chunk_ex fmt_info;
    unsigned char *out_data = NULL;
    unsigned char *out_ptr = NULL;
    unsigned char in_buffer[40];
    unsigned int file_offset;
    unsigned int chunk_offset;

    SirenDecoder decoder = Siren7_NewDecoder (16000);

    input = fopen (input_file, "rb");
    output = fopen (output_file, "wb");

    file_offset = 0;
    fread (&riff_header, sizeof (riff_data), 1, input);
    file_offset += sizeof (riff_data);

    riff_header.chunk_id = GUINT32_FROM_LE (riff_header.chunk_id);
    riff_header.chunk_size = GUINT32_FROM_LE (riff_header.chunk_size);
    riff_header.type_id = GUINT32_FROM_LE (riff_header.type_id);

    if (riff_header.chunk_id == RIFF_ID && riff_header.type_id == WAVE_ID)
    {
        while (file_offset < riff_header.chunk_size)
        {
            fread (&current_chunk, sizeof (wav_data), 1, input);
            file_offset += sizeof (wav_data);
            current_chunk.chunk_id = GUINT32_FROM_LE (current_chunk.chunk_id);
            current_chunk.chunk_size = GUINT32_FROM_LE (current_chunk.chunk_size);

            chunk_offset = 0;
            if (current_chunk.chunk_id == FMT_ID)
            {
                fread (&fmt_info, sizeof (fmt_chunk), 1, input);
                /* Should convert from LE the fmt_info structure, but it's not necessary... */
                if (current_chunk.chunk_size > sizeof (fmt_chunk))
                {
                    fread (&(fmt_info.extra_size), sizeof (short), 1, input);
                    fmt_info.extra_size = GUINT32_FROM_LE (fmt_info.extra_size);
                    fmt_info.extra_content = (unsigned char *) malloc (fmt_info.extra_size);
                    fread (fmt_info.extra_content, fmt_info.extra_size, 1, input);
                }
                else
                {
                    fmt_info.extra_size = 0;
                    fmt_info.extra_content = NULL;
                }
            }
            else if (current_chunk.chunk_id  == DATA_ID)
            {
                out_data = (unsigned char *) malloc (current_chunk.chunk_size * 16);
                out_ptr = out_data;
                while (chunk_offset + 40 <= current_chunk.chunk_size)
                {
                    fread (in_buffer, 1, 40, input);
                    Siren7_DecodeFrame (decoder, in_buffer, out_ptr);
                    out_ptr += 640;
                    chunk_offset += 40;
                }
                fread (in_buffer, 1, current_chunk.chunk_size - chunk_offset, input);
            }
            else
            {
                fseek (input, current_chunk.chunk_size, SEEK_CUR);
            }

            file_offset += current_chunk.chunk_size;
        }
    }

    /* The WAV heder should be converted TO LE, but should be done inside the library and it's not important for now ... */
    fwrite (&(decoder->WavHeader), sizeof (decoder->WavHeader), 1, output);
    fwrite (out_data, 1, GUINT32_FROM_LE (decoder->WavHeader.DataSize), output);
    fclose (output);

    Siren7_CloseDecoder (decoder);

    free (out_data);
    free (fmt_info.extra_content);
}
