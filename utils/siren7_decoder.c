/**
 * Copyright (C) 2008 Felipe Contreras
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

/**
 * This file was originally written by Youness Alaoui <kakaroto@kakaroto.homelinux.net>
 * in order to create a simple test program for libsiren. The original file is
 * available at:
 * https://amsn.svn.sourceforge.net/svnroot/amsn/trunk/amsn/utils/tcl_siren/src/siren_test.c
 */

#include <stdio.h>
#include "utils/libsiren/siren7.h"

#define RIFF_ID 0x46464952
#define WAVE_ID 0x45564157
#define FMT__ID 0x20746d66
#define DATA_ID 0x61746164
#define FACT_ID 0x74636166

typedef struct {
	unsigned int ChunkId;
	unsigned int ChunkSize;
} WAVE_CHUNK;

typedef struct {
	unsigned int ChunkId;
	unsigned int ChunkSize;
	unsigned int TypeID;
} RIFF;

typedef struct {
	unsigned short Format; 
	unsigned short Channels;
	unsigned int SampleRate; 
	unsigned int ByteRate;
	unsigned short BlockAlign;
	unsigned short BitsPerSample;
} fmtChunk;

typedef struct {
	fmtChunk fmt;
	unsigned short ExtraSize;
	unsigned char *ExtraContent;
} fmtChunkEx;


#define IDX(val, i) ((unsigned int) ((unsigned char *) &val)[i])

#define GUINT16_FROM_LE(val) ( (unsigned short) ( IDX(val, 0) + (unsigned short) IDX(val, 1) * 256 ))
#define GUINT32_FROM_LE(val) ( (unsigned int) (IDX(val, 0) + IDX(val, 1) * 256 + \
        IDX(val, 2) * 65536 + IDX(val, 3) * 16777216)) 


void
decode_wav_using_siren7 (char *input_file, char *output_file)
{
	FILE * input;
	FILE * output;
	RIFF riff_header;
	WAVE_CHUNK current_chunk;
	fmtChunkEx fmt_info;
	unsigned char *out_data = NULL;
	unsigned char *out_ptr = NULL;
	unsigned char InBuffer[40];
	unsigned int fileOffset;
	unsigned int chunkOffset;

	SirenDecoder decoder = Siren7_NewDecoder(16000);
	
	input = fopen(input_file, "rb");
	output = fopen(output_file, "wb");

	fileOffset = 0;
	fread(&riff_header, sizeof(RIFF), 1, input);
	fileOffset += sizeof(RIFF);

	riff_header.ChunkId = GUINT32_FROM_LE(riff_header.ChunkId);
	riff_header.ChunkSize = GUINT32_FROM_LE(riff_header.ChunkSize);
	riff_header.TypeID = GUINT32_FROM_LE(riff_header.TypeID);

	if (riff_header.ChunkId == RIFF_ID && riff_header.TypeID == WAVE_ID) {
		while (fileOffset < riff_header.ChunkSize) {
			fread(&current_chunk, sizeof(WAVE_CHUNK), 1, input);
			fileOffset += sizeof(WAVE_CHUNK);
			current_chunk.ChunkId = GUINT32_FROM_LE(current_chunk.ChunkId);
			current_chunk.ChunkSize = GUINT32_FROM_LE(current_chunk.ChunkSize);

			chunkOffset = 0;
			if (current_chunk.ChunkId == FMT__ID) {
				fread(&fmt_info, sizeof(fmtChunk), 1, input);
				/* Should convert from LE the fmt_info structure, but it's not necessary... */
				if (current_chunk.ChunkSize > sizeof(fmtChunk)) {
					fread(&(fmt_info.ExtraSize), sizeof(short), 1, input);
					fmt_info.ExtraSize= GUINT32_FROM_LE(fmt_info.ExtraSize);
					fmt_info.ExtraContent = (unsigned char *) malloc (fmt_info.ExtraSize);
					fread(fmt_info.ExtraContent, fmt_info.ExtraSize, 1, input);
				} else {
					fmt_info.ExtraSize = 0;
					fmt_info.ExtraContent = NULL;
				}
			} else if (current_chunk.ChunkId  == DATA_ID) {
				out_data = (unsigned char *) malloc(current_chunk.ChunkSize * 16);
				out_ptr = out_data;
				while (chunkOffset + 40 <= current_chunk.ChunkSize) {
					fread(InBuffer, 1, 40, input);
					Siren7_DecodeFrame(decoder, InBuffer, out_ptr);
					out_ptr += 640;
					chunkOffset += 40;
				}
				fread(InBuffer, 1, current_chunk.ChunkSize - chunkOffset, input);
			} else {
				fseek(input, current_chunk.ChunkSize, SEEK_CUR);
			}
			fileOffset += current_chunk.ChunkSize;
		}
	}
	
	/* The WAV heder should be converted TO LE, but should be done inside the library and it's not important for now ... */
	fwrite(&(decoder->WavHeader), sizeof(decoder->WavHeader), 1, output);
	fwrite(out_data, 1, GUINT32_FROM_LE(decoder->WavHeader.DataSize), output);
	fclose(output);

	Siren7_CloseDecoder(decoder);

	free(out_data);
	if (fmt_info.ExtraContent != NULL)
		free(fmt_info.ExtraContent);
}
