/*
 *   zsync - client side rsync over http
 *   Copyright (C) 2004,2005,2009 Colin Phipps <cph@moria.org.uk>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the Artistic License v2 (see the accompanying
 *   file COPYING for the full license terms), or, at your option, any later
 *   version of the same license.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   COPYING file for details.
 */

#include <stdio.h>
#include <time.h>
#include "sha1.h"

/* State used during construction of a zsync file.
 */
typedef struct zsyncfile_state_s
{
    size_t blocksize;

    SHA1_CTX shactx;
    off_t len;

    /* State for compressed file handling */
    FILE *zmap;
    int zmapentries;
    char *zhead;

    void (*stream_error)(const char *func, FILE *stream, void *error_context);
    void *error_context;
} zsyncfile_state;

/* Initializes a zsyncfile_state
 */
zsyncfile_state *zsyncfile_init(size_t blocksize);

/* Cleans up a zsyncfile_state
 */
void zsyncfile_finish(zsyncfile_state **state_ptr);

/* Reads the data stream fin and writes to the zsync stream fout the blocksums
 * for the given data.
 *
 * If no_look_inside is 0 and fin begins with the gzip magic, the checksums are
 * computed for the decompressed contents.
 *
 * The state's blocksize and shactx must be initialized, the rest should be
 * zeroed.
 *
 * Returns 0 on success
 */
int zsyncfile_read_stream_write_blocksums(
        FILE *fin, FILE *fout, int no_look_inside, zsyncfile_state *state);

/* Decide how many bytes from the rsum hash and checksum hash per block to keep for
 * a file with the given length and blocksize. Also decide on seq_matches.
 */
void zsyncfile_compute_hash_lengths(off_t len, size_t blocksize,
        int *rsum_len, int *checksum_len);

/* Create a zsync file in fout.
 *
 * It first writes the header followed by the checksums from tf.
 *
 * If do_recompress is 0, zfname and gzopts may be 0.
 * If fname is 0, mtime isn't used.
 * If nurls or nUurls is 0, url and Uurl won't be used.
 *
 * Returns 0 on success.
 */
int zsyncfile_write(FILE *fout, FILE *tf,
        int rsum_len, int checksum_len,
        int do_recompress, const char *zfname, char *gzopts,
        const char *fname, time_t mtime,
        char **url, int nurls,
        char **Uurl, int nUurls,
        zsyncfile_state *state);
