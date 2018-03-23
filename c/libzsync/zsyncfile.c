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

#include "zsyncfile.h"
#include "zsglobal.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#include "librcksum/rcksum.h"
#include "zlib/zlib.h"
#include "zmap.h"
#include "sha1.h"
#include "../format_string.h"

static inline int min_int(int a, int b) {
    return a > b ? b : a;
}

static inline int max_int(int a, int b) {
    return a > b ? a : b;
}

zsyncfile_state *zsyncfile_init(size_t blocksize)
{
    zsyncfile_state *state = malloc(sizeof(zsyncfile_state));
    memset(state, 0, sizeof *state);
    state->blocksize = blocksize;
    SHA1Init(&state->shactx);
    return state;
}

void zsyncfile_finish(zsyncfile_state **state_ptr)
{
    zsyncfile_state *state = *state_ptr;
    if (state->zmap) {
        fclose(state->zmap);
    }
    if (state->zhead) {
        free(state->zhead);
    }
    free(state);
    *state_ptr = 0;
}

static int stream_error(zsyncfile_state *state, const char *func, FILE *stream) {
    state->stream_error(func, stream, state->error_context);
    return -1;
}

static int write_block_sums(unsigned char *buf, size_t got, FILE * f, zsyncfile_state *state) {
    struct rsum r;
    unsigned char checksum[CHECKSUM_SIZE];

    /* Pad for our checksum, if this is a short last block  */
    if (got < state->blocksize)
        memset(buf + got, 0, state->blocksize - got);

    /* Do rsum and checksum, and convert to network endian */
    r = rcksum_calc_rsum_block(buf, state->blocksize);
    rcksum_calc_checksum(&checksum[0], buf, state->blocksize);
    r.a = htonl(r.a);
    r.b = htonl(r.b);

    /* Write them raw to the stream */
    if (fwrite(&r, sizeof r, 1, f) != 1)
        return stream_error(state, "fwrite", f);
    if (fwrite(checksum, sizeof checksum, 1, f) != 1)
        return stream_error(state, "fwrite", f);

    return 0;
}

/* long long pos = in_position(z_stream*)
 * Returns the position (in bits) that zlib has used in the compressed data
 * stream so far */
static inline long long in_position(z_stream * pz) {
    return pz->total_in * (long long)8 - (63 & pz->data_type);
}

#ifdef WITH_ZLIB

/* write_zmap_delta(*prev_in, *prev_out, new_in, new_out, blockstart)
 * Given a position in the compressed and uncompressed streams, write a
 * checkpoint/map entry (to the stream held in the state variable zmap).
 * This is relative to the previous position supplied, and positions must be
 * supplied in order; caller provide two long long* as the first two parameters
 * for write_zmap_delta to use to keep state in.
 * blockstart is a boolean, is true if this is the start of a zlib block
 * (otherwise, this is a mid-block marker).
 */
static void write_zmap_delta(long long *prev_in, long long *prev_out,
                             long long new_in, long long new_out,
                             int blockstart, zsyncfile_state *state) {
    struct gzblock g;
    {   /* Calculate number of bits that the input (compressed stream) pointer
         * has advanced from the previous entry. */
        uint16_t inbits = new_in - *prev_in;

        if (*prev_in + inbits != new_in) {
            fprintf(stderr,
                    "too long between blocks (try a smaller block size with -b)\n");
            exit(1);
        }

        /* Convert to network endian, save in zmap struct, update state */
        inbits = htons(inbits);
        g.inbitoffset = inbits;
        *prev_in = new_in;
    }
    {   /* Calculate number of bits that the output (uncompressed stream)
         * pointer has advanced from the previous entry. */
        uint16_t outbytes = new_out - *prev_out;

        outbytes &= ~GZB_NOTBLOCKSTART;
        if ((long long)outbytes + *prev_out != new_out) {
            fprintf(stderr, "too long output of block blocks?");
            exit(1);
        }
        /* Encode blockstart marker in this value */
        if (!blockstart)
            outbytes |= GZB_NOTBLOCKSTART;

        /* Convert to network endian, save in zmap struct, update state */
        outbytes = htons(outbytes);
        g.outbyteoffset = outbytes;
        *prev_out = new_out;
    }

    /* Write out the zmap delta struct */
    if (fwrite(&g, sizeof(g), 1, state->zmap) != 1) {
        perror("write");
        exit(1);
    }

    /* And keep state */
    state->zmapentries++;
}

/* do_zstream(data_stream, zsync_stream, buffer, buffer_len)
 * Constructs the zmap for a compressed data stream, in a temporary file.
 * The compressed data is from data_stream, except that some bytes have already
 * been read from it - those are supplied in buffer (buffer_len of them).
 * The zsync block checksums are written to zsync_stream, and the zmap is
 * written to a temp file and the handle returned in the state var zmap.
 */
static void do_zstream(FILE * fin, FILE * fout, const char *bufsofar, size_t got, zsyncfile_state *state) {
    z_stream zs;
    Bytef *inbuf = malloc(state->blocksize);
    const size_t inbufsz = state->blocksize;
    Bytef *outbuf = malloc(state->blocksize);
    int eoz = 0;
    int header_bits;
    long long prev_in = 0;
    long long prev_out = 0;
    long long midblock_in = 0;
    long long midblock_out = 0;
    int want_zdelta = 0;

    if (!inbuf || !outbuf) {
        fprintf(stderr, "memory allocation failure\n");
        exit(1);
    }

    /* Initialize decompressor */
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = NULL;
    zs.next_in = inbuf;
    zs.avail_in = 0;
    zs.total_in = 0;
    zs.next_out = outbuf;
    zs.avail_out = 0;
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK)
        exit(-1);

    {   /* Skip gzip header and do initial buffer fill */
        const char *p = skip_zhead(bufsofar);

        {   /* Store hex version of gzip header in zhead */
            int header_bytes = p - bufsofar;
            int i;

            header_bits = 8 * header_bytes;
            got -= header_bytes;

            state->zhead = malloc(1 + 2 * header_bytes);
            for (i = 0; i < header_bytes; i++)
                sprintf(state->zhead + 2 * i, "%02x", (unsigned char)bufsofar[i]);
        }
        if (got > inbufsz) {
            fprintf(stderr,
                    "internal failure, " SIZE_T_PF " > " SIZE_T_PF
                    " input buffer available\n", got, inbufsz);
            exit(2);
        }

        /* Copy any remaining already-read data from the buffer to the
         * decompressor input buffer */
        memcpy(inbuf, p, got);
        zs.avail_in = got;

        /* Fill the buffer up to offset inbufsz of the input file - we want to
         * try and keep the input blocks aligned with block boundaries in the
         * underlying filesystem and physical storage */
        if (inbufsz > got + (header_bits / 8))
            zs.avail_in +=
                fread(inbuf + got, 1, inbufsz - got - (header_bits / 8), fin);
    }

    /* Start the zmap. We write into a temp file, which the caller then copies into the zsync file later. */
    state->zmap = tmpfile();
    if (!state->zmap) {
        perror("tmpfile");
        exit(2);
    }

    /* We are past the header, so we are now at the start of the first block */
    write_zmap_delta(&prev_in, &prev_out, header_bits, zs.total_out, 1, state);
    zs.avail_out = state->blocksize;

    /* keep going until the end of the compressed stream */
    while (!eoz) {
        /* refill input buffer if empty */
        if (zs.avail_in == 0) {
            int rc = fread(inbuf, 1, inbufsz, fin);
            if (rc < 0) {
                perror("read");
                exit(2);
            }

            /* Still expecting data (!eoz and avail_in == 0) but none there. */
            if (rc == 0) {
                fprintf(stderr, "Premature end of compressed data.\n");
                exit(1);
            }

            zs.next_in = inbuf;
            zs.avail_in = rc;
        }
        {
            int rc;

            /* Okay, decompress more data from inbuf to outbuf.
             * Z_BLOCK means that decompression will halt if we reach the end of a
             *  compressed block in the input file.
             * And decompression will also stop if outbuf is filled (at which point
             *  we have a whole block of uncompressed data and so should write its
             *  checksums)
             *
             * Terminology note:
             * Compressed block   = zlib block (stream of bytes compressed with
             *                      common huffman table)
             * Uncompressed block = Block of blocksize bytes (starting at an
             *                      offset that is a whole number of blocksize
             *                      bytes blocks from the start of the
             *                      (uncompressed) data. I.e. a zsync block.
             */
            rc = inflate(&zs, Z_BLOCK);
            switch (rc) {
            case Z_STREAM_END:
                eoz = 1;
            case Z_BUF_ERROR:  /* Not really an error, just means we provided stingy buffers */
            case Z_OK:
                break;
            default:
                fprintf(stderr, "zlib error %s\n", zs.msg);
                exit(1);
            }

            /* If the output buffer is filled, i.e. we've now got a whole block of uncompressed data. */
            if (zs.avail_out == 0 || rc == Z_STREAM_END) {
                /* Add to the running SHA1 of the entire file. */
                SHA1Update(&state->shactx, outbuf, state->blocksize - zs.avail_out);

                /* Completed a block; write out its checksums */
                write_block_sums(outbuf, state->blocksize - zs.avail_out, fout, state);

                /* Clear the decompressed data buffer, ready for the next block of uncompressed data. */
                zs.next_out = outbuf;
                zs.avail_out = state->blocksize;

                /* Having passed a block boundary in the uncompressed data */
                want_zdelta = 1;
            }

            /* If we have reached a block boundary in the compressed data */
            if (zs.data_type & 128 || rc == Z_STREAM_END) {
                /* write out info on this block */
                write_zmap_delta(&prev_in, &prev_out,
                                 header_bits + in_position(&zs), zs.total_out,
                                 1, state);

                midblock_in = midblock_out = 0;
                want_zdelta = 0;
            }

            /* If we passed a block boundary in the uncompressed data, record the
             * next available point at which we could stop or start decompression.
             * Write a zmap delta with the 1st when we see the 2nd, etc */
            if (want_zdelta && inflateSafePoint(&zs)) {
                long long cur_in = header_bits + in_position(&zs);
                if (midblock_in) {
                    write_zmap_delta(&prev_in, &prev_out, midblock_in,
                                     midblock_out, 0, state);
                }
                midblock_in = cur_in;
                midblock_out = zs.total_out;
                want_zdelta = 0;
            }
        }
    }

    /* Record uncompressed length */
    state->len += zs.total_out;
    fputc('\n', fout);
    /* Move back to the start of the zmap constructed, ready for the caller to read it back in */
    rewind(state->zmap);

    /* Clean up */
    inflateEnd(&zs);
    free(inbuf);
    free(outbuf);
}

#endif

int zsyncfile_read_stream_write_blocksums(
        FILE *fin, FILE *fout, int no_look_inside, zsyncfile_state *state) {
    unsigned char *buf = malloc(state->blocksize);
    int result = 0;

    if (!buf) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    while (!feof(fin) && result == 0) {
        int got = fread(buf, 1, state->blocksize, fin);

        if (got > 0) {
#ifdef WITH_ZLIB
            if (!no_look_inside && state->len == 0 && buf[0] == 0x1f && buf[1] == 0x8b) {
                do_zstream(fin, fout, (char *)buf, got, state);
                break;
            }
#else
            (void)no_look_inside;
#endif

            /* The SHA-1 sum, unlike our internal block-based sums, is on the whole file and nothing else - no padding */
            SHA1Update(&state->shactx, buf, got);

            result = write_block_sums(buf, got, fout, state);
            state->len += got;
        }
        else {
            if (ferror(fin)) {
                result = stream_error(state, "fread", fin);
            }
        }
    }
    free(buf);
    return result;
}

/* Decide how long a rsum hash and checksum hash per block we need for this file */
void zsyncfile_compute_hash_lengths(
        off_t len, size_t blocksize, int *rsum_len, int *checksum_len) {
    *rsum_len = ceil(((log(len) + log(blocksize)) / log(2) - 8.6) / 8);
    /* For large files, the optimum weak checksum size can be more than
     * what we have available, tough luck */
    if (*rsum_len > 8) {
        *rsum_len = 8;
    }

    /* min lengths of rsums to store */
    *rsum_len = max_int(2, *rsum_len);

    /* Now the checksum length; min of two calculations */
    *checksum_len = max_int(ceil(
            (20 + (log(len) + log(1 + len / blocksize)) / log(2)) / 8),
            ceil((20 + log(1 + len / blocksize) / log(2)) / 8));

    /* Keep checksum_len within 4-16 bytes */
    *checksum_len = min_int(16, max_int(4, *checksum_len));
}

/* fcopy(instream, outstream)
 * Copies data from one stream to the other until EOF on the input.
 */
static int fcopy(FILE * fin, FILE * fout, zsyncfile_state *state) {
    unsigned char buf[4096];
    size_t len;
    int result = 0;

    while ((len = fread(buf, 1, sizeof(buf), fin)) > 0) {
        if (fwrite(buf, 1, len, fout) < len)
            break;
    }
    if (ferror(fin)) {
        result = stream_error(state, "fread", fin);
    }
    if (ferror(fout)) {
        result = stream_error(state, "fwrite", fout);
    }
    return result;
}

/* fcopy_hashes(hash_stream, zsync_stream, rsum_bytes, hash_bytes)
 * Copy the full block checksums from their temporary store file to the .zsync,
 * stripping the hashes down to the desired lengths specified by the last 2
 * parameters.
 */
static int fcopy_hashes(FILE * fin, FILE * fout, size_t rsum_bytes, size_t hash_bytes, zsyncfile_state *state) {
    unsigned char buf[CHECKSUM_SIZE + sizeof(struct rsum)];
    size_t len;
    int result = 0;

    while ((len = fread(buf, 1, sizeof(buf), fin)) > 0) {
        /* write trailing rsum_bytes of the rsum (trailing because the second part of the rsum is more useful in practice for hashing), and leading checksum_bytes of the checksum */
        if (fwrite(buf + sizeof(struct rsum) - rsum_bytes, 1, rsum_bytes, fout) < rsum_bytes)
            break;
        if (fwrite(buf + sizeof(struct rsum), 1, hash_bytes, fout) < hash_bytes)
            break;
    }
    if (ferror(fin)) {
        result = stream_error(state, "fread", fin);
    }
    if (ferror(fout)) {
        result = stream_error(state, "fwrite", fout);
    }
    return result;
}

int zsyncfile_write(
        FILE *fout, FILE *tf,
        int rsum_len, int checksum_len,
        int do_recompress, const char *zfname, char *gzopts,
        const char *fname, time_t mtime,
        char **url, int nurls,
        char **Uurl, int nUurls,
        zsyncfile_state *state) {

    int result = 0;

    /* Okay, start writing the zsync file */
    fprintf(fout, "zsync: " VERSION "\n");

    /* Lines we might include but which older clients can ignore */
    if (do_recompress) {
        if (zfname)
            fprintf(fout, "Safe: Z-Filename Recompress MTime\nZ-Filename: %s\n",
                    zfname);
        else
            fprintf(fout, "Safe: Recompress MTime:\n");
    }

    if (fname) {
        fprintf(fout, "Filename: %s\n", fname);
        if (mtime != -1) {
            char buf[32];
            struct tm mtime_tm;

#ifdef _WIN32
            if (gmtime_s(&mtime_tm, &mtime) == 0) {
#else
            if (gmtime_r(&mtime, &mtime_tm) != NULL) {
#endif
                if (strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %z", &mtime_tm) > 0)
                    fprintf(fout, "MTime: %s\n", buf);
            }
            else {
                fprintf(stderr, "error converting %ld to struct tm\n", mtime);
            }
        }
    }
    fprintf(fout, "Blocksize: " SIZE_T_PF "\n", state->blocksize);
    fprintf(fout, "Length: " OFF_T_PF "\n", state->len);
    fprintf(fout, "Hash-Lengths: 1,%d,%d\n", rsum_len, checksum_len);
    {                           /* Write URLs */
        int i;
        for (i = 0; i < nurls; i++)
            fprintf(fout, "%s: %s\n", state->zmapentries ? "Z-URL" : "URL", url[i]);
        for (i = 0; i < nUurls; i++)
            fprintf(fout, "URL: %s\n", Uurl[i]);
    }

    {   /* Write out SHA1 checksum of the entire file */
        unsigned char digest[SHA1_DIGEST_LENGTH];
        unsigned int i;

        fputs("SHA-1: ", fout);

        SHA1Final(digest, &state->shactx);

        for (i = 0; i < sizeof digest; i++)
            fprintf(fout, "%02x", digest[i]);
        fputc('\n', fout);
    }

    if (do_recompress)      /* Write Recompress header if wanted */
        fprintf(fout, "Recompress: %s %s\n", state->zhead, gzopts);

    /* If we have a zmap, write it, header first and then the map itself */
    if (state->zmapentries) {
        fprintf(fout, "Z-Map2: %d\n", state->zmapentries);
        result = fcopy(state->zmap, fout, state);
        if (result != 0)
            return result;
    }

    /* End of headers */
    fputc('\n', fout);

    /* Now copy the actual block hashes to the .zsync */
    rewind(tf);
    return fcopy_hashes(tf, fout, rsum_len, checksum_len, state);
}
