
/*
 *   rcksum/lib - library for using the rsync algorithm to determine
 *               which parts of a file you have and which you need.
 *   Copyright (C) 2004,2005,2007,2009 Colin Phipps <cph@moria.org.uk>
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

/* Effectively the constructor and destructor for the rcksum object.
 * Also handles the file handles on the temporary store.
 */

#include "zsglobal.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#if !defined(_MSC_VER)
#include <unistd.h>
#else
int mkstemp(char *template)
{
    char *t = mktemp(template);
    int fd = open(t, O_RDWR | O_CREAT | O_EXCL);
    return fd;
}
#endif


#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#include "rcksum.h"
#include "internal.h"

/* rcksum_init(num_blocks, block_size, rsum_bytes, checksum_bytes, require_consecutive_matches)
 * Creates and returns an rcksum_state with the given properties
 */
struct rcksum_state *rcksum_init(zs_blockid nblocks, size_t blocksize,
                                 int rsum_bytes, unsigned int checksum_bytes) {
    /* Allocate memory for the object */
    struct rcksum_state *z = malloc(sizeof(struct rcksum_state));
    if (z == NULL) return NULL;

    /* Enter supplied properties. */
    z->blocksize = blocksize;
    z->blocks = nblocks;

    // For every byte above the 4th, we get a bit of 'a'
    // see fcopy_hashes()
    z->rsum_a_mask = 0;
    for (int i = 4; i < rsum_bytes; ++i) {
        z->rsum_a_mask <<= 8;
        z->rsum_a_mask |= 0xFF;
    }
    z->rsum_bits = rsum_bytes * 8;
    z->checksum_bytes = checksum_bytes;
    z->lid_offset = 0;

    z->context = blocksize;

    /* Temporary file to hold the target file as we get blocks for it */
    z->filename = strdup("rcksum-XXXXXX");

    /* Initialise to 0 various state & stats */
    z->gotblocks = 0;
    memset(&(z->stats), 0, sizeof(z->stats));
    z->ranges = NULL;
    z->numranges = 0;

    /* Hashes for looking up checksums are generated when needed.
     * So initially store NULL so we know there's nothing there yet.
     */
    z->rsum_hash = NULL;
    z->bithash = NULL;

    if (!(z->blocksize & (z->blocksize - 1)) && z->filename != NULL
            && z->blocks) {
        /* Create temporary file */
        z->fd = mkstemp(z->filename);
        if (z->fd == -1) {
            perror("open");
        }
        else {
            {   /* Calculate bit-shift for blocksize */
                int i;
                for (i = 0; i < 32; i++)
                    if (z->blocksize == (1u << i)) {
                        z->blockshift = i;
                        break;
                    }
            }

            z->blockhashes =
                malloc(sizeof(z->blockhashes[0]) * (z->blocks + 1));
            if (z->blockhashes != NULL)
                return z;

            /* All below is error handling */
        }
    }
    free(z->filename);
    free(z);
    return NULL;
}

/* rcksum_filename(self)
 * Returns temporary filename to caller as malloced string.
 * Ownership of the file passes to the caller - the function returns NULL if
 * called again, and it is up to the caller to deal with the file. */
char *rcksum_filename(struct rcksum_state *rs, char* next) {
    char *p = rs->filename;
    rs->filename = strdup(next);
    return p;
}

/* rcksum_filehandle(self)
 * Returns the filehandle for the temporary file.
 * Ownership of the handle passes to the caller - the function returns -1 if
 * called again, and it is up to the caller to close it. */
int rcksum_filehandle(struct rcksum_state *rs) {
    int h = rs->fd;
    rs->fd = -1;
    return h;
}

int rcksum_fileopen(struct rcksum_state *rs) {
    rs->fd = open(rs->filename, O_RDWR | O_CREAT, 0666);
    return 0;
}

/* rcksum_end - destructor */
void rcksum_end(struct rcksum_state *z) {
    /* Free temporary file resources */
    if (z->fd != -1)
        close(z->fd);
    if (z->filename) {
        if (strncmp(z->filename, "rcksum-", 7) == 0)
            unlink(z->filename);
        free(z->filename);
        z->filename = NULL;
    }

    /* Free other allocated memory */
    free(z->rsum_hash);
    free(z->blockhashes);
    free(z->bithash);
    free(z->ranges);            // Should be NULL already
#ifdef DEBUG
    fprintf(stderr, "hashhit %lld, weakhit %d, checksummed %d, stronghit %d\n",
            z->stats.hashhit, z->stats.weakhit, z->stats.checksummed,
            z->stats.stronghit);
#endif
    free(z);
}
