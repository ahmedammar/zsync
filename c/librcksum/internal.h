
/*
 *   rcksum/lib - library for using the rsync algorithm to determine
 *               which parts of a file you have and which you need.
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

#include <stdint.h>

/* Internal data structures to the library. Not to be included by code outside librcksum. */

/* Two types of checksum -
 * rsum: rolling Adler-style checksum
 * checksum: hopefully-collision-resistant MD4 checksum of the block
 */

struct hash_entry {
    struct hash_entry *next;    /* next entry with the same rsum */
    struct rsum r;
    unsigned char checksum[CHECKSUM_SIZE];
};

typedef uint32_t rsum_component_type;

/* An rcksum_state contains the set of checksums of the blocks of a target
 * file, and is used to apply the rsync algorithm to detect data in common with
 * a local file. It essentially contains as rsum and a checksum per block of
 * the target file, plus various hash tables to speed up lookups when looping
 * over data looking for matching blocks. */

struct rcksum_state {
    struct rsum r;              /* Current rsum */

    zs_blockid blocks;          /* Number of blocks in the target file */
    size_t blocksize;           /* And how many bytes per block */
    int blockshift;             /* log2(blocksize) */
    rsum_component_type rsum_a_mask; /* The mask to apply to rsum values before looking up */
    unsigned short rsum_bits;   /* # of bits of rsum data in the .zsync for each block */
    unsigned short hash_func_shift; /* Config for the hash function */
    unsigned int checksum_bytes; /* How many bytes of the MD4 checksum are available */
    unsigned int context;       /* precalculated blocksize */

    /* These are used by the library. Note, not thread safe. */
    int skip;                   /* skip forward on next submit_source_data */
    const struct hash_entry *rover;

    /* Internal; hint to rcksum_submit_source_data that it should try matching
     * the following block of input data against the block ->next_match.
     * next_known is a cached lookup of the id of the next block after that
     * that we already have data for. */
    const struct hash_entry *next_match;
    zs_blockid next_known;

    /* Hash table for rsync algorithm */
    uint64_t hashmask;
    struct hash_entry *blockhashes;
    struct hash_entry **rsum_hash;

    /* And a 1-bit per rsum value table to allow fast negative lookups for hash
     * values that don't occur in the target file. */
    unsigned char *bithash;
    uint64_t bithashmask;

    /* Current state and stats for data collected by algorithm */
    int numranges;
    zs_blockid *ranges;
    int gotblocks;
    struct {
        long long hashhit;
        int weakhit, stronghit, checksummed;
    } stats;

    /* Temp file for output */
    char *filename;
    int fd;

    /* local id offset, used in upload mode to match blocks */
    int lid_offset;
};

#define BITHASHBITS 3

/* rcksum_state methods */

/* From a hash entry, return the corresponding blockid */
static inline zs_blockid get_HE_blockid(const struct rcksum_state *z,
                                        const struct hash_entry *e) {
    return e - z->blockhashes;
}

/* From a file offset return the corresponding local file blockid */
static inline zs_blockid get_L_blockid(struct rcksum_state *const z, off_t offset, int x) {
    int lid = (offset  + x) / z->blocksize;
    return offset ? lid - z->context/z->blocksize : lid;
}

void add_to_ranges(struct rcksum_state *z, zs_blockid n);
int already_got_block(struct rcksum_state *z, zs_blockid n);
zs_blockid next_known_block(struct rcksum_state *rs, zs_blockid x);

struct hash_entry *calc_hash_entry(void *data, size_t len);

/* Hash the checksum values for the given hash entry and return the hash value */
static inline uint64_t calc_rhash(const struct rcksum_state *const z,
                                  const struct rsum *const r) {
    uint64_t h = r->b;
    h ^= (r->a & z->rsum_a_mask) << z->hash_func_shift;
    return h;
}

int build_hash(struct rcksum_state *z);
void remove_block_from_hash(struct rcksum_state *z, zs_blockid id);
