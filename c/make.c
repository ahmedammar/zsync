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

/* Command-line utility to create .zsync files */

#include "zsglobal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <math.h>
#include <time.h>

#include <arpa/inet.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#include "makegz.h"
#include "librcksum/rcksum.h"
#include "libzsync/zmap.h"
#include "libzsync/sha1.h"
#include "libzsync/zsyncfile.h"
#include "zlib/zlib.h"
#include "format_string.h"

/* And settings from the command line */
int verbose = 0;

/* stream_error(function, stream) - Exit with IO-related error message */
void
#ifdef __GNUC__
    __attribute__ ((noreturn))
#endif
stream_error(const char *func, FILE * stream, void *error_context) {
    (void)error_context;
    fprintf(stderr, "%s: %s\n", func, strerror(ferror(stream)));
    exit(2);
}

/* read_sample_and_close(stream, len, buf)
 * Reads len bytes from stream into buffer */
static int read_sample_and_close(FILE * f, size_t l, void *buf) {
    int rc = 0;
    if (fread(buf, 1, l, f) == l)
        rc = 1;
    else if (errno != EBADF)
        perror("read");
    fclose(f);
    return rc;
}

/* str = encode_filename(filename_str)
 * Returns shell-escaped version of a given (filename) string */
static char *encode_filename(const char *fname) {
    char *cmd = malloc(2 + strlen(fname) * 2);
    if (!cmd)
        return NULL;

    {   /* pass through string character by character */
        int i, j;
        for (i = j = 0; fname[i]; i++) {
            if (!isalnum(fname[i]))
                cmd[j++] = '\\';
            cmd[j++] = fname[i];
        }
        cmd[j] = 0;
    }
    return cmd;
}

/* opt_str = guess_gzip_options(filename_str)
 * For the given (gzip) file, try to guess the options that were used with gzip
 * to create it.
 * Returns a malloced string containing the options for gzip, or NULL */
static const char *const try_opts[] =
    { "--best", "", "--rsync", "--rsync --best", NULL };
#define SAMPLE 1024

char *guess_gzip_options(const char *f) {
    char orig[SAMPLE];
    {   /* Read sample of the header of the compressed file */
        FILE *s = fopen(f, "r");
        if (!s) {
            perror("open");
            return NULL;
        }
        if (!read_sample_and_close(s, SAMPLE, orig))
            return NULL;
    }
    {
        int i;
        const char *o;
        char *enc_f = encode_filename(f);
        int has_mtime_fname;

        {
            int has_mtime = zhead_has_mtime(orig);
            int has_fname = zhead_has_fname(orig);

            if (has_mtime && !has_fname) {
                fprintf(stderr, "can't recompress, stream has mtime but no fname\n");
                return NULL;
            }
            else if (has_fname && !has_mtime) {
                fprintf(stderr, "can't recompress, stream has fname but no mtime\n");
                return NULL;
            }
            else {
                has_mtime_fname = has_fname; /* which = has_mtime */
            }
        }

        /* For each likely set of options, try recompressing the content with
         * those options */
        for (i = 0; (o = try_opts[i]) != NULL; i++) {
            FILE *p;
            {   /* Compose command line */
                char cmd[1024];
                snprintf(cmd, sizeof(cmd), "zcat %s | gzip -n %s 2> /dev/null",
                        enc_f, o);

                /* And run it */
                if (verbose)
                    fprintf(stderr, "running %s to determine gzip options\n",
                            cmd);
                p = popen(cmd, "r");
                if (!p) {
                    perror(cmd);
                }
            }

            if (p) {   /* Read the recompressed content */
                char samp[SAMPLE];
                if (!read_sample_and_close(p, SAMPLE, samp)) {
                    ;       /* Read error - just fail this one and let the loop
                             * try another */
                }
                else {
                    /* We have the compressed version with these options.
                     * Compare with the original */
                    const char *a = skip_zhead(orig);
                    const char *b = skip_zhead(samp);
                    if (!memcmp(a, b, 900))
                        break;
                }
            }
        }
        free(enc_f);

        if (!o) {
            return NULL;
        }
        else if (has_mtime_fname) {
            return strdup(o);
        }
        else {  /* Add --no-name to options to return */
            static const char noname[] = { "--no-name" };
            char* opts = malloc(strlen(o)+strlen(noname)+2);
            if (o[0]) {
                strcpy(opts, o);
                strcat(opts, " ");
            }
            else { opts[0] = 0; }
            strcat(opts, noname);
            return opts;
        }
    }
}

/* len = get_len(stream)
 * Returns the length of the file underlying this stream */
off_t get_len(FILE * f) {
    struct stat s;

    if (fstat(fileno(f), &s) == -1)
        return 0;
    return s.st_size;
}


/****************************************************************************
 *
 * Main program
 */
int main(int argc, char **argv) {
    FILE *instream;
    char *fname = NULL, *zfname = NULL;
    char **url = NULL;
    int nurls = 0;
    char **Uurl = NULL;
    int nUurls = 0;
    char *outfname = NULL;
    FILE *fout;
    char *infname = NULL;
    int rsum_len, checksum_len;
    int do_compress = 0;
    int do_recompress = -1;     // -1 means we decide for ourselves
    int do_exact = 0;
    char *gzopts = NULL;
    time_t mtime = -1;
    size_t blocksize = 0;
    int no_look_inside = 0;

    /* Open temporary file */
    FILE *tf = tmpfile();

    {   /* Options parsing */
        int opt;
        while ((opt = getopt(argc, argv, "b:Ceo:f:u:U:vVzZ")) != -1) {
            switch (opt) {
            case 'e':
                do_exact = 1;
                break;
            case 'C':
                do_recompress = 0;
                break;
            case 'o':
                if (outfname) {
                    fprintf(stderr, "specify -o only once\n");
                    exit(2);
                }
                outfname = strdup(optarg);
                break;
            case 'f':
                if (fname) {
                    fprintf(stderr, "specify -f only once\n");
                    exit(2);
                }
                fname = strdup(optarg);
                break;
            case 'b':
                blocksize = atoi(optarg);
                if ((blocksize & (blocksize - 1)) != 0) {
                    fprintf(stderr,
                            "blocksize must be a power of 2 (512, 1024, 2048, ...)\n");
                    exit(2);
                }
                break;
            case 'u':
                url = realloc(url, (nurls + 1) * sizeof *url);
                url[nurls++] = optarg;
                break;
            case 'U':
                Uurl = realloc(Uurl, (nUurls + 1) * sizeof *Uurl);
                Uurl[nUurls++] = optarg;
                break;
            case 'v':
                verbose++;
                break;
            case 'V':
                printf(PACKAGE " v" VERSION " (zsyncmake compiled " __DATE__ " "
                       __TIME__ ")\n" "By Colin Phipps <cph@moria.org.uk>\n"
                       "Published under the Artistic License v2, see the COPYING file for details.\n");
                exit(0);
            case 'z':
                do_compress = 1;
                break;
            case 'Z':
                no_look_inside = 1;
                break;
            }
        }

        /* Open data to create .zsync for - either it's a supplied filename, or stdin */
        if (optind == argc - 1) {
            infname = strdup(argv[optind]);
            instream = fopen(infname, "rb");
            if (!instream) {
                perror("open");
                exit(2);
            }

            {   /* Get mtime if available */
                struct stat st;
                if (fstat(fileno(instream), &st) == 0) {
                    mtime = st.st_mtime;
                }
            }

            /* Use supplied filename as the target filename */
            if (!fname)
                fname = basename(argv[optind]);
        }
        else {
            instream = stdin;
        }
    }

    /* If not user-specified, choose a blocksize based on size of the input file */
    if (!blocksize) {
        blocksize = (get_len(instream) < 100000000) ? 2048 : 4096;
    }

    /* If we've been asked to compress this file, do so and substitute the
     * compressed version for the original */
    if (do_compress) {
        char *newfname = NULL;

        {   /* Try adding .gz to the input filename */
            char *tryfname = infname;
            if (!tryfname) {
                tryfname = fname;
            }
            if (tryfname) {
                newfname = malloc(strlen(tryfname) + 4);
                if (!newfname)
                    exit(1);
                strcpy(newfname, tryfname);
                strcat(newfname, ".gz");
            }
        }

        /* If we still don't know what to call it, default name */
        if (!newfname) {
            newfname = strdup("zsync-target.gz");
            if (!newfname)
                exit(1);
        }

        /* Create optimal compressed version */
        instream = optimal_gzip(instream, newfname, blocksize);
        if (!instream) {
            fprintf(stderr, "failed to compress\n");
            exit(-1);
        }

        /* This replaces the original input stream for creating the .zsync */
        if (infname) {
            free(infname);
            infname = newfname;
        }
        else
            free(newfname);
    }

    zsyncfile_state *state = zsyncfile_init(blocksize);
    state->stream_error = &stream_error;

    /* Read the input file and construct the checksum of the whole file, and
     * the per-block checksums */
    zsyncfile_read_stream_write_blocksums(instream, tf, no_look_inside, state);

    /* Recompression:
     * Where we were given a compressed file (not an uncompressed file that we
     * then compressed), but we nonetheless looked inside and made a .zsync for
     * the uncompressed data, the user may want to actually have the client
     * have the compressed version once the whole operation is done.
     * If so, if possible we want the compressed version that the client gets
     * to exactly match the original; but as the client will have to compress
     * it after completion of zsyncing, it might not be possible to achieve
     * that.
     * So a load of code here to work out whether (the client should)
     * recompress, what options it should use to do so, and to inform the
     * creator of the zsync if we don't think the recompression will work.
     */

    /* The only danger of the client not getting the original file is if we have compressed;
     * in that case we want to recompress iff the compressed version was supplied
     * (i.e. we weren't told to generate it ourselves with -z). */
    if (do_exact) {
        int old_do_recompress = do_recompress;
        do_recompress = (state->zmapentries && !do_compress) ? 2 : 0;
        if (old_do_recompress != -1 && (!old_do_recompress) != (!do_recompress)) {
            fprintf(stderr,
                    "conflicting request for compression and exactness\n");
            exit(2);
        }
    }

    /* We recompress if we were told to, OR if
     *  we were left to make our own decision about recompression
     *  the original was compressed & the zsync is of the uncompressed (i.e. there is a zmap)
     *  AND this compressed original isn't one we made ourselves just for transmission
     */
    if ((do_recompress > 0)
        || (do_recompress == -1 && state->zmapentries && !do_compress))
        gzopts = guess_gzip_options(infname);
    /* We now know whether to recompress - if the above and guess_gzip_options worked */
    if (do_recompress == -1)
        do_recompress = (gzopts != NULL) ? 1 : 0;
    if (do_recompress > 1 && gzopts == NULL) {
        fprintf(stderr, "recompression required, but %s\n",
                state->zmap ?
                "could not determine gzip options to reproduce this archive" :
                "we are not looking into a compressed stream");
        exit(2);
    }

    /* Work out filename for the .zsync */
    if (fname && state->zmapentries) {
        /* Remove any trailing .gz, as it is the uncompressed file being transferred */
        char *p = strrchr(fname, '.');
        if (p) {
            zfname = strdup(fname);
            if (!strcmp(p, ".gz"))
                *p = 0;
            if (!strcmp(p, ".tgz"))
                strcpy(p, ".tar");
        }
    }
    if (!outfname && fname) {
        outfname = malloc(strlen(fname) + 10);
        sprintf(outfname, "%s.zsync", fname);
    }

    /* Open output file */
    if (outfname) {
        fout = fopen(outfname, "wb");
        if (!fout) {
            perror("open");
            exit(2);
        }
        free(outfname);
    }
    else {
        fout = stdout;
    }

    if (nurls == 0 && infname) {
        /* Assume that we are in the public dir, and use relative paths.
         * Look for an uncompressed version and add a URL for that to if appropriate. */
        url = realloc(url, (nurls + 1) * sizeof *url);
        url[nurls++] = infname;
        if (state->zmapentries && fname && !access(fname, R_OK)) {
            Uurl = realloc(Uurl, (nUurls + 1) * sizeof *Uurl);
            Uurl[nUurls++] = fname;
            fprintf(fout, "URL: %s\n", fname);
        }
        fprintf(stderr,
                "No URL given, so I am including a relative URL in the .zsync file - you must keep the file being served and the .zsync in the same public directory. Use -u %s to get this same result without this warning.\n",
                infname);
    }

    zsyncfile_compute_hash_lengths(state->len, state->blocksize, &rsum_len, &checksum_len);

    zsyncfile_write(
        fout, tf,
        rsum_len, checksum_len,
        do_recompress, zfname, gzopts,
        fname, mtime,
        url, nurls,
        Uurl, nUurls,
        state);

    /* And cleanup */
    fclose(tf);
    fclose(fout);
    if (gzopts)
        free(gzopts);
    zsyncfile_finish(&state);

    return 0;
}
