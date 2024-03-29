/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE
#include <fcntl.h>

#include <sys/uio.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>

#include "monkey.h"

#include "mk_macros.h"
#include "mk_header.h"
#include "mk_memory.h"
#include "mk_utils.h"
#include "mk_iov.h"

inline int mk_iov_add_entry(struct mk_iov *mk_io, char *buf, int len,
                            mk_pointer sep, int free)
{
    if (buf) {
        mk_io->io[mk_io->iov_idx].iov_base = (unsigned char *) buf;
        mk_io->io[mk_io->iov_idx].iov_len = len;
        mk_io->iov_idx++;
        mk_io->total_len += len;
    }

#ifdef DEBUG_IOV
    if (mk_io->iov_idx > mk_io->size) {
        printf("\nDEBUG IOV :: ERROR, Broken array size in:");
        printf("\n          '''%s'''", buf);
        fflush(stdout);
    }
#endif

    /* Add separator */
    if (sep.len > 0) {
        mk_io->io[mk_io->iov_idx].iov_base = sep.data;
        mk_io->io[mk_io->iov_idx].iov_len = sep.len;
        mk_io->iov_idx++;
        mk_io->total_len += sep.len;
    }

    if (free == MK_IOV_FREE_BUF) {
        _mk_iov_set_free(mk_io, buf);
    }

    mk_bug(mk_io->iov_idx > mk_io->size);

    return mk_io->iov_idx;
}

struct mk_iov *mk_iov_create(int n, int offset)
{
    int i;
    struct mk_iov *iov;

    iov = mk_mem_malloc_z(sizeof(struct mk_iov));
    iov->iov_idx = offset;
    iov->io = mk_mem_malloc(n * sizeof(struct iovec));
    iov->buf_to_free = mk_mem_malloc(n * sizeof(char *));
    iov->buf_idx = 0;
    iov->total_len = 0;
    iov->size = n;

    /*
     * Make sure to set to zero initial entries when an offset
     * is specified
     */
    if (offset > 0) {
        for (i=0; i < offset; i++) {
            iov->io[0].iov_base = NULL;
            iov->io[0].iov_len = 0;
        }
    }

    return iov;
}

int mk_iov_realloc(struct mk_iov *mk_io, int new_size)
{
    int i;
    char **new_buf;
    struct iovec *new_io;

    new_io  = mk_mem_realloc(mk_io->io, sizeof(struct iovec) * new_size) ;
    new_buf = mk_mem_realloc(mk_io->buf_to_free, sizeof(char *) * new_size);

    if (!new_io || !new_buf) {
        MK_TRACE("could not reallocate IOV");
        return -1;
    }

    /* update data */
    mk_io->io = new_io;
    mk_io->buf_to_free = new_buf;

    mk_io->size = new_size;

    for (i=mk_io->iov_idx; i < mk_io->size - 1; i++) {
        mk_io->io[0].iov_base = NULL;
        mk_io->io[0].iov_len = 0;
    }

    return 0;
}

int mk_iov_set_entry(struct mk_iov *mk_io, char *buf, int len,
                     int free, int idx)
{
    mk_io->io[idx].iov_base = buf;
    mk_io->io[idx].iov_len = len;
    mk_io->total_len += len;

    if (free == MK_IOV_FREE_BUF) {
        _mk_iov_set_free(mk_io, buf);
    }

    return 0;
}

void _mk_iov_set_free(struct mk_iov *mk_io, char *buf)
{
    mk_io->buf_to_free[mk_io->buf_idx] = (char *) buf;
    mk_io->buf_idx++;
}

ssize_t mk_iov_send(int fd, struct mk_iov *mk_io)
{
    ssize_t n = writev(fd, mk_io->io, mk_io->iov_idx);
    if( n < 0 ) {
        MK_TRACE( "[FD %i] writev() '%s'", fd, strerror(errno));
        return -1;
    }

    return n;
}

void mk_iov_free(struct mk_iov *mk_io)
{
    mk_iov_free_marked(mk_io);
    mk_mem_free(mk_io->buf_to_free);
    mk_mem_free(mk_io->io);
    mk_mem_free(mk_io);
}

void mk_iov_free_marked(struct mk_iov *mk_io)
{
    int i, limit = 0;

    limit = mk_io->buf_idx;

    for (i = 0; i < limit; i++) {

#ifdef DEBUG_IOV
        printf("\nDEBUG IOV :: going free (idx: %i/%i): %s", i,
               limit, mk_io->buf_to_free[i]);
        fflush(stdout);
#endif
        mk_mem_free(mk_io->buf_to_free[i]);
    }

    mk_io->iov_idx = 0;
    mk_io->buf_idx = 0;
}

void mk_iov_print(struct mk_iov *mk_io)
{
    int i, j;
    char *c;

    for (i = 0; i < mk_io->iov_idx; i++) {
        printf("\n[index=%i len=%i]\n'", i, (int) mk_io->io[i].iov_len);
        fflush(stdout);
        continue;
        for (j=0; j < mk_io->io[i].iov_len; j++) {
            c = mk_io->io[i].iov_base;
            printf("%c", c[j]);
            fflush(stdout);
        }
        printf("'[end=%i]\n", j);
        fflush(stdout);
    }
}

void mk_iov_separators_init()
{
    mk_pointer_set(&mk_iov_crlf, MK_IOV_CRLF);
    mk_pointer_set(&mk_iov_lf, MK_IOV_LF);
    mk_pointer_set(&mk_iov_space, MK_IOV_SPACE);
    mk_pointer_set(&mk_iov_slash, MK_IOV_SLASH);
    mk_pointer_set(&mk_iov_none, MK_IOV_NONE);
    mk_pointer_set(&mk_iov_equal, MK_IOV_EQUAL);
}
