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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monkey.h"
#include "mk_header.h"
#include "mk_memory.h"
#include "mk_request.h"
#include "mk_iov.h"
#include "mk_http_status.h"
#include "mk_config.h"
#include "mk_socket.h"
#include "mk_utils.h"
#include "mk_clock.h"
#include "mk_cache.h"
#include "mk_http.h"
#include "mk_string.h"
#include "mk_macros.h"

static struct header_status_response status_response[] = {

    /*
     * The most used first:
     *
     *  - HTTP/1.1 200 OK
     *  - HTTP/1.1 404 Not Found
     */
    {MK_HTTP_OK,
     MK_RH_HTTP_OK,
     sizeof(MK_RH_HTTP_OK) - 1},
    {MK_CLIENT_NOT_FOUND,
     MK_RH_CLIENT_NOT_FOUND,
     sizeof(MK_RH_CLIENT_NOT_FOUND) -1
    },

    /* Informational */
    {MK_INFO_CONTINUE,
     MK_RH_INFO_CONTINUE,
     sizeof(MK_RH_INFO_CONTINUE) - 1
    },
    {MK_INFO_SWITCH_PROTOCOL,
     MK_RH_INFO_SWITCH_PROTOCOL,
     sizeof(MK_RH_INFO_SWITCH_PROTOCOL) - 1
    },

    /* Successful */
    {MK_HTTP_CREATED,
     MK_RH_HTTP_CREATED,
     sizeof(MK_RH_HTTP_CREATED) - 1},
    {MK_HTTP_ACCEPTED,
     MK_RH_HTTP_ACCEPTED,
     sizeof(MK_RH_HTTP_ACCEPTED) - 1},
    {MK_HTTP_NON_AUTH_INFO,
     MK_RH_HTTP_NON_AUTH_INFO,
     sizeof(MK_RH_HTTP_NON_AUTH_INFO) - 1},
    {MK_HTTP_NOCONTENT,
     MK_RH_HTTP_NOCONTENT,
     sizeof(MK_RH_HTTP_NOCONTENT) - 1},
    {MK_HTTP_RESET,
     MK_RH_HTTP_RESET,
     sizeof(MK_RH_HTTP_RESET) - 1},
    {MK_HTTP_PARTIAL,
     MK_RH_HTTP_PARTIAL,
     sizeof(MK_RH_HTTP_PARTIAL) - 1},

    /* Redirections */
    {MK_REDIR_MULTIPLE,
     MK_RH_REDIR_MULTIPLE,
     sizeof(MK_RH_REDIR_MULTIPLE) - 1
    },
    {MK_REDIR_MOVED,
     MK_RH_REDIR_MOVED,
     sizeof(MK_RH_REDIR_MOVED) - 1
    },
    {MK_REDIR_MOVED_T,
     MK_RH_REDIR_MOVED_T,
     sizeof(MK_RH_REDIR_MOVED_T) - 1
    },
    {MK_REDIR_SEE_OTHER,
     MK_RH_REDIR_SEE_OTHER,
     sizeof(MK_RH_REDIR_SEE_OTHER) - 1
    },
    {MK_NOT_MODIFIED,
     MK_RH_NOT_MODIFIED,
     sizeof(MK_RH_NOT_MODIFIED) - 1
    },
    {MK_REDIR_USE_PROXY,
     MK_RH_REDIR_USE_PROXY,
     sizeof(MK_RH_REDIR_USE_PROXY) - 1
    },

    /* Client side errors */
    {MK_CLIENT_BAD_REQUEST,
     MK_RH_CLIENT_BAD_REQUEST,
     sizeof(MK_RH_CLIENT_BAD_REQUEST) - 1
    },
    {MK_CLIENT_UNAUTH,
     MK_RH_CLIENT_UNAUTH,
     sizeof(MK_RH_CLIENT_UNAUTH) - 1
    },
    {MK_CLIENT_PAYMENT_REQ,
     MK_RH_CLIENT_PAYMENT_REQ,
     sizeof(MK_RH_CLIENT_PAYMENT_REQ) - 1
    },
    {MK_CLIENT_FORBIDDEN,
     MK_RH_CLIENT_FORBIDDEN,
     sizeof(MK_RH_CLIENT_FORBIDDEN) -1
    },
    {MK_CLIENT_METHOD_NOT_ALLOWED,
     MK_RH_CLIENT_METHOD_NOT_ALLOWED,
     sizeof(MK_RH_CLIENT_METHOD_NOT_ALLOWED) - 1
    },
    {MK_CLIENT_NOT_ACCEPTABLE,
     MK_RH_CLIENT_NOT_ACCEPTABLE,
     sizeof(MK_RH_CLIENT_NOT_ACCEPTABLE) - 1
    },
    {MK_CLIENT_PROXY_AUTH,
     MK_RH_CLIENT_PROXY_AUTH,
     sizeof(MK_RH_CLIENT_PROXY_AUTH) - 1
    },
    {MK_CLIENT_REQUEST_TIMEOUT,
     MK_RH_CLIENT_REQUEST_TIMEOUT,
     sizeof(MK_RH_CLIENT_REQUEST_TIMEOUT) - 1
    },
    {MK_CLIENT_CONFLICT,
     MK_RH_CLIENT_CONFLICT,
     sizeof(MK_RH_CLIENT_CONFLICT) - 1
    },
    {MK_CLIENT_GONE,
     MK_RH_CLIENT_GONE,
     sizeof(MK_RH_CLIENT_GONE) - 1
    },
    {MK_CLIENT_LENGTH_REQUIRED,
     MK_RH_CLIENT_LENGTH_REQUIRED,
     sizeof(MK_RH_CLIENT_LENGTH_REQUIRED) - 1
    },
    {MK_CLIENT_PRECOND_FAILED,
     MK_RH_CLIENT_PRECOND_FAILED,
     sizeof(MK_RH_CLIENT_PRECOND_FAILED) - 1
    },
    {MK_CLIENT_REQUEST_ENTITY_TOO_LARGE,
     MK_RH_CLIENT_REQUEST_ENTITY_TOO_LARGE,
     sizeof(MK_RH_CLIENT_REQUEST_ENTITY_TOO_LARGE) - 1
    },
    {MK_CLIENT_REQUEST_URI_TOO_LONG,
     MK_RH_CLIENT_REQUEST_URI_TOO_LONG,
     sizeof(MK_RH_CLIENT_REQUEST_URI_TOO_LONG) - 1
    },
    {MK_CLIENT_UNSUPPORTED_MEDIA,
     MK_RH_CLIENT_UNSUPPORTED_MEDIA,
     sizeof(MK_RH_CLIENT_UNSUPPORTED_MEDIA) - 1
    },

    /* Server side errors */
    {MK_SERVER_INTERNAL_ERROR,
     MK_RH_SERVER_INTERNAL_ERROR,
     sizeof(MK_RH_SERVER_INTERNAL_ERROR) - 1
    },
    {MK_SERVER_NOT_IMPLEMENTED,
     MK_RH_SERVER_NOT_IMPLEMENTED,
     sizeof(MK_RH_SERVER_NOT_IMPLEMENTED) - 1
    },
    {MK_SERVER_BAD_GATEWAY,
     MK_RH_SERVER_BAD_GATEWAY,
     sizeof(MK_RH_SERVER_BAD_GATEWAY) - 1
    },
    {MK_SERVER_SERVICE_UNAV,
     MK_RH_SERVER_SERVICE_UNAV,
     sizeof(MK_RH_SERVER_SERVICE_UNAV) - 1
    },
    {MK_SERVER_GATEWAY_TIMEOUT,
     MK_RH_SERVER_GATEWAY_TIMEOUT,
     sizeof(MK_RH_SERVER_GATEWAY_TIMEOUT) - 1
    },
    {MK_SERVER_HTTP_VERSION_UNSUP,
     MK_RH_SERVER_HTTP_VERSION_UNSUP,
     sizeof(MK_RH_SERVER_HTTP_VERSION_UNSUP)
    }
};

static int status_response_len =
    (sizeof(status_response)/(sizeof(status_response[0])));

int mk_header_iov_add_entry(struct mk_iov *mk_io, mk_pointer data,
                            mk_pointer sep, int free)
{
    return mk_iov_add_entry(mk_io, data.data, data.len, sep, free);
}

struct mk_iov *mk_header_iov_get()
{
    return mk_cache_get(mk_cache_iov_header);
}

void mk_header_iov_free(struct mk_iov *iov)
{
    mk_iov_free_marked(iov);
}

/* Send response headers */
int mk_header_send(int fd, struct client_session *cs,
                   struct session_request *sr)
{
    int i=0, fd_status = 0;
    unsigned long len = 0;
    char *buffer = 0;
    mk_pointer response;
    struct response_headers *sh;
    struct mk_iov *iov;

    sh = &sr->headers;

    iov = mk_header_iov_get();

    /* HTTP Status Code */
    if (sh->status == MK_CUSTOM_STATUS) {
        response.data = sh->custom_status.data;
        response.len = sh->custom_status.len;
    }
    else {
        for (i=0; i < status_response_len; i++) {
            if (status_response[i].status == sh->status) {
                response.data = status_response[i].response;
                response.len  = status_response[i].length;
                break;
            }
        }
    }

    /* Invalid status set */
    mk_bug(i == status_response_len);

    mk_header_iov_add_entry(iov, response, mk_iov_none, MK_IOV_NOT_FREE_BUF);

    if (fd_status < 0) {
        mk_header_iov_free(iov);
        return -1;
    }

    /* Server details */
    mk_iov_add_entry(iov, sr->host_conf->header_host_signature.data,
                     sr->host_conf->header_host_signature.len,
                     mk_iov_crlf, MK_IOV_NOT_FREE_BUF);

    /* Date */
    mk_iov_add_entry(iov,
                     mk_header_short_date.data,
                     mk_header_short_date.len,
                     header_current_time,
                     MK_IOV_NOT_FREE_BUF);

    /* Last-Modified */
    if (sh->last_modified > 0) {
        mk_pointer *lm;
        lm = mk_cache_get(mk_cache_header_lm);
        lm->len = mk_utils_utime2gmt(&lm->data, sh->last_modified);

        mk_iov_add_entry(iov, mk_header_last_modified.data,
                         mk_header_last_modified.len,
                         *lm, MK_IOV_NOT_FREE_BUF);
    }

    /* Connection */
    if (sh->connection == 0) {
        if (mk_http_keepalive_check(fd, cs) == 0) {
            if (sr->connection.len > 0) {
                /* Get cached mk_pointers */
                mk_pointer *ka_format = mk_cache_get(mk_cache_header_ka);
                mk_pointer *ka_header = mk_cache_get(mk_cache_header_ka_max);

                /* Compose header and add entries to iov */
                mk_string_itop(config->max_keep_alive_request - cs->counter_connections, ka_header);
                mk_iov_add_entry(iov, ka_format->data, ka_format->len,
                                 mk_iov_none, MK_IOV_NOT_FREE_BUF);
                mk_iov_add_entry(iov, ka_header->data, ka_header->len,
                                 mk_header_conn_ka, MK_IOV_NOT_FREE_BUF);
            }
        }
        else {
            mk_iov_add_entry(iov,
                             mk_header_conn_close.data,
                             mk_header_conn_close.len,
                             mk_iov_none, MK_IOV_NOT_FREE_BUF);
        }

    }

    /* Location */
    if (sh->location != NULL) {
        mk_iov_add_entry(iov,
                         mk_header_short_location.data,
                         mk_header_short_location.len,
                         mk_iov_none, MK_IOV_NOT_FREE_BUF);

        mk_iov_add_entry(iov,
                         sh->location,
                         strlen(sh->location), mk_iov_crlf, MK_IOV_FREE_BUF);
    }

    /* Content type */
    if (sh->content_type.len > 0) {
        mk_iov_add_entry(iov,
                         mk_header_short_ct.data,
                         mk_header_short_ct.len,
                         sh->content_type, MK_IOV_NOT_FREE_BUF);
    }

    /*
     * Transfer Encoding: the transfer encoding header is just sent when
     * the response has some content defined by the HTTP status response
     */
    if ((sh->status < MK_REDIR_MULTIPLE) || (sh->status > MK_REDIR_USE_PROXY)) {
        switch (sh->transfer_encoding) {
        case MK_HEADER_TE_TYPE_CHUNKED:
            mk_iov_add_entry(iov,
                             mk_header_te_chunked.data,
                             mk_header_te_chunked.len,
                             mk_iov_none, MK_IOV_NOT_FREE_BUF);
            break;
        }
    }

    /* Content-Encoding */
    if (sh->content_encoding.len > 0) {
        mk_iov_add_entry(iov, mk_header_content_encoding.data,
                         mk_header_content_encoding.len,
                         mk_iov_none, MK_IOV_NOT_FREE_BUF);
        mk_iov_add_entry(iov, sh->content_encoding.data,
                         sh->content_encoding.len,
                         mk_iov_none, MK_IOV_NOT_FREE_BUF);
    }

    /* Content-Length */
    if (sh->content_length >= 0) {
        /* Map content length to MK_POINTER */
        mk_pointer *cl;
        cl = mk_cache_get(mk_cache_header_cl);
        mk_string_itop(sh->content_length, cl);

        /* Set headers */
        mk_iov_add_entry(iov, mk_header_content_length.data,
                         mk_header_content_length.len,
                         *cl, MK_IOV_NOT_FREE_BUF);
    }

    if ((sh->content_length != 0 && (sh->ranges[0] >= 0 || sh->ranges[1] >= 0)) &&
        config->resume == MK_TRUE) {
        buffer = 0;

        /* yyy- */
        if (sh->ranges[0] >= 0 && sh->ranges[1] == -1) {
            mk_string_build(&buffer,
                            &len,
                            "%s bytes %d-%d/%d",
                            RH_CONTENT_RANGE,
                            sh->ranges[0],
                            (sh->real_length - 1), sh->real_length);
            mk_iov_add_entry(iov, buffer, len, mk_iov_crlf, MK_IOV_FREE_BUF);
        }

        /* yyy-xxx */
        if (sh->ranges[0] >= 0 && sh->ranges[1] >= 0) {
            mk_string_build(&buffer,
                            &len,
                            "%s bytes %d-%d/%d",
                            RH_CONTENT_RANGE,
                            sh->ranges[0], sh->ranges[1], sh->real_length);

            mk_iov_add_entry(iov, buffer, len, mk_iov_crlf, MK_IOV_FREE_BUF);
        }

        /* -xxx */
        if (sh->ranges[0] == -1 && sh->ranges[1] > 0) {
            mk_string_build(&buffer,
                            &len,
                            "%s bytes %d-%d/%d",
                            RH_CONTENT_RANGE,
                            (sh->real_length - sh->ranges[1]),
                            (sh->real_length - 1), sh->real_length);
            mk_iov_add_entry(iov, buffer, len, mk_iov_crlf, MK_IOV_FREE_BUF);
        }
    }

    mk_socket_set_cork_flag(fd, TCP_CORK_ON);

    if (sh->cgi == SH_NOCGI || sh->breakline == MK_HEADER_BREAKLINE) {
        if (!sr->headers._extra_rows) {
            mk_iov_add_entry(iov, mk_iov_crlf.data, mk_iov_crlf.len,
                             mk_iov_none, MK_IOV_NOT_FREE_BUF);
        }
        else {
            mk_iov_add_entry(sr->headers._extra_rows, mk_iov_crlf.data,
                             mk_iov_crlf.len, mk_iov_none, MK_IOV_NOT_FREE_BUF);
        }
    }

    mk_socket_sendv(fd, iov);
    if (sr->headers._extra_rows) {
        mk_socket_sendv(fd, sr->headers._extra_rows);
        mk_iov_free(sr->headers._extra_rows);
    }

    mk_header_iov_free(iov);
    return 0;
}

char *mk_header_chunked_line(int len)
{
    char *buf;

    buf = mk_mem_malloc_z(10);
    snprintf(buf, 9, "%x%s", len, MK_CRLF);

    return buf;
}

void mk_header_set_http_status(struct session_request *sr, int status)
{
    mk_bug(!sr);
    sr->headers.status = status;

    MK_TRACE("Set HTTP status = %i", status);
}

void mk_header_response_reset(struct response_headers *header)
{
    header->status = 0;
    header->ranges[0] = -1;
    header->ranges[1] = -1;
    header->content_length = -1;
    header->connection = 0;
    header->transfer_encoding = -1;
    header->last_modified = -1;
    header->cgi = SH_NOCGI;
    mk_pointer_reset(&header->content_type);
    mk_pointer_reset(&header->content_encoding);
    header->location = NULL;
    header->_extra_rows = NULL;
}
