/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2010-2011, Eduardo Silva P. <edsiper@gmail.com>
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

/* Common  */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

/* Networking - I/O*/
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "sha1.h"
#include "base64.h"
#include "request.h"
#include "websocket.h"
#include "webservice.h"
#include "MKPlugin.h"

int ws_handler(int socket, struct client_session *cs, struct session_request *sr,
               struct plugin *plugin)
{
    int len;
    size_t out_len;
    char buffer[256];
    char accept_token[256];
    mk_pointer row;
    mk_pointer ws_key;
    struct mk_ws_request *wr_node;
    unsigned char digest[SHA1_DIGEST_LEN];
    unsigned char *encoded_accept = NULL;
    SHA_CTX sha; /* defined in sha1/sha1.h */

    wr_node = mk_ws_request_get(socket);

    if (!wr_node) {
        /* Validate if it's a WebSockets upgrade request */
        if (strncasecmp(sr->connection.data,
                        WS_CONN_UPGRADE, sizeof(WS_CONN_UPGRADE) - 1) != 0) {
            return MK_WS_ERROR;
        }

        PLUGIN_TRACE("[FD %i] WebSockets Connection Upgrade", cs->socket);

        /* Get upgrade type */
        row = monkey->header_get(&sr->headers_toc, WS_HEADER_UPGRADE,
                                 sizeof(WS_HEADER_UPGRADE) - 1);

        if (strncasecmp(row.data, WS_UPGRADE_WS, sizeof(WS_UPGRADE_WS) - 1) != 0) {
            return MK_WS_ERROR;
        }

        PLUGIN_TRACE("[FD %i] WebSockets Upgrade to 'websocket'", cs->socket);

        /* Validate Sec-WebSocket-Key */
        ws_key = monkey->header_get(&sr->headers_toc, WS_HEADER_SEC_WS_KEY,
                                    sizeof(WS_HEADER_SEC_WS_KEY) - 1);
        if (ws_key.data == NULL) {
            PLUGIN_TRACE("[FD %i] WebSockets missing key", cs->socket);
            return MK_WS_ERROR;
        }
        
        monkey->event_socket_change_mode(cs->socket, MK_EPOLL_RW, MK_EPOLL_LEVEL_TRIGGERED);

        /* Ok Baby, Handshake time! */
        strncpy(buffer, ws_key.data, ws_key.len);
        buffer[ws_key.len] = '\0';

        /* Websockets GUID */
        strncpy(buffer + ws_key.len, WS_GUID, sizeof(WS_GUID) - 1);
        buffer[ws_key.len + sizeof(WS_GUID) - 1] = '\0'; 

        /* Buffer to sha1() */
        SHA1_Init(&sha);
        SHA1_Update(&sha, buffer, strlen(buffer));
        SHA1_Final(digest, &sha); 

        /* Encode accept key with base64 */
        encoded_accept = base64_encode(digest, SHA1_DIGEST_LEN, &out_len);
        encoded_accept[out_len] = '\0';

        /* Set a custom response status */
        strncpy(buffer, WS_RESP_SWITCHING, sizeof(WS_RESP_SWITCHING) - 1);

        sr->headers.status = MK_CUSTOM_STATUS;
        sr->headers.custom_status.data = buffer;
        sr->headers.custom_status.len  = (sizeof(WS_RESP_SWITCHING) -1);

        /* Monkey core must not handle the Connection header */
        sr->headers.connection = -1;

        /* Set 'Upgrade: websocket' */
        monkey->header_add(sr, WS_RESP_UPGRADE, sizeof(WS_RESP_UPGRADE) - 1);
        
        /* Set 'Connection: upgrade' */
        monkey->header_add(sr, WS_RESP_CONNECTION, sizeof(WS_RESP_CONNECTION) - 1);        

        /* Compose accept token */
        len = sizeof(WS_RESP_WS_ACCEPT) - 1;
        strncpy(accept_token, WS_RESP_WS_ACCEPT, len);
        strncpy(accept_token + len, (char *) encoded_accept, out_len);
        len += out_len - 1;
        accept_token[len] = '\0';
        
        /* Add accept token to response headers */
        monkey->header_add(sr, accept_token, len);

        monkey->header_send(cs->socket, cs, sr);
        monkey->socket_cork_flag(cs->socket, TCP_CORK_OFF);

        /* Free block used by base64_encode() */
        monkey->mem_free(encoded_accept);
        
        /* Register node in main list */
        wr_node = mk_ws_request_create(socket, cs, sr);
        mk_ws_request_add(wr_node);

        /* Register socket with plugin events interface */
        //monkey->event_add(cs->socket, MK_EPOLL_RW, plugin, 
        //                  cs, sr, MK_EPOLL_LEVEL_TRIGGERED);
        return MK_WS_NEW_REQUEST;
    }
    else {
        return MK_WS_ESTABLISHED;
    }
}

int ws_send_data(int sockfd,
                unsigned int fin,
                unsigned int rsv1,
                unsigned int rsv2,
                unsigned int rsv3,
                unsigned int opcode,
                unsigned int frame_mask,
                uint64_t payload_len,
                unsigned char *frame_masking_key,
                unsigned char *payload_data)
{
    unsigned char buf[256];
    unsigned int offset = 0;
    int n;

    memset(buf, 0, sizeof(buf));
    buf[0] |= ((fin << 7) | (rsv1 << 6) | (rsv2 << 5) | (rsv3 << 4) | opcode);

    if (payload_len < 126) {
        buf[1] |= ((frame_mask << 7) | payload_len);
        offset = 2;
    }
    else if (payload_len >= 126 && payload_len <= 0xFFFF) {
        buf[1] |= ((frame_mask << 7) | 126);
        buf[2] = payload_len >> 8;
        buf[3] = payload_len & 0x0F;
        offset = 4;
    }
    else {
        buf[1] |= ((frame_mask << 7) | 127);
        memcpy(buf + 2, &payload_len, 8);
        offset = 10;
    }

    if (frame_mask) {
        memcpy(buf + offset, frame_masking_key, WS_FRAME_MASK_LEN);
        offset += WS_FRAME_MASK_LEN;
    }

    memcpy(buf + offset, payload_data, payload_len);

    n = monkey->socket_send(sockfd, buf, offset + payload_len);
    if (n <= 0) {
        return -1;
    }

    return n;
}

/* _MKP_EVENTs */
uint64_t ws_read_data(int sockfd, unsigned char **data)
{
    int i, n;
    unsigned char *buf;
    unsigned int frame_size = 0;
    unsigned int frame_opcode = 0;
    unsigned int frame_mask = 0;
    unsigned char *frame_payload;
    unsigned char frame_masking_key[WS_FRAME_MASK_LEN];
    uint64_t payload_length = 0;
    unsigned int masking_key_offset = 0;
    struct mk_ws_request *wr;

    buf = monkey->mem_alloc(256);
    memset(buf, '\0', sizeof(buf));

    wr = mk_ws_request_get(sockfd);
    if (!wr){
        PLUGIN_TRACE("[FD %i] this FD is not a WebSocket Frame", sockfd);
        return MK_WS_ERROR;
    }

    /* Read incoming data from Palm socket */
    n = monkey->socket_read(sockfd, buf, 256);
    if (n <= 0) {
        return MK_WS_ERROR;
    }

    frame_size    = n;
    frame_opcode  = buf[0] & 0x0f;
    frame_mask    = CHECK_BIT(buf[1], 7);
    payload_length = buf[1] & 0x7f;

    if (payload_length == 126) {
        payload_length = buf[2] * 256 + buf[3];
        masking_key_offset = 4;
    }
    else if (payload_length == 127) {
        memcpy(&payload_length, buf + 2, 8);
        masking_key_offset = 10;
    }
    else {
        masking_key_offset = 2;
    }

    
#ifdef TRACE
    PLUGIN_TRACE("Frame Headers:");
    (CHECK_BIT(buf[0], 7)) ? printf("FIN  ON\n") : printf("FIN  OFF\n");
    (CHECK_BIT(buf[0], 6)) ? printf("RSV1 ON\n") : printf("RSV1 OFF\n");
    (CHECK_BIT(buf[0], 5)) ? printf("RSV2 ON\n") : printf("RSV2 OFF\n");
    (CHECK_BIT(buf[0], 4)) ? printf("RSV3 ON\n") : printf("RSV3 OFF\n");   

    printf("Op Code\t%i\n", frame_opcode);
    printf("Mask ?\t%i\n", frame_mask);
    printf("Frame Size\t%i\n", frame_size);
    printf("Payload Length\t%i\n", (unsigned int) payload_length);
    printf("Mask Key Offset\t%i\n", (unsigned int) masking_key_offset);
    fflush(stdout);
#endif

    wr->payload_len = payload_length;
    wr->payload = monkey->mem_alloc(256);
    memset(wr->payload, '\0', sizeof(wr->payload));

    if (frame_mask) {
        memcpy(frame_masking_key, buf + masking_key_offset, WS_FRAME_MASK_LEN);

        if (payload_length != (frame_size - (masking_key_offset + WS_FRAME_MASK_LEN))) {
            //mk_err("Invalid frame size: %i", (frame_size - (mask_key_init + WS_FRAME_MASK_LEN)));
            /* FIXME: Send error, frame size does not cover the payload size */
            //return MK_PLUGIN_RET_EVENT_CLOSE;
        }

        /* Unmasking the frame payload */
        frame_payload = buf + masking_key_offset + WS_FRAME_MASK_LEN;
        for (i = 0; i < payload_length; i++) {
            wr->payload[i] = frame_payload[i] ^ frame_masking_key[i & 0x03];
        }
    }
    else {
        // There is no masking key, get to the frame payload
        frame_payload = buf + masking_key_offset;
        memcpy(wr->payload, frame_payload, payload_length);
    }

#ifdef TRACE
    if (frame_opcode == 1) printf("Data:\n\"%s\"\n", wr->payload);
#endif

    *data = wr->payload;

    return payload_length;
}

void ws_end_request(int sockfd)
{
    struct mk_ws_request *wr;

    wr = mk_ws_request_get(sockfd);
    if (!wr){
        PLUGIN_TRACE("[FD %i] this FD is not a WebSocket Frame", sockfd);
        return;
    }

    if (wr->payload_len == 0 || wr->payload == NULL)
        return;

    monkey->mem_free(wr->payload);
    wr->payload_len = 0;

    return;
}

void ws_init(struct duda_api_objects *api, struct mk_list *duda_global_dist)
{
    /* Init request list */
    monkey = api->monkey;
    //duda_global_init(websocket_request_list, mk_ws_request_init);
    //duda_global_init(websocket_request_list, NULL);
    pthread_key_create(&websocket_request_list.key, NULL);                           
    websocket_request_list.callback = mk_ws_request_init;                                            
    mk_list_add(&websocket_request_list._head, duda_global_dist);                  
}
/*
void *ws_thctx_callback()
{
    return mk_ws_request_init();
}*/

int ws_handle_request(struct plugin *plugin, struct client_session *cs, 
                  struct session_request *sr)
{
    return ws_handler(cs->socket, cs, sr, plugin);
}
