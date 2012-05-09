/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdlib.h>

#include "duda_package.h"
#include "websocket.h"

struct duda_api_websocket *get_websocket_api()
{
    struct duda_api_websocket *websocket;

    /* Alloc object */
    websocket = malloc(sizeof(struct duda_api_websocket));

    /* Map API calls */
    websocket->handle_request = ws_handle_request;
    websocket->send_data = ws_send_data;
    websocket->read_data = ws_read_data;
    websocket->end_request = ws_end_request;

    return websocket;
}

duda_package_t *init_duda_package(struct duda_api_objects *api)
{
    ws_init(api);

    duda_package_t *dpkg = malloc(sizeof(duda_package_t));

    dpkg->name = "websocket";
    dpkg->version = "0.1";
    dpkg->api = get_websocket_api();

    return dpkg;
}
