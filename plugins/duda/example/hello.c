/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "webservice.h"
#include "../packages/json/json.h"
#include "../packages/sha1/sha1.h"
#include "../packages/websocket/websocket.h"

#define INCORRECT_PARAMETERS "Incorrect Parameters\n"
#define FORMATTED_OUT "==Formatted JSON output==\n"
#define UNFORMATTED_OUT "\n\n==Unformatted JSON output==\n"

/* Allowed parameter values */
#define CREATE "create"
#define PARSE "parse"
#define FORMATTED "formatted"
#define UNFORMATTED "unformatted"

DUDA_REGISTER("Service Example", "service");

duda_global_t my_data_mem;
duda_global_t my_data_empty;

/*
 *
 * URI Map example
 * +--------------------------------------------------------------+
 * |  Interface         Method     Param Name  Param Max Length   |
 * +--------------------------------------------------------------+
 * |  examples         hello_world                   0            |
 * +--------------------------------------------------------------+
 * |                   sendfile                      0            |
 * +--------------------------------------------------------------+
 * |                   json_first                    0            |
 * +--------------------------------------------------------------+
 * |                   json_second     action        6            |
 * |                               (create/parse)                 |
 * |                                   format        11           |
 * |                          (formatted/unformatted)             |
 * +--------------------------------------------------------------+
 * |                   sha1_test                     0            |
 * +--------------------------------------------------------------+
 *
 */

void cb_end(duda_request_t *dr)
{
    msg->info("my end callback");
}

void cb_hello_world(duda_request_t *dr)
{
    msg->warn("my global key: %p", global->get(my_data_mem));

    response->http_status(dr, 200);
    response->http_header(dr, "Content-Type: text/plain", 24);

    response->body_write(dr, "hello world!\n", 13);
    response->end(dr, cb_end);
}

void cb_sendfile(duda_request_t *dr)
{
    response->http_status(dr, 200);
    response->http_header(dr, "Content-Type: text/plain", 24);

    response->sendfile(dr, "/etc/issue");
    response->sendfile(dr, "/etc/motd");
    response->end(dr, cb_end);

}

void cb_sha1_test(duda_request_t *dr)
{
    char toEncode[] = "hello world!";
    unsigned int length = strlen(toEncode);
    unsigned char encoded[SHA_DIGEST_LENGTH];
    sha1->encode(toEncode, encoded, length);

    response->http_status(dr, 200);
    response->http_header(dr, "Content-Type: text/html;charset=UTF-8", 37);
    response->body_write(dr, "Raw: hello world!<br>Encoded: ", 30);
    response->body_write(dr, (char *)encoded, SHA_DIGEST_LENGTH);
    response->end(dr, cb_end);
}

void cb_websocket_test(duda_request_t *dr)
{
    int ret;
    unsigned char *data;
    uint64_t data_len;
    
    ret = websocket->handle_request(NULL, dr->cs, dr->sr);
    if (ret == MK_WS_NEW_REQUEST) {
        return;
    } else if (ret == MK_WS_ERROR) {
        return;
    }

    data_len = websocket->read_data(dr->cs->socket, &data);
    if (data_len == MK_WS_ERROR) {
        return;
    }

    /*Just echo it*/
    ret = websocket->send_data(dr->cs->socket, 1, 0, 0, 0, WS_FRAME_TEXT, 
            0, data_len, NULL, data);

    websocket->end_request(dr->cs->socket);
}

void cb_json_first(duda_request_t *dr)
{
    char *resp;
    const char strparse[]= " {                   \
        \"name\":   \"Michel Perez\",            \
        \"age\":    22,                          \
        \"address\":      {                      \
             \"streetAddress\": \"Piso 15\",     \
             \"city\": \"Valparaiso\",           \
             \"country\": \"Chile\"              \
         },                                      \
        \"phoneNumber\":    [                    \
             {                                   \
              \"type\": \"work\",                \
              \"number\": \"2 666 4567\"         \
             },                                  \
             {                                   \
             \"type\": \"fax\",                  \
             \"number\": null                    \
             }                                   \
         ]                                       \
        }";
    json_t *jroot,*jaddress,*jphone,*jphone1,*jphone2,*jparse;

    response->http_status(dr, 200);
    response->http_header(dr, "Content-Type: text/plain", 24);

    jroot = json->create_object();
    json->add_to_object(jroot, "name", json->create_string("Michel Perez"));
    json->add_to_object(jroot, "age", json->create_number(22.0));

    jaddress = json->create_object();
    json->add_to_object(jaddress, "streetAddress", json->create_string("Piso 15"));
    json->add_to_object(jaddress, "city", json->create_string("Valparaiso"));
    json->add_to_object(jaddress, "country", json->create_string("Chile"));
    json->add_to_object(jroot, "address", jaddress);

    jphone = json->create_array();
    jphone1 = json->create_object();
    json->add_to_object(jphone1, "type", json->create_string("work"));
    json->add_to_object(jphone1, "number", json->create_string("2 666 4567"));
    jphone2 = json->create_object();
    json->add_to_object(jphone2, "type", json->create_string("fax"));
    json->add_to_object(jphone2, "number", json->create_null());
    json->add_to_array(jphone, jphone1);
    json->add_to_array(jphone, jphone2);
    json->add_to_object(jroot, "phoneNumber", jphone);

    response->body_write(dr, FORMATTED_OUT, sizeof(FORMATTED_OUT) - 1);
    resp = json->print(jroot);
    response->body_write(dr, resp, strlen(resp));

    resp = NULL;
    jparse = json->parse(strparse);
    response->body_write(dr, UNFORMATTED_OUT, sizeof(UNFORMATTED_OUT) - 1);
    resp = json->print_unformatted(jparse);
    json->delete(jparse);
    response->body_write(dr, resp, strlen(resp));

    response->end(dr, cb_end);
}

void cb_json_second(duda_request_t *dr){
    char *resp,*pvalue1="",*pvalue2="";
    short int pnumber;
    const char strparse[]= " {                   \
        \"name\":   \"Michel Perez\",            \
        \"age\":    22,                          \
        \"address\":      {                      \
             \"streetAddress\": \"Piso 15\",     \
             \"city\": \"Valparaiso\",           \
             \"country\": \"Chile\"              \
         },                                      \
        \"phoneNumber\":    [                    \
             {                                   \
              \"type\": \"work\",                \
              \"number\": \"2 666 4567\"         \
             },                                  \
             {                                   \
             \"type\": \"fax\",                  \
             \"number\": null                    \
             }                                   \
         ]                                       \
        }";
    json_t *jroot,*jaddress,*jphone,*jphone1,*jphone2,*jparse;

    response->http_status(dr, 200);
    response->http_header(dr, "Content-Type: text/plain", 24);

    pnumber = 0;
    pvalue1 = param->get(dr, pnumber);
    pnumber = 1;
    pvalue2 = param->get(dr, pnumber);

    if(!pvalue1 || !pvalue2) {
        response->body_write(dr, INCORRECT_PARAMETERS, sizeof(INCORRECT_PARAMETERS) - 1);
    }else if(strncmp(pvalue1, CREATE, sizeof(CREATE) - 1) == 0 && (sizeof(CREATE) - 1) == strlen(pvalue1)) {
        jroot = json->create_object();
        json->add_to_object(jroot, "name", json->create_string("Michel Perez"));
        json->add_to_object(jroot, "age", json->create_number(22.0));

        jaddress = json->create_object();
        json->add_to_object(jaddress, "streetAddress", json->create_string("Piso 15"));
        json->add_to_object(jaddress, "city", json->create_string("Valparaiso"));
        json->add_to_object(jaddress, "country", json->create_string("Chile"));
        json->add_to_object(jroot, "address", jaddress);

        jphone = json->create_array();
        jphone1 = json->create_object();
        json->add_to_object(jphone1, "type", json->create_string("work"));
        json->add_to_object(jphone1, "number", json->create_string("2 666 4567"));
        jphone2 = json->create_object();
        json->add_to_object(jphone2, "type", json->create_string("fax"));
        json->add_to_object(jphone2, "number", json->create_null());
        json->add_to_array(jphone, jphone1);
        json->add_to_array(jphone, jphone2);
        json->add_to_object(jroot, "phoneNumber", jphone);

        if(strncmp(pvalue2, FORMATTED, sizeof(FORMATTED) - 1) == 0 && (sizeof(FORMATTED) - 1) == strlen(pvalue2)) {
            resp = json->print(jroot);
            response->body_write(dr, resp, strlen(resp));
        }else if(strncmp(pvalue2, UNFORMATTED, sizeof(UNFORMATTED) - 1) == 0 && (sizeof(UNFORMATTED) - 1) == strlen(pvalue2)) {
            resp = json->print_unformatted(jroot);
            response->body_write(dr, resp, strlen(resp));
        }else  {
            response->body_write(dr, INCORRECT_PARAMETERS, sizeof(INCORRECT_PARAMETERS) - 1);
        }
    }else if(strncmp(pvalue1, PARSE, sizeof(PARSE) - 1) == 0 && (sizeof(PARSE) - 1) == strlen(pvalue1)) {
        jparse = json->parse(strparse);
        if(strncmp(pvalue2, FORMATTED, sizeof(FORMATTED) - 1) == 0 && (sizeof(FORMATTED) - 1) == strlen(pvalue2)) {
            resp = json->print(jparse);
            response->body_write(dr, resp, strlen(resp));
        }else if(strncmp(pvalue2, UNFORMATTED, sizeof(UNFORMATTED) - 1) == 0 && (sizeof(UNFORMATTED) - 1) == strlen(pvalue2)) {
            resp = json->print_unformatted(jparse);
            response->body_write(dr, resp, strlen(resp));
        }else {
            response->body_write(dr, INCORRECT_PARAMETERS, sizeof(INCORRECT_PARAMETERS) - 1);
        }
        json->delete(jparse);
    }else {
        response->body_write(dr, INCORRECT_PARAMETERS, sizeof(INCORRECT_PARAMETERS) - 1);
    }
        response->end(dr, cb_end);
}

void *cb_global_mem()
{
    void *mem = malloc(16);
    return mem;
}

int duda_init(struct duda_api_objects *api)
{
    duda_interface_t *if_system;
    duda_method_t    *method;
    duda_param_t *param;

    duda_service_init();

    session->init();

    duda_load_package(json, "json", api);
    duda_load_package(sha1, "sha1", api);
    duda_load_package(websocket, "websocket", api);

    /* An empty global variable */
    duda_global_init(my_data_empty, NULL);

    /* A global variable with the value returned by the callback */
    duda_global_init(my_data_mem, cb_global_mem);

    /* archive interface */
    if_system = map->interface_new("examples");

    /* URI: /hello/examples/hello_world */
    method = map->method_new("hello_world", "cb_hello_world", 0);
    map->interface_add_method(method, if_system);

    /* URI: /hello/examples/sha1_test */
    method = map->method_new("sha1_test", "cb_sha1_test", 0);
    map->interface_add_method(method, if_system);

    /* URI: /hello/examples/json_first */
    method = map->method_new("json_first", "cb_json_first", 0);
    map->interface_add_method(method, if_system);

    /* URI: /hello/examples/websocket_test */
    method = map->method_new("websocket_test", "cb_websocket_test", 0);
    map->interface_add_method(method, if_system);
    websocket->init(api, &_duda_global_dist);

    /* URI: /hello/examples/json_second/<action>/<format>
     * action: create/parse
     * format: formatted/unformatted
     */
    method = map->method_new("json_second", "cb_json_second", 2);
    param = map->param_new("action", strlen("create"));
    map->method_add_param(param, method);
    param = map->param_new("format", strlen("unformatted"));
    map->method_add_param(param, method);
    map->interface_add_method(method, if_system);

    /* URI: /hello/examples/sendfile */
    method = map->method_new("sendfile", "cb_sendfile", 0);
    map->interface_add_method(method, if_system);

    /* Add interface to map */
    duda_service_add_interface(if_system);

    if_system = map->interface_new("test");
    duda_service_add_interface(if_system);

    duda_service_ready();
}
