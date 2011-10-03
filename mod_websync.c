/** 
 * Copyright 2011 Doug Bridgens (doug.bridgens@soogate.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * mod_websync : a tool to sync files over http.
 * author : doug.bridgens@soogate.com
 * date : 26/09/2011
 * version : 0.1 (very beta)
 *
 * usage : GET http://web2/websync/img/test.gif?f=web1
 *
 * tell web2 to sync (pull) /img/test.gif from the
 * webserver web1, and save it to DOCROOT/img/test.gif
 *
 */ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "ap_config.h"
#include "apr_network_io.h"
#include "apr_file_io.h"
#include "apr_strings.h"

#define MODULE_VERSION "mod_websync 0.1-beta"
#define DEFAULT_HTTP_PORT 80
#define NET_BUFSIZE 4096

static int websync_handler(request_rec *r)
{
    apr_socket_t *sock = NULL;
    apr_sockaddr_t *sa = NULL;
    apr_status_t rv;
    char errorbuf[120];

    char *urip, *hostp;

    /* some sanitation checks */
    if (strcmp(r->handler, "websync")) {
        return DECLINED;
    }
    if (M_GET != r->method_number) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    /* move the urip past the first portion of the uri, to the start of
     * the file path to sync
     *
     * http://web1/websync/img/test.gif
     *       urip ^
     *
     * http://web1/websync/img/test.gif
     *               urip ^
     */
    urip = r->uri;
    if ('/' != *urip)
        return HTTP_INTERNAL_SERVER_ERROR;
    do {
        ++urip;
    } while ('/' != *urip && '\0' != *urip);

    /* ensure we have f= args */
    if (NULL == r->args)
        return HTTP_INTERNAL_SERVER_ERROR;

    /* move hostp to the beginning of the hostname */
    /* TODO: clean this up */
    hostp = r->args;
    if ('f' != *hostp && '=' != *(hostp+1))
        return HTTP_INTERNAL_SERVER_ERROR;
    hostp += 2;

    /* if we detect the X-Requestor: header then don't continue incase of recursive loop */
    const char *x_requestor = NULL;
    x_requestor = apr_table_get(r->headers_in, "X-Requestor");
    if (NULL != x_requestor)
        return HTTP_INTERNAL_SERVER_ERROR;

    /* some temporary debug info */
    r->content_type = "text/html";      
    ap_rprintf(r, "the uri is %s<br>", r->uri);
    ap_rprintf(r, "the args %s<br>", r->args);
    ap_rprintf(r, "the file is %s<br>", urip);
    ap_rprintf(r, "calling GET : http://%s%s<br>", hostp, urip);
    ap_rprintf(r, "document root: %s<br>", ap_document_root(r));

    /**
     * now create the return request and download the file
     *
     * Note, HTTP 1.1 must send Host: header
     */

    const char *req_hdr = apr_pstrcat(r->pool, 
                                      "GET ", urip, " ", "HTTP/1.1\r\n",
                                      "Host: ", hostp, "\r\n",
                                      "X-Requested-With: ", MODULE_VERSION, "\r\n",
                                      "\r\n",
                                      NULL);

    apr_size_t len = strlen(req_hdr);

    rv = apr_sockaddr_info_get(&sa, hostp, APR_INET, DEFAULT_HTTP_PORT, 0, r->pool);
    if (APR_SUCCESS != rv)
        return HTTP_INTERNAL_SERVER_ERROR;

    rv = apr_socket_create(&sock, APR_INET, SOCK_STREAM, APR_PROTO_TCP, r->pool);
    if (APR_SUCCESS != rv)
        return rv;

    rv = apr_socket_connect(sock, sa);
    if (rv != APR_SUCCESS)
        return HTTP_INTERNAL_SERVER_ERROR;

    rv = apr_socket_send(sock, req_hdr, &len);
    if (APR_SUCCESS != rv)
        return HTTP_INTERNAL_SERVER_ERROR;

    apr_file_t *fp;
    const char *filepath = apr_pstrcat(r->pool, ap_document_root(r), urip, NULL);

    ap_rprintf(r, "filepath %s<br>", filepath);

    rv = apr_file_open(&fp,
                       filepath,
                       APR_FOPEN_TRUNCATE | 
                       APR_FOPEN_WRITE |
                       APR_FOPEN_CREATE, 
                       APR_OS_DEFAULT, 
                       r->pool);

    if (APR_SUCCESS != rv) {
        /* TODO: attempt to create the parent dir if it's missing */
        ap_rprintf(r, "the file result %d : %s<br>", rv, (apr_strerror(rv, errorbuf, sizeof(errorbuf))));
    }
    else {

        char buf[NET_BUFSIZE];
        apr_size_t len = sizeof(buf);

        while (1) {

            rv = apr_socket_recv(sock, buf, &len);
            if (APR_EOF == rv || 0 == len)
                break;
            
            char *bufp = buf;
            int found = 0;

            /* skip the http headers ending at \r\n\r\n, TODO: find a more elegant method */
            while (!found) {
                if (*bufp == 13 && *(bufp+1) == 10 && *(bufp+2) == 13 && *(bufp+3) == 10)
                    ++found;

                ++bufp;
            }
            bufp += 3; /* adjust */
            apr_file_write(fp, bufp, &len);
        }

        apr_file_close(fp);
    }

    apr_socket_close(sock);

    return OK;
}

static void websync_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(websync_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA websync_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    websync_register_hooks  /* register hooks                      */
};

