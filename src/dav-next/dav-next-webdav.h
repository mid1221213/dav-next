/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-webdav.h
 * WebDAV protocol implementation for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#ifndef DAV_NEXT_WEBDAV_H
#define DAV_NEXT_WEBDAV_H

ngx_int_t dav_next_propfind(ngx_http_request_t *r, ngx_uint_t props);
ngx_int_t dav_next_propfind_response(ngx_http_request_t *r, ngx_array_t *entries, ngx_uint_t props);
uintptr_t dav_next_format_propfind(ngx_http_request_t *r, u_char *dst, dav_next_entry_t *entry, ngx_uint_t props);
ngx_int_t dav_next_webdav_rewrite(ngx_http_request_t *r, dav_next_ctx_t *ctx);
void dav_next_propfind_handler(ngx_http_request_t *r);
void dav_next_propfind_xml_start(void *data, const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri, int nb_namespaces, const xmlChar **namespaces, int nb_attributes, int nb_defaulted, const xmlChar **attributes);
void dav_next_propfind_xml_end(void *data, const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri);

#endif // DAV_NEXT_WEBDAV_H
