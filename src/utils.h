/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-utils.h
 * Utility functions for dav-next
 * © Alexandre Jousset
 */

#ifndef DAV_NEXT_UTILS_H
#define DAV_NEXT_UTILS_H

#include "dav-next.h"

void sanitize_str(u_char *str);
ngx_uint_t hex_digit_value(u_char c);
void hex_decode(ngx_str_t *dst, ngx_str_t *src);
char *dav_next_set_complex_value(ngx_conf_t *cf, ngx_http_complex_value_t **where, ngx_str_t *value, ngx_int_t conf_prefix);
ngx_int_t dav_next_send_header(ngx_http_request_t *r);
ngx_int_t dav_next_strip_uri(ngx_http_request_t *r, ngx_str_t *uri);
ngx_int_t dav_next_error(ngx_log_t *log, ngx_err_t err, ngx_int_t not_found, char *failed, u_char *path);
time_t dav_next_get_mtime(ngx_http_request_t *r);
ngx_int_t dav_next_location(ngx_http_request_t *r);
ngx_int_t dav_next_nc_location(ngx_http_request_t *r, ngx_str_t *buf);
ngx_int_t dav_next_fs_get_quota(u_char *name, off_t *used, off_t *avail);
ngx_int_t dav_next_set_file_time(u_char *name, uint64_t ns);
ngx_int_t dav_next_update_etags(ngx_http_request_t *r, ngx_str_t *path, size_t root, uint64_t mtime);
ngx_int_t dav_next_depth(ngx_http_request_t *r, ngx_int_t dflt);
ngx_int_t dav_next_webdav_rewrite(ngx_http_request_t *r, dav_next_ctx_t *ctx);
char *parse_conf_block(ngx_conf_t *cf, ngx_conf_handler_pt handler, void *conf);
ngx_int_t dav_next_read_token(ngx_conf_t *cf);

#endif // DAV_NEXT_UTILS_H
