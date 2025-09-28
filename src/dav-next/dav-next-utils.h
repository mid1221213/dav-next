/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-utils.h
 * Utility functions for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#ifndef DAV_NEXT_UTILS_H
#define DAV_NEXT_UTILS_H

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

#endif // DAV_NEXT_UTILS_H
