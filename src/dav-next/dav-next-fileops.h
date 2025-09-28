/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-fileops.h
 * File operations for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#ifndef DAV_NEXT_FILEOPS_H
#define DAV_NEXT_FILEOPS_H

ngx_int_t dav_next_delete_path(ngx_http_request_t *r, ngx_str_t *path, ngx_uint_t dir);
ngx_int_t dav_next_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
ngx_int_t dav_next_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
ngx_int_t dav_next_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path);
ngx_int_t dav_next_append_file(ngx_http_request_t *r, u_char *from, u_char *to, ngx_uint_t first);
int ngx_libc_cdecl dav_next_cmp_chunk_entries(const void *one, const void *two);
ngx_int_t dav_next_copy_move_handler(ngx_http_request_t *r, dav_next_loc_conf_t *dlcf);
ngx_int_t dav_next_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
ngx_int_t dav_next_copy_dir_time(ngx_tree_ctx_t *ctx, ngx_str_t *path);
ngx_int_t dav_next_copy_tree_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);

#endif // DAV_NEXT_FILEOPS_H
