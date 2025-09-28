/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-locks.h
 * Locking system for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#ifndef DAV_NEXT_LOCKS_H
#define DAV_NEXT_LOCKS_H

uint32_t dav_next_if(ngx_http_request_t *r, ngx_str_t *uri);
ngx_int_t dav_next_lock_handler(ngx_http_request_t *r);
ngx_int_t dav_next_unlock_handler(ngx_http_request_t *r);
ngx_int_t dav_next_lock_response(ngx_http_request_t *r, ngx_uint_t status, time_t timeout, ngx_uint_t depth, uint32_t token);
uint32_t dav_next_lock_token(ngx_http_request_t *r);
ngx_int_t dav_next_set_locks(ngx_http_request_t *r, dav_next_entry_t *entry);
uintptr_t dav_next_format_token(u_char *dst, uint32_t token, ngx_uint_t brackets);
uintptr_t dav_next_format_lockdiscovery(ngx_http_request_t *r, u_char *dst, dav_next_entry_t *entry);
ngx_int_t dav_next_verify_lock(ngx_http_request_t *r, ngx_str_t *uri, ngx_uint_t delete_lock);
dav_next_node_t *dav_next_lock_lookup(ngx_http_request_t *r, dav_next_lock_t *lock, ngx_str_t *uri, ngx_int_t depth);

#endif // DAV_NEXT_LOCKS_H/
