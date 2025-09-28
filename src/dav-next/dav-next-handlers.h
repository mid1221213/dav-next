/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-handlers.h
 * Request handlers for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#ifndef DAV_NEXT_HANDLERS_H
#define DAV_NEXT_HANDLERS_H

ngx_str_t dav_next_in_user_rewrite(ngx_http_request_t *r, dav_next_ctx_t *ctx, ngx_str_t uri);
ngx_int_t dav_next_user_check(ngx_http_request_t *r, ngx_str_t uri, ngx_int_t reset_flag);
ngx_int_t dav_next_location_checker(ngx_http_request_t *r);
ngx_int_t dav_next_location_parser(ngx_http_request_t *r);
ngx_int_t dav_next_preaccess_handler(ngx_http_request_t *r);
ngx_int_t dav_next_access_handler(ngx_http_request_t *r);
ngx_int_t dav_next_precontent_handler(ngx_http_request_t *r);
ngx_int_t dav_next_content_handler(ngx_http_request_t *r);
void dav_next_put_handler(ngx_http_request_t *r);
void dav_next_post_handler(ngx_http_request_t *r);

#endif // DAV_NEXT_HANDLERS_H
