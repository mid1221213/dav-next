/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-auth.h
 * Authentication provider abstraction for dav-next
 * © Alexandre Jousset
 */

#ifndef DAV_NEXT_AUTH_H
#define DAV_NEXT_AUTH_H

#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>

#define MAX_PROVIDERS 5
#define DAV_NEXT_AUTH_CAP_GROUPS 0x01

// authentication identity result
typedef struct {
    ngx_str_t uid;
    ngx_array_t *gids;
} dav_next_auth_identity_t;

typedef struct {
    ngx_str_t name;
    char *(*set)(ngx_conf_t *cf, void *conf);
} dav_next_directive_t;

#define dav_next_null_directive { ngx_null_string, NULL }

// authentication provider interface
typedef struct {
    ngx_str_t name;
    ngx_uint_t capabilities;
    dav_next_directive_t *directives;
    ngx_int_t (*auth)(ngx_http_request_t *r, void *conf);
    ngx_int_t (*get_identity)(ngx_http_request_t *r, dav_next_auth_identity_t *identity, void *conf);
    void *(*prepare_conf)(ngx_conf_t *cf);
    ngx_int_t (*disable)(ngx_http_request_t *r, void *conf);
    ngx_int_t (*enable)(ngx_http_request_t *r, void *conf);
} dav_next_auth_provider_t;

typedef ngx_int_t (*register_provider_t)(dav_next_auth_provider_t *provider);

ngx_int_t dav_next_auth_preinit_providers(ngx_conf_t *cf);
ngx_int_t dav_next_auth_init_providers(register_provider_t *register_provider);
dav_next_auth_provider_t *dav_next_auth_find_provider(ngx_str_t *name);
dav_next_auth_identity_t *dav_next_auth_get_identity(ngx_http_request_t *r);
void dav_next_auth_identity_init(dav_next_auth_identity_t *identity);
void dav_next_auth_log_providers(ngx_log_t *log);
ngx_int_t set_header_auth(ngx_http_request_t *r);

#endif // DAV_NEXT_AUTH_H
