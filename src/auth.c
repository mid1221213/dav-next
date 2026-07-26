/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-auth.c
 * Authentication provider abstraction for dav-next
 * © Alexandre Jousset
 */

#include "dav-next.h"
#include "auth.h"

ngx_int_t set_header_auth(ngx_http_request_t *r)
{
    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    RETURN_500_IF(r->headers_out.www_authenticate == NULL);

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->next = NULL;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    size_t len = sizeof("Basic realm=\"") - 1;
    r->headers_out.www_authenticate->value.len = len + dlcf->name.len + 1;
    u_char *p = r->headers_out.www_authenticate->value.data = ngx_pnalloc(r->pool, r->headers_out.www_authenticate->value.len);
    p = ngx_cpymem(p, (u_char *) "Basic realm=\"", len);
    p = ngx_cpymem(p, dlcf->name.data, dlcf->name.len);
    *p = '"';

    return NGX_HTTP_UNAUTHORIZED;
}

#pragma GCC visibility push(hidden)

static ngx_array_t *auth_providers = NULL;

ngx_int_t dav_next_auth_register_provider(dav_next_auth_provider_t *provider)
{
    dav_next_auth_provider_t **p = ngx_array_push(auth_providers);
    if (p == NULL) {
        return NGX_ERROR;
    }

    *p = provider;

    return NGX_OK;
}

ngx_int_t dav_next_auth_preinit_providers(ngx_conf_t *cf)
{
    if (auth_providers == NULL) {
        auth_providers = ngx_pcalloc(cf->pool, sizeof(ngx_array_t));
    }

    return ngx_array_init(auth_providers, cf->pool, MAX_PROVIDERS, sizeof(dav_next_auth_provider_t *));
}

ngx_int_t dav_next_auth_init_providers(register_provider_t *register_provider)
{
    *register_provider = dav_next_auth_register_provider;

    return NGX_OK;
}

// find a provider by name
dav_next_auth_provider_t *dav_next_auth_find_provider(ngx_str_t *name)
{
    if (name == NULL || name->len == 0) {
        return NULL;
    }

    dav_next_auth_provider_t **p = auth_providers->elts;

    for (ngx_uint_t i = 0; i < auth_providers->nelts; i++) {
        if (NGX_STR_EQ(&(*p)->name, name)) {
            return *p;
        }
    }

    return NULL;
}

// get identity using the configured provider
//  and fall back to extracting uid from basic auth if no provider is set
dav_next_auth_identity_t *dav_next_auth_get_identity(ngx_http_request_t *r)
{
    dav_next_auth_identity_t *identity = ngx_pcalloc(r->pool, sizeof(dav_next_auth_identity_t));

    if (identity == NULL) {
        return NULL;
    }

    identity->uid.len = 0;
    identity->uid.data = NULL;
    identity->gids = NULL;

    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    // if a provider is configured, use it
    if (dlcf->auth_provider != NULL) {
        if (dlcf->auth_provider->get_identity(r, identity, dlcf->auth_conf) != NGX_OK) {
            return NULL;
        }

        return identity;
    }

    // no provider configured: fallback to basic uid extraction
    if (ngx_http_auth_basic_user(r) != NGX_OK) {
        return NULL;
    }

    identity->uid = r->headers_in.user;
    identity->gids = NULL;

    return identity;
}

// check if identity belongs to a specific group
ngx_int_t dav_next_auth_in_group(dav_next_auth_identity_t *identity, ngx_str_t *gid)
{
    if (identity == NULL || gid == NULL || gid->len == 0) {
        return NGX_DECLINED;
    }

    if (identity->gids == NULL || identity->gids->nelts == 0) {
        return NGX_DECLINED;
    }

    for (size_t i = 0; i < identity->gids->nelts; i++) {
        ngx_str_t *g = (ngx_str_t *) identity->gids->elts + i;

        if (NGX_STR_EQ(g, gid)) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

// log available providers
void dav_next_auth_log_providers(ngx_log_t *log)
{
    dav_next_auth_provider_t *p = auth_providers->elts;
    ngx_uint_t i = 0;

    while (i < auth_providers->nelts) {
        ERROR_A(INFO, log, 0, "  [%ui] %V (capabilities: 0x%02Xd)", i, &p->name, p->capabilities);
        i++; p++;
    }

    ERROR_A(INFO, log, 0, "%ui auth provider(s) available:", i);
}
