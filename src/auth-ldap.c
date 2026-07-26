/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-auth-ldap.c
 * LDAP authentication provider for dav-next
 * © Alexandre Jousset
 */

#include "dav-next.h"
#include "utils.h"
#include "auth.h"
#include "auth-ldap.h"

#pragma GCC visibility push(hidden)

char *ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
char *servers_directive(ngx_conf_t *cf, void *conf);
char *resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *parse_url(ngx_conf_t *cf, server_url_t *server_url);
char *parse_binddn_passwd(ngx_conf_t *cf, server_t *server);
char *parse_require(ngx_conf_t *cf, server_t *server);
char *parse_satisfy(ngx_conf_t *cf, server_t *server);
char *parse_referral(ngx_conf_t *cf, server_t *server);
void *create_main_conf(ngx_conf_t *cf);
char *init_main_conf(ngx_conf_t *cf, void *parent);
void *create_loc_conf(ngx_conf_t *);
char *merge_loc_conf(ngx_conf_t *, void *, void *);
ngx_int_t init_worker(ngx_cycle_t *cycle);
ngx_int_t init(ngx_conf_t *cf);

ngx_module_t dav_next_auth_ldap_module;

ngx_command_t commands[] = {
    {
        ngx_string("ldap_server"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
        ldap_server_block,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("auth_ldap_cache_enabled"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(main_conf_t, cache_enabled),
        NULL
    },
    {
        ngx_string("auth_ldap_cache_expiration_time"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(main_conf_t, cache_expiration_time),
        NULL
    },
    {
        ngx_string("auth_ldap_cache_size"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(main_conf_t, cache_size),
        NULL
    },
    {
        ngx_string("ldap_resolver"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        resolver,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("ldap_resolver_timeout"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(main_conf_t, resolver_timeout),
        NULL
    },
    ngx_null_command
};


// configuration directives
dav_next_directive_t directives[] = {
    {
        ngx_string("servers"),
        servers_directive,
    },
    dav_next_null_directive
};

// configuration and initialization

// reads ldap_server block and sets ldap_server as a handler of each conf value
char *ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_str_t name = value[1];

    RETURN_CONF_ERROR_IF(name.len == 0, "missing server name in ldap_server", NULL);

    main_conf_t *cnf = conf;
    if (cnf->servers == NULL) {
        cnf->servers = ngx_array_create(cf->pool, MAX_SERVERS_SIZE, sizeof(server_t));
        RETURN_CONF_ERROR_IF(cnf->servers == NULL, "internal error", NULL);
    }

    server_t *server = ngx_array_push(cnf->servers);
    RETURN_CONF_ERROR_IF(server == NULL, "internal error", NULL);

    ngx_memzero(server, sizeof(*server));
    server->connect_timeout = 10000;
    server->reconnect_timeout = 10000;
    server->max_down_retries = 0;
    server->bind_timeout = 5000;
    server->request_timeout = 10000;
    server->alias = name;
    server->referral = 1;
    server->clean_on_timeout = 0;

    char *rv = parse_conf_block(cf, ldap_server, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    RETURN_CONF_ERROR_IF(server->users_url.ludpp == NULL, "missing 'users_url' directive", NULL);

    // "uid" attribute is 1st attribute in "users_url"
    server->user_attribute.data = (u_char *) server->users_url.ludpp->lud_attrs[0];
    RETURN_CONF_ERROR_IF(server->user_attribute.data == NULL, "no user attribute given in 'users_url'", NULL);
    server->user_attribute.len = ngx_strlen(server->user_attribute.data);

    if (server->groups_url.ludpp == NULL) { // no "groups_url" directive present, "gid" is 2nd attribute in "users_url"
        server->group_attribute.data = (u_char *) server->users_url.ludpp->lud_attrs[1];
        if (server->group_attribute.data == NULL) {
            CF_ERROR(WARN, cf, 0, "no group attribute given in 'users_url', ignoring groups");
            server->group_attribute.len = 0;
        } else {
            server->group_attribute.len = ngx_strlen(server->group_attribute.data);
        }
    } else {
        RETURN_CONF_ERROR_IF(ngx_strcmp(server->users_url.ludpp->lud_scheme, server->groups_url.ludpp->lud_scheme) != 0, "'users_url' and 'groups_url' must use the same scheme", NULL);
        RETURN_CONF_ERROR_IF(ngx_strcmp(server->users_url.ludpp->lud_host,   server->groups_url.ludpp->lud_host  ) != 0, "'users_url' and 'groups_url' must use the same host",   NULL);

        // "groups_url" directive is present, "gid" is 1st attribute in "groups_url"
        server->group_attribute.data = (u_char *) server->groups_url.ludpp->lud_attrs[0];
        RETURN_CONF_ERROR_IF(server->group_attribute.data == NULL, "no group attribute given in 'groups_url'", NULL);
        server->group_attribute.len = ngx_strlen(server->group_attribute.data);
    }

    return NGX_CONF_OK;
}

#define CONF_MSEC_VALUE(value, server, x)                               \
    if (has_arg && NGX_STR_CST_EQ(&value[0], #x)) {                     \
        ngx_msec_t _i = ngx_parse_time(&value[1], 0);                   \
        RETURN_CONF_ERROR_IF(_i == (ngx_msec_t) NGX_ERROR || _i == 0, #x "' value has to be a valid time unit greater than 0 ('%V')", &value[1]); \
        server->x = _i;                                                 \
    }

// called for every variable inside ldap_server block
char *ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    main_conf_t *cnf = conf;

    // it should be safe to just use latest server from array
    server_t *server = ((server_t *) cnf->servers->elts + (cnf->servers->nelts - 1));
    ngx_str_t *value = cf->args->elts;
    ngx_int_t has_arg = cf->args->nelts == 2;

    // TODO: add more validation
    if (NGX_STR_CST_EQ(&value[0], "users_url")) {
        return parse_url(cf, &server->users_url);
    } else if (NGX_STR_CST_EQ(&value[0], "groups_url")) {
        return parse_url(cf, &server->groups_url);
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "binddn")) {
        server->bind_dn = value[1];
    } else if (NGX_STR_CST_EQ(&value[0], "binddn_passwd")) {
        return parse_binddn_passwd(cf, server);
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "member_attribute")) {
        server->member_attribute = value[1];
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "member_attribute_is_dn") && NGX_STR_CST_EQ(&value[1], "on")) {
        server->member_attribute_dn = 1;
    } else if (NGX_STR_CST_EQ(&value[0], "require")) {
        return parse_require(cf, server);
    } else if (NGX_STR_CST_EQ(&value[0], "satisfy")) {
        return parse_satisfy(cf, server);
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "referral") && NGX_STR_CST_EQ(&value[1], "on")) {
        server->referral = 1;
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "clean_on_timeout") && NGX_STR_CST_EQ(&value[1], "on")) {
        server->clean_on_timeout = 1;
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "max_down_retries")) {
        ngx_int_t val = ngx_atoi(value[1].data, value[1].len);
        RETURN_CONF_ERROR_IF(val == NGX_ERROR || val == 0, "'max_down_retries' value must be an integer ('%V')", &value[1]);
        server->max_down_retries = val;
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "connections")) {
        ngx_int_t val = ngx_atoi(value[1].data, value[1].len);
        RETURN_CONF_ERROR_IF(val == NGX_ERROR || val == 0, "'connections' value has to be a number greater than 0 ('%V')", &value[1]);
        server->connections = val;
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "ssl_check_cert")) {
        if (NGX_STR_CST_EQ(&value[1], "on") || NGX_STR_CST_EQ(&value[1], "full")) {
            server->ssl_check_cert = SSL_CERT_VERIFY_FULL;
        } else if (NGX_STR_CST_EQ(&value[1], "chain")) {
            server->ssl_check_cert = SSL_CERT_VERIFY_CHAIN;
        } else {
            server->ssl_check_cert = SSL_CERT_VERIFY_OFF;
        }
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "ssl_ca_dir")) {
      server->ssl_ca_dir = value[1];
    } else if (has_arg && NGX_STR_CST_EQ(&value[0], "ssl_ca_file")) {
      server->ssl_ca_file = value[1];
    }
    else CONF_MSEC_VALUE(value, server, connect_timeout)
    else CONF_MSEC_VALUE(value, server, reconnect_timeout)
    else CONF_MSEC_VALUE(value, server, bind_timeout)
    else CONF_MSEC_VALUE(value, server, request_timeout)
    else {
        CF_ERROR_A(EMERG, cf, 0, "unknown directive ('%V')", &value[0]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

// parse servers directive
char *servers_directive(ngx_conf_t *cf, void *conf)
{
    main_conf_t *mconf = ngx_http_conf_get_module_main_conf(cf, dav_next_auth_ldap_module);
    RETURN_CONF_ERROR_IF(mconf->servers == NULL, "using \"servers\" when no \"ldap_server\" has been previously defined"
                         " (make sure that \"servers\" goes after \"ldap_server\"s in your configuration file)", NULL);

    loc_conf_t *lconf = ngx_http_conf_get_module_loc_conf(cf, dav_next_auth_ldap_module);
    RETURN_CONF_ERROR_IF(lconf->servers == NULL, "internal error", NULL);

    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *value = &((ngx_str_t *) cf->args->elts)[i];

        server_t *server = NULL;

        for (ngx_uint_t j = 0; j < mconf->servers->nelts; j++) {
            server_t *s = &((server_t *) mconf->servers->elts)[j];
            if (s->alias.len == value->len && ngx_memcmp(s->alias.data, value->data, s->alias.len) == 0) {
                server = s;
                break;
            }
        }

        RETURN_CONF_ERROR_IF(server == NULL, "server \"%V\" has not been defined", value);

        if (lconf->servers == NGX_CONF_UNSET_PTR) {
            lconf->servers = ngx_array_create(cf->pool, 4, sizeof(server_t *));
            RETURN_CONF_ERROR_IF(lconf->servers == NULL, "internal error", NULL);
        }

        server_t **target = ngx_array_push(lconf->servers);
        RETURN_CONF_ERROR_IF(target == NULL, "internal error", NULL);

        *target = server;
    }

    return NGX_CONF_OK;
}

// parse resolver directive
char *resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    main_conf_t *cnf = conf;

    if (cnf->resolver) {
        return "is duplicate";
    }

    ngx_str_t *value = cf->args->elts;

    cnf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    RETURN_CONF_ERROR_IF(cnf->resolver == NULL, "internal error", NULL);

    CF_ERROR_A(DEBUG, cf, 0, "configured resolver %V", &value[1]);

    return NGX_CONF_OK;
}

// parse a URL conf parameter
char *parse_url(ngx_conf_t *cf, server_url_t *server_url)
{
    ngx_str_t *value = cf->args->elts;

    int rc = ldap_url_parse((const char *) value[1].data, &server_url->ludpp);
    if (rc != LDAP_SUCCESS) {
        switch (rc) {
            case LDAP_URL_ERR_MEM:
                CF_ERROR(ERR, cf, 0, "cannot allocate memory space");
                break;

            case LDAP_URL_ERR_PARAM:
                CF_ERROR(ERR, cf, 0, "invalid parameter");
                break;

            case LDAP_URL_ERR_BADSCHEME:
                CF_ERROR(ERR, cf, 0, "URL doesn't begin with \"ldap[s]://\"");
                break;

            case LDAP_URL_ERR_BADENCLOSURE:
                CF_ERROR(ERR, cf, 0, "URL is missing trailing \">\"");
                break;

            case LDAP_URL_ERR_BADURL:
                CF_ERROR(ERR, cf, 0, "invalid URL");
                break;

            case LDAP_URL_ERR_BADHOST:
                CF_ERROR(ERR, cf, 0, "host / port is invalid");
                break;

            case LDAP_URL_ERR_BADATTRS:
                CF_ERROR(ERR, cf, 0, "invalid or missing attributes");
                break;

            case LDAP_URL_ERR_BADSCOPE:
                CF_ERROR(ERR, cf, 0, "invalid or missing scope string");
                break;

            case LDAP_URL_ERR_BADFILTER:
                CF_ERROR(ERR, cf, 0, "invalid or missing filter");
                break;

            case LDAP_URL_ERR_BADEXTS:
                CF_ERROR(ERR, cf, 0, "invalid or missing extensions");
                break;
        }

        return NGX_CONF_ERROR;
    }

    RETURN_CONF_ERROR_IF(server_url->ludpp->lud_attrs == NULL, "no attribute specified in LDAP URL", NULL);

    server_url->url.data = ngx_palloc(cf->pool, ngx_strlen(server_url->ludpp->lud_scheme) + sizeof("://") - 1 + ngx_strlen(server_url->ludpp->lud_host) + sizeof(":65535") - 1 + 1);
    u_char *p = ngx_sprintf(server_url->url.data, "%s://%s:%d%Z", server_url->ludpp->lud_scheme, server_url->ludpp->lud_host, server_url->ludpp->lud_port);
    server_url->url.len = p - server_url->url.data - 1;

    ngx_memzero(&server_url->parsed_url, sizeof(ngx_url_t));
    server_url->parsed_url.url.data = (u_char *) server_url->ludpp->lud_host;
    server_url->parsed_url.url.len = ngx_strlen(server_url->ludpp->lud_host);
    server_url->parsed_url.default_port = server_url->ludpp->lud_port;

    server_url->parsed_url.no_resolve = 1; // do not use hostname resolution checking during configuration parsing
    if (ngx_parse_url(cf->pool, &server_url->parsed_url) != NGX_OK) {
        if (server_url->parsed_url.err) {
            CF_ERROR_A(EMERG, cf, 0, "%s in LDAP URL \"%V\"", server_url->parsed_url.err, &server_url->parsed_url.url);
        } else {
            CF_ERROR_A(EMERG, cf, 0, "unknown error in LDAP URL \"%V\"", &server_url->parsed_url.url);
        }
        return NGX_CONF_ERROR;
    }
    server_url->parsed_url.no_resolve = 0; // reset the no_resolve flag

    if (ngx_strcmp(server_url->ludpp->lud_scheme, "ldap") == 0) {
        return NGX_CONF_OK;
    } else if (ngx_strcmp(server_url->ludpp->lud_scheme, "ldaps") == 0) {
        main_conf_t *halmcf = ngx_http_conf_get_module_main_conf(cf, dav_next_auth_ldap_module);

        if (halmcf->ssl.ctx == NULL) {
            ngx_uint_t protos = NGX_SSL_SSLv2 | NGX_SSL_SSLv3 | NGX_SSL_TLSv1 | NGX_SSL_TLSv1_1 | NGX_SSL_TLSv1_2; // FIXME: !!!
            RETURN_CONF_ERROR_IF(ngx_ssl_create(&halmcf->ssl, protos, halmcf) != NGX_OK, "internal error", NULL);
        }

        return NGX_CONF_OK;
    } else {
        CF_ERROR_A(EMERG, cf, 0, "protocol \"%s://\" is not supported", server_url->ludpp->lud_scheme);

        return NGX_CONF_ERROR;
    }
}

char *parse_binddn_passwd(ngx_conf_t *cf, server_t *server)
{
    ngx_str_t *value = cf->args->elts;
    RETURN_CONF_ERROR_IF(cf->args->nelts < 2 || cf->args->nelts > 3, "bad number of parameters for binddn_passwd", NULL);

    if (cf->args->nelts == 2 && value[1].len != 0) {
        // just copy reference
        server->bind_dn_passwd = value[1];

        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 3 && value[1].len != 0) {
        // non empty password and have a second parameter value (encoding)
        if (NGX_STR_CST_EQ(&value[2], "text")) {

            // just copy reference
            server->bind_dn_passwd = value[1];

        } else if (NGX_STR_CST_EQ(&value[2], "base64")) {

            // base64 decode
            server->bind_dn_passwd.len = 0;
            int decoded_length = 3 * value[1].len / 4;
            server->bind_dn_passwd.data = ngx_pnalloc(cf->pool, decoded_length + 1);
            ngx_decode_base64(&server->bind_dn_passwd, &value[1]);
            server->bind_dn_passwd.data[decoded_length] = '\0';

        } else if (NGX_STR_CST_EQ(&value[2], "hex")) {

            // hex decode
            server->bind_dn_passwd.len = value[1].len / 2;
            server->bind_dn_passwd.data = ngx_pnalloc(cf->pool, server->bind_dn_passwd.len + 1);
            hex_decode(&server->bind_dn_passwd, &value[1]);
            server->bind_dn_passwd.data[server->bind_dn_passwd.len] = '\0';

        } else {
            CF_ERROR_A(WARN, cf, 0, "unknown encoding ('%V') for binddn_password. (assumming clear text)", &value[2]);

            // just copy reference
            server->bind_dn_passwd = value[1];
        }
    }

    return NGX_CONF_OK;
}

// parse "require" conf parameter
char *parse_require(ngx_conf_t *cf, server_t *server)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_complex_value_t* target = NULL;

    if (NGX_STR_CST_EQ(&value[1], "valid_user")) {
        RETURN_CONF_ERROR_IF(cf->args->nelts > 2, "'require valid_user' extra arguments provided", NULL);
        server->require_valid_user = 1;
        return NGX_CONF_OK;
    } else if (NGX_STR_CST_EQ(&value[1], "user")) {
        if (server->require_user == NULL) {
            server->require_user = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            RETURN_CONF_ERROR_IF(server->require_user == NULL, "internal error", NULL);
        }
        target = ngx_array_push(server->require_user);
    } else if (NGX_STR_CST_EQ(&value[1], "group")) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "http_auth_ldap: Setting group");
        if (server->require_group == NULL) {
            server->require_group = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            RETURN_CONF_ERROR_IF(server->require_group == NULL, "internal error", NULL);
        }
        target = ngx_array_push(server->require_group);
    }

    RETURN_CONF_ERROR_IF(target == NULL, "internal error", NULL);

    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = target;
    RETURN_CONF_ERROR_IF(ngx_http_compile_complex_value(&ccv), "internal error", NULL);

    return NGX_CONF_OK;
}

// parse "satisfy" conf parameter
char *parse_satisfy(ngx_conf_t *cf, server_t *server)
{
    ngx_str_t *value;
    value = cf->args->elts;

    if (NGX_STR_CST_EQ(&value[1], "all")) {
        server->satisfy_all = 1;
        return NGX_CONF_OK;
    }

    if (NGX_STR_CST_EQ(&value[1], "any")) {
        server->satisfy_all = 0;
        return NGX_CONF_OK;
    }

    CF_ERROR_A(EMERG, cf, 0, "incorrect value for satisfy ('%V')", &value[2]);

    return NGX_CONF_ERROR;
}

// parse "referral" conf parameter
char *parse_referral(ngx_conf_t *cf, server_t *server)
{
    ngx_str_t *value;
    value = cf->args->elts;

    if (NGX_STR_CST_EQ(&value[1], "on")) {
        server->referral = 1;
        return NGX_CONF_OK;
    }

    if (NGX_STR_CST_EQ(&value[1], "off")) {
        server->referral = 0;
        return NGX_CONF_OK;
    }

    CF_ERROR_A(EMERG, cf, 0, "incorrect value for referral ('%V')", &value[1]);

    return NGX_CONF_ERROR;
}



// create main config which will store ldap_servers array
void *create_main_conf(ngx_conf_t *cf)
{
    main_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->cnf_pool = cf->pool;
    conf->cache_enabled = NGX_CONF_UNSET;
    conf->cache_expiration_time = NGX_CONF_UNSET_MSEC;
    conf->cache_size = NGX_CONF_UNSET_SIZE;
    conf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    conf->resolver = NULL;

    return conf;
}

char *init_main_conf(ngx_conf_t *cf, void *parent)
{
    main_conf_t *conf = parent;

    if (conf->resolver_timeout == NGX_CONF_UNSET_MSEC) {
        conf->resolver_timeout = 10000;
    }

    if (conf->cache_enabled == NGX_CONF_UNSET) {
        conf->cache_enabled = 0;
    }
    if (conf->cache_enabled == 0) {
        return NGX_CONF_OK;
    }

    if (conf->cache_size == NGX_CONF_UNSET_SIZE) {
        conf->cache_size = 100;
    }
    RETURN_CONF_ERROR_IF(conf->cache_size < 100, "auth_ldap_cache_size cannot be smaller than 100 entries (%d)", conf->cache_size);

    if (conf->cache_expiration_time == NGX_CONF_UNSET_MSEC) {
        conf->cache_expiration_time = 10000;
    }
    RETURN_CONF_ERROR_IF(conf->cache_expiration_time < 1000, "auth_ldap_cache_expiration_time cannot be smaller than 1000 ms (%d)", conf->cache_expiration_time);

    return NGX_CONF_OK;
}

// create location conf
void *create_loc_conf(ngx_conf_t *cf)
{
    loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->servers = NGX_CONF_UNSET_PTR;
    conf->enabled = 1;

    return conf;
}

// merge location conf
char *merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    loc_conf_t *prev = parent;
    loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->servers, prev->servers, NULL);
    ngx_conf_merge_uint_value(conf->enabled, prev->enabled, 1);

    return NGX_CONF_OK;
}

dav_next_auth_provider_t provider;

ngx_int_t preinit(ngx_conf_t *cf)
{

    dav_next_loc_conf_t *dlcf = ngx_http_conf_get_module_loc_conf(cf, dav_next_module);

    if (dlcf == NULL || dlcf->register_provider == NULL) {
        ERROR(EMERG, cf->log, 0, "Please load dav-next main module before this one.");
        return NGX_ERROR;
    }

    if (dlcf->register_provider(&provider) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t init(ngx_conf_t *cf)
{
    return NGX_OK;
}

ngx_int_t init_worker(ngx_cycle_t *cycle)
{
    if (ngx_process != NGX_PROCESS_SINGLE && ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    RETURN_RC_IF_NOK_EXT(cycle->log, init_cache(cycle));
    RETURN_RC_IF_NOK_EXT(cycle->log, init_connections(cycle));

    return NGX_OK;
}

ngx_http_module_t ctx = {
    preinit,                             // preconfiguration
    init,                                // postconfiguration
    create_main_conf,                    // create main configuration
    init_main_conf,                      // init main configuration
    NULL,                                // create server configuration
    NULL,                                // merge server configuration
    create_loc_conf,                     // create location configuration
    merge_loc_conf                       // merge location configuration
};

ngx_module_t dav_next_auth_ldap_module = {
    NGX_MODULE_V1,
    &ctx,                                // module context
    commands,                            // module directives
    NGX_HTTP_MODULE,                     // module type
    NULL,                                // init master
    NULL,                                // init module
    init_worker,                         // init process
    NULL,                                // init thread
    NULL,                                // exit thread
    NULL,                                // exit process
    NULL,                                // exit master
    NGX_MODULE_V1_PADDING
};

// get authenticated identity from LDAP
ngx_int_t get_identity(ngx_http_request_t *r, dav_next_auth_identity_t *identity, void *dummy)
{
    ngx_int_t rc = ngx_http_auth_basic_user(r);
    if (rc != NGX_OK) {
        DEBUG1(r->connection->log, 0, "no basic auth user, rc=%i", rc);
        return NGX_DECLINED;
    }

    // set uid from request
    identity->uid = r->headers_in.user;
    DEBUG1(r->connection->log, 0, "uid='%V'", &identity->uid);

    // set gids from LDAP
    ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_auth_ldap_module);
    identity->gids = &ctx->groups;

    if (identity->gids == NULL) {
        DEBUG0(r->connection->log, 0, "no gid (NULL)");
        return NGX_OK;
    }

    if (identity->gids->nelts == 0) {
        DEBUG0(r->connection->log, 0, "no gid (empty)");
        identity->gids = NULL; // better NULL than empty
        return NGX_OK;
    }

    // log the gids found
    DEBUG1(r->connection->log, 0, "%ui gids found", identity->gids->nelts);

    return NGX_OK;
}

ngx_int_t disable(ngx_http_request_t *r, void *conf)
{
    loc_conf_t *cnf = ngx_http_get_module_loc_conf(r, dav_next_auth_ldap_module);

    cnf->enabled = 0;
    DEBUG0(r->connection->log, 0, "auth ldap disabled");

    return NGX_OK;
}

ngx_int_t enable(ngx_http_request_t *r, void *conf)
{
    loc_conf_t *cnf = ngx_http_get_module_loc_conf(r, dav_next_auth_ldap_module);

    cnf->enabled = 1;
    DEBUG0(r->connection->log, 0, "auth ldap enabled");

    return NGX_OK;
}

// LDAP provider definition
dav_next_auth_provider_t provider = {
    .name = ngx_string("ldap"),
    .capabilities = DAV_NEXT_AUTH_CAP_GROUPS,
    .directives = directives,
    .auth = auth,
    .get_identity = get_identity,
    .prepare_conf = NULL,
    .disable = disable,
    .enable = enable
};
