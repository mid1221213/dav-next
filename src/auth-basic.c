/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-auth-basic.c
 * Basic authentication provider for dav-next
 * © Alexandre Jousset
 */

#include "dav-next.h"
#include "auth.h"
#include "utils.h"

extern ngx_module_t ngx_http_auth_basic_module;

#pragma GCC visibility push(hidden)

ngx_module_t dav_next_auth_basic_module;

// nginx Basic Auth *must* be available
typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t  *user_file;
} ngx_http_auth_basic_loc_conf_t;

// basic provider configuration
typedef struct {
    ngx_str_t groups_file;
    ngx_hash_t groups_hash;
    ngx_uint_t groups_loaded:1;
    ngx_http_complex_value_t *disabled_realm;
    ngx_http_complex_value_t *saved_realm;
} conf_t;

// gid entry in hash table
typedef struct {
    ngx_str_t  uid;
    ngx_str_t  gids; // comma-separated gids
} group_entry_t;

void *prepare_conf(ngx_conf_t *cf);
ngx_int_t auth(ngx_http_request_t *r, void *conf);
ngx_int_t disable(ngx_http_request_t *r, void *conf);
ngx_int_t enable(ngx_http_request_t *r, void *conf);
ngx_int_t get_identity(ngx_http_request_t *r, dav_next_auth_identity_t *identity, void *provider_conf);
char *realm_directive(ngx_conf_t *cf, void *conf);
char *users_file_directive(ngx_conf_t *cf, void *conf);

// configuration directives
dav_next_directive_t directives[] = {
    {
        ngx_string("realm"),
        realm_directive,
    },
    {
        ngx_string("users_file"),
        users_file_directive,
    },
    dav_next_null_directive
};

// basic provider definition
dav_next_auth_provider_t provider = {
    .name = ngx_string("basic"),
    .capabilities = DAV_NEXT_AUTH_CAP_GROUPS,
    .directives = directives,
    .auth = auth,
    .get_identity = get_identity,
    .prepare_conf = prepare_conf,
    .disable = disable,
    .enable = enable
};

// create basic provider configuration
void *prepare_conf(ngx_conf_t *cf)
{
    conf_t *dabc = ngx_http_conf_get_module_loc_conf(cf, dav_next_auth_basic_module);
    if (dabc == NULL) {
        return NGX_CONF_ERROR;
    }

    if (((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    dav_next_loc_conf_t *dlcf = ngx_http_conf_get_module_loc_conf(cf, dav_next_module);

    ngx_http_auth_basic_loc_conf_t *alcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_auth_basic_module);

    // set default realm to dav-next name
    if (alcf->realm == NGX_CONF_UNSET_PTR) {
        ngx_str_t default_value = dlcf->name;
        if (dav_next_set_complex_value(cf, &alcf->realm, &default_value, 0) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    // set default user filename
    if (alcf->user_file == NGX_CONF_UNSET_PTR) {
        ngx_str_t default_value = ngx_string("htpasswd");

        if (dav_next_set_complex_value(cf, &alcf->user_file, &default_value, 1) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        // resolve relative path against nginx prefix
        ngx_str_t full_path = default_value;
        if (ngx_conf_full_name(cf->cycle, &full_path, 1) != NGX_OK) {
            CF_ERROR_A(EMERG, cf, 0, "failed to resolve path '%V'", &default_value);
            return NGX_CONF_ERROR;
        }

        // copy the path
        dabc->groups_file.len = full_path.len;
        dabc->groups_file.data = ngx_pstrdup(cf->pool, &full_path);
        if (dabc->groups_file.data == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    return dabc;
}

// create basic provider configuration
void *create_loc_conf(ngx_conf_t *cf)
{
    conf_t *conf = ngx_pcalloc(cf->pool, sizeof(conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

// create basic provider configuration
char *merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    conf_t *dabc = child;
    conf_t *prev = parent;

    ngx_conf_merge_str_value(dabc->groups_file, prev->groups_file, NULL);
    dabc->groups_hash = prev->groups_hash; // HACK: is that valid?
    ngx_conf_merge_uint_value(dabc->groups_loaded, prev->groups_loaded, 0);

    return NGX_CONF_OK;
}

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

// module context
ngx_http_module_t ctx = {
    preinit, // preconfiguration
    init,    // postconfiguration

    NULL, // create main configuration
    NULL, // init main configuration

    NULL, // create server configuration
    NULL, // merge server configuration

    create_loc_conf, // create location configuration
    merge_loc_conf, // merge location configuration
};

#pragma GCC visibility push(default)

// module info, only this symbol is exported from the shared library
ngx_module_t dav_next_auth_basic_module = {
    NGX_MODULE_V1,
    &ctx,                  // module context
    NULL,                  // module directives
    NGX_HTTP_MODULE,       // module type
    NULL,                  // init master
    NULL,                  // init module
    NULL,                  // init process
    NULL,                  // init thread
    NULL,                  // exit thread
    NULL,                  // exit process
    NULL,                  // exit master
    NGX_MODULE_V1_PADDING
};

#pragma GCC visibility pop

// parse a single line from the groups file
ngx_int_t parse_line(ngx_pool_t *pool, ngx_str_t *line, group_entry_t *entry)
{
    if (line == NULL || line->len == 0) {
        return NGX_DECLINED;
    }

    u_char *start = line->data, *end = line->data + line->len;

    // skip leading whitespace
    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }

    // skip empty lines
    if (start >= end) {
        return NGX_DECLINED;
    }

    // skip comment lines
    if (*start == '#') {
        return NGX_DECLINED;
    }

    //  find the colon separator
    u_char *p = start;
    while (p < end && *p != ':') {
        p++;
    }

    if (p >= end || p == start) {
        // no colon found or empty uid
        return NGX_DECLINED;
    }

    // extract uid
    entry->uid.data = start;
    entry->uid.len = p - start;

    // skip the colon
    p++;

    // now skip the password (2nd field)

    //  find the colon separator
    u_char *start_gids = p;
    while (p < end && *p != ':') {
        p++;
    }

    if (p >= end || p == start_gids) {
        // no colon found or empty password = no groups
        return NGX_OK;
    }

    // skip the colon
    p++;

    // rest is the gids (may be empty)
    entry->gids.data = p;
    entry->gids.len = end - p;

    // trim trailing whitespace from gids
    while (entry->gids.len > 0 &&
           (entry->gids.data[entry->gids.len - 1] == ' ' ||
            entry->gids.data[entry->gids.len - 1] == '\t' ||
            entry->gids.data[entry->gids.len - 1] == '\r' ||
            entry->gids.data[entry->gids.len - 1] == '\n')) {
        entry->gids.len--;
    }

    return NGX_OK;
}

// parse comma-separated group ids into an array
ngx_int_t parse_gids(ngx_array_t *gids, ngx_str_t *value)
{
    if (value == NULL || value->len == 0) {
        return NGX_OK;
    }

    u_char *start = value->data, *end = value->data + value->len;

    while (start < end) {
        // Find next comma or end of string
        u_char *p = start;
        while (p < end && *p != ',') {
            p++;
        }

        size_t len = p - start;

        // Skip empty segments
        if (len > 0) {
            ngx_str_t *gid = ngx_array_push(gids);
            if (gid == NULL) {
                return NGX_ERROR;
            }

            gid->data = start;
            gid->len = len;
        }

        // move past the comma
        start = p + 1;
    }

    return NGX_OK;
}

// load groups from file into hash table
ngx_int_t load_groups(ngx_http_request_t *r, conf_t *dabc)
{
    if (dabc->groups_file.len == 0 || dabc->groups_loaded) {
        return NGX_OK;
    }

    ngx_log_t *log = r->connection->log;

    DEBUG1(log, 0, "loading groups from '%V'", &dabc->groups_file);

    // open the file
    ngx_file_t file;
    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = dabc->groups_file;
    file.log = log;

    file.fd = ngx_open_file(dabc->groups_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ERROR_A(EMERG, log, ngx_errno, "failed to open groups file '%V'", &dabc->groups_file);
        return NGX_ERROR;
    }

    // get file size
    ngx_file_info_t fi;
    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ERROR_A(EMERG, log, ngx_errno, "failed to stat groups file '%V'", &dabc->groups_file);
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    size_t size = ngx_file_size(&fi);
    if (size == 0) {
        DEBUG0(log, 0, "groups file is empty");
        ngx_close_file(file.fd);
        dabc->groups_loaded = 1;
        return NGX_OK;
    }

    u_char *buf = ngx_pnalloc(ngx_cycle->pool, size + 1);
    if (buf == NULL) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    // read file contents
    ssize_t n = ngx_read_file(&file, buf, size, 0);
    ngx_close_file(file.fd);

    if (n == NGX_ERROR) {
        ERROR_A(EMERG, log, ngx_errno, "failed to read groups file '%V'", &dabc->groups_file);
        return NGX_ERROR;
    }

    buf[size] = '\0';

    ngx_array_t entries;
    // initialize entries array for hash keys
    if (ngx_array_init(&entries, ngx_cycle->pool, 32, sizeof(ngx_hash_key_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    u_char *start = buf, *end = buf + size;

    // parse file line by line
    while (start < end) {
        // find end of line
        u_char *p = start;
        while (p < end && *p != '\n') {
            p++;
        }

        ngx_str_t line;
        line.data = start;
        line.len = p - start;

        group_entry_t entry;
        ngx_int_t rc = parse_line(ngx_cycle->pool, &line, &entry);

        ngx_hash_key_t *hk;

        switch (rc) {
            case NGX_OK:
                // add to hash keys array
                hk = ngx_array_push(&entries);
                if (hk == NULL) {
                    return NGX_ERROR;
                }

                hk->key = entry.uid;
                hk->key_hash = ngx_hash_key(entry.uid.data, entry.uid.len);

                hk->value = ngx_array_create(ngx_cycle->pool, 10, sizeof(ngx_str_t));
                if (hk->value == NULL) {
                    return NGX_ERROR;
                }

                // parse comma-separated group ids
                if (parse_gids(hk->value, &entry.gids) != NGX_OK) {
                    return NGX_ERROR;
                }

                ERROR_A(WARN, log, 0, "loaded uid='%V' → %ui gids", &entry.uid, ((ngx_array_t *) hk->value)->nelts);

                break;

            case NGX_ERROR:
                ERROR(WARN, log, 0, "failed to parse group line, ignoring…");
                break;

            case NGX_DECLINED:
                // nothing (empty or comment line)
                break;
        }

        // move to next line
        start = p + 1;
    }

    // uild the hash table
    if (entries.nelts == 0) {
        DEBUG0(log, 0, "no valid entries in groups file, ignoring…");
        dabc->groups_loaded = 1;
        return NGX_OK;
    }

    ngx_hash_init_t hash_init;
    hash_init.hash = &dabc->groups_hash;
    hash_init.key = ngx_hash_key;
    hash_init.max_size = 512;
    hash_init.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash_init.name = "dav_next_auth_basic_groups";
    hash_init.pool = ngx_cycle->pool;
    hash_init.temp_pool = ngx_cycle->pool;

    if (ngx_hash_init(&hash_init, entries.elts, entries.nelts) != NGX_OK) {
        ERROR(EMERG, log, 0, "failed to build groups hash");
        return NGX_ERROR;
    }

    ERROR_A(NOTICE, log, 0, "loaded %ui group entries from '%V'", entries.nelts, &dabc->groups_file);

    dabc->groups_loaded = 1;

    return NGX_OK;
}

char *realm_directive(ngx_conf_t *cf, void *conf)
{
    dav_next_loc_conf_t *dlcf = conf;
    conf_t *dabc = dlcf->auth_conf;

    ngx_str_t off = ngx_string("off");
    char *rv = dav_next_set_complex_value(cf, &dabc->disabled_realm, &off, 0);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    ngx_http_auth_basic_loc_conf_t *alcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_auth_basic_module);

    ngx_str_t value = *((ngx_str_t *) cf->args->elts + 1);

    return dav_next_set_complex_value(cf, &alcf->realm, &value, 0);
}

ngx_int_t disable(ngx_http_request_t *r, void *conf)
{
    ngx_http_auth_basic_loc_conf_t *alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_module);
    dav_next_loc_conf_t *dlcf = conf;
    conf_t *dabc = dlcf->auth_conf;

    dabc->saved_realm = alcf->realm;
    alcf->realm = dabc->disabled_realm;

    return NGX_OK;
}

ngx_int_t enable(ngx_http_request_t *r, void *conf)
{
    ngx_http_auth_basic_loc_conf_t *alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_module);
    dav_next_loc_conf_t *dlcf = conf;
    conf_t *dabc = dlcf->auth_conf;

    alcf->realm = dabc->saved_realm;

    return NGX_OK;
}

// process `users_file` configuration directive
// file format: one "uid:pass:gid1,gid2,..." entry per line
char *users_file_directive(ngx_conf_t *cf, void *conf)
{
    dav_next_loc_conf_t *dlcf = conf;
    conf_t *dabc = dlcf->auth_conf;

    ngx_str_t value = *((ngx_str_t *) cf->args->elts + 1);

    // resolve relative path against nginx prefix
    ngx_str_t full_path = value;
    if (ngx_conf_full_name(cf->cycle, &full_path, 1) != NGX_OK) {
        CF_ERROR_A(EMERG, cf, 0, "failed to resolve path '%V'", &value);
        return NGX_CONF_ERROR;
    }

    // copy the path
    dabc->groups_file.len = full_path.len;
    dabc->groups_file.data = ngx_pstrdup(cf->pool, &full_path);
    if (dabc->groups_file.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_http_auth_basic_loc_conf_t *alcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_auth_basic_module);

    return dav_next_set_complex_value(cf, &alcf->user_file, &value, 1);
}

// let nginx make the Basic Auth test
ngx_int_t auth(ngx_http_request_t *r, void *conf)
{
    dav_next_loc_conf_t *dlcf = conf;
    conf_t *dabc = dlcf->auth_conf;

    if (load_groups(r, dabc) != NGX_OK) {
        ERROR_A(EMERG, r->connection->log, 0, "failed to load groups in file '%V'", &dabc->groups_file);
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}

// get authenticated identity from Basic Auth
ngx_int_t get_identity(ngx_http_request_t *r, dav_next_auth_identity_t *identity, void *provider_conf)
{
    conf_t *conf = provider_conf;

    ngx_int_t rc = ngx_http_auth_basic_user(r);
    if (rc != NGX_OK) {
        DEBUG1(r->connection->log, 0, "dav-next auth-basic: no basic auth user: %i", rc);
        return NGX_DECLINED;
    }

    // set uid from request
    identity->uid = r->headers_in.user;
    identity->gids = NULL;

    DEBUG1(r->connection->log, 0, "uid: '%V'", &identity->uid);

    // if no groups file or hash not initialized, we're done
    if (conf == NULL || conf->groups_file.len == 0 || !conf->groups_loaded) {
        DEBUG0(r->connection->log, 0, "no groups file configured");
        return NGX_OK;
    }

    // look up user in groups hash
    identity->gids = ngx_hash_find(&conf->groups_hash, ngx_hash_key(identity->uid.data, identity->uid.len), identity->uid.data, identity->uid.len);

    if (identity->gids == NULL) {
        DEBUG1(r->connection->log, 0, "no groups for uid = '%V'", &identity->uid);
        return NGX_OK;  // user exists but has no groups
    }

    if (identity->gids->nelts == 0) {
        DEBUG1(r->connection->log, 0, "empty group list for uid = '%V'", &identity->uid);
        return NGX_OK;  // user exists but has no groups
    }

    DEBUG2(r->connection->log, 0, "uid='%V', %ui gids", &identity->uid, identity->gids->nelts);
    for (ngx_uint_t i = 0; i < identity->gids->nelts; i++) {
        DEBUG2(r->connection->log, 0, "gid #%ui = '%V'", i, ((ngx_str_t *)identity->gids->elts) + i);
    }

    return NGX_OK;
}
