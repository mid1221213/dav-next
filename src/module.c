/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-module.c
 * Module configuration and initialization for dav-next
 * © Alexandre Jousset
 */

#define DAV_NEXT_MODULE_C

#include "dav-next.h"
#include "handlers.h"
#include "auth.h"
#include <ngx_config.h>

#pragma GCC visibility push(hidden)

// forward declarations
char *conf_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t dav_next_preinit(ngx_conf_t *cf);
ngx_int_t dav_next_init(ngx_conf_t *cf);
void *create_loc_conf(ngx_conf_t *cf);
char *merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

// configuration directives
ngx_command_t dav_next_commands[] = {
    {
        ngx_string("dav_next"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        conf_block,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

// dav-next module directives
ngx_http_module_t dav_next_module_ctx = {
    dav_next_preinit,             // preconfiguration
    dav_next_init,                // postconfiguration

    NULL,                         // create main configuration
    NULL,                         // init main configuration

    NULL,                         // create server configuration
    NULL,                         // merge server configuration

    create_loc_conf,              // create location configuration
    merge_loc_conf                // merge location configuration
};

#pragma GCC visibility push(default)

// module info, only this symbol is exported from the shared library
ngx_module_t dav_next_module = {
    NGX_MODULE_V1,
    &dav_next_module_ctx,         // module context
    dav_next_commands,            // module directives
    NGX_HTTP_MODULE,              // module type
    NULL,                         // init master
    NULL,                         // init module
    NULL,                         // init process
    NULL,                         // init thread
    NULL,                         // exit thread
    NULL,                         // exit process
    NULL,                         // exit master
    NGX_MODULE_V1_PADDING
};

#pragma GCC visibility pop

// init shared memory zone
ngx_int_t dav_next_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    dav_next_lock_t *lock = shm_zone->data;
    dav_next_lock_t *olock = data;

    // if already inited
    if (olock) {
        // get and store shared memory info
        lock->sh = olock->sh;
        lock->shpool = olock->shpool;

        return NGX_OK;
    }

    // set shared memory address as lock pool
    lock->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    // if already exists
    if (shm_zone->shm.exists) {
        // get and store lock shared memory pool info
        lock->sh = lock->shpool->data;

        return NGX_OK;
    }

    // allocate lock shared memory pool
    lock->sh = ngx_slab_alloc(lock->shpool, sizeof(dav_next_lock_sh_t));
    // no news = bad news
    if (lock->sh == NULL) {
        return NGX_ERROR;
    }

    // store lock shared memory info
    lock->shpool->data = lock->sh;

    // init lock queue
    ngx_queue_init(&lock->sh->queue);

    // calc len of log string
    size_t len = sizeof(" in dav_next zone ''") + shm_zone->shm.name.len;

    // allocate log context
    lock->shpool->log_ctx = ngx_slab_alloc(lock->shpool, len);
    if (lock->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    // insert log string
    ngx_sprintf(lock->shpool->log_ctx, " in dav_next zone '%V'%Z", &shm_zone->shm.name);

    return NGX_OK;
}

// copied / modified from nginx source's src/core/ngx_file.c:ngx_get_full_name()
ngx_int_t dav_next_get_full_name(ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *name)
{
    if (name->data[0] == '/') {
        return NGX_OK;
    }

    size_t len = prefix->len;

    u_char *n = ngx_pnalloc(pool, len + name->len + 1 + 1);
    if (n == NULL) {
        return NGX_ERROR;
    }

    u_char *p = ngx_cpymem(n, prefix->data, len);
    p = ngx_cpymem(p, "/", 1);
    ngx_cpystrn(p, name->data, name->len + 1);

    name->len += len;
    name->data = n;

    return NGX_OK;
}

// create local conf (called by nginx for each server)
void *create_loc_conf(ngx_conf_t *cf)
{
    dav_next_loc_conf_t *dlcf = ngx_pcalloc(cf->pool, sizeof(dav_next_loc_conf_t));
    if (dlcf == NULL) {
        return NULL;
    }

    // set conf default values
    dlcf->shm_timeout = 60;
    dlcf->shm_size = (ssize_t) (8 * ngx_pagesize);

    return dlcf;
}

// create local conf (called by nginx for each server)
char *merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    dav_next_loc_conf_t *dlcf = child;
    dav_next_loc_conf_t *prev = parent;

    // get shared memory zone pointer if needed
    if (dlcf->shm_zone == NULL) {
        dlcf->shm_zone = prev->shm_zone;
    }

    // // not given, not our business
    // if (dlcf->shm_zone == NULL) {
    //     return NGX_CONF_OK;
    // }

    // get loc core module conf (to fetch `root` dir and tweak etag / satisfy)
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);

    // chunk_size defaults to 10M, client_max_body_size should be ≥ 100M?
    if (clcf->client_max_body_size < 100 * 1024 * 1024) {
        CF_ERROR_A(WARN, cf, 0, "client_max_body_size (%d B) must be ≥ 100 MB, fixing…", clcf->client_max_body_size);
        clcf->client_max_body_size = 100 * 1024 * 1024;
    }

    // force internal etag processing off (defaults to 'on' but we manage it ourselves)
    clcf->etag = 0;

    // TODO: check if needed ↓ (satisfy management HOWTO)
    // RETURN_CONF_ERROR_IF(clcf->satisfy != NGX_HTTP_SATISFY_ALL, "satisfy (%d) directive must be set to all (default)", clcf->satisfy);

    ngx_str_t test_dir;
    ngx_int_t rc;
    ngx_file_info_t fi;

    // `<root>/files`
    ngx_str_set(&test_dir, "files\0");
    rc = dav_next_get_full_name(cf->pool, &clcf->root, &test_dir);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // this directory must exist
    if (ngx_file_info(test_dir.data, &fi) == NGX_FILE_ERROR) {
        DEBUG1(cf->log, ngx_errno, "dir '%V' not found, creating it", &test_dir);
        // let's suppose my dir does not exist (may be wrong but we don't care)
        RETURN_CONF_ERROR_IF(ngx_create_dir(test_dir.data, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST, "directory '%V' not found and not creatable!", &test_dir);
    }

    // and belong to user
    RETURN_CONF_ERROR_IF(chown((const char *) test_dir.data, ccf->user, ccf->group) == -1, "chown(\"%V\", %d) failed", &test_dir, ccf->user);

    // `<root>/uploads`
    ngx_str_set(&test_dir, "uploads\0");
    rc = dav_next_get_full_name(cf->pool, &clcf->root, &test_dir);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // this directory must exist too
    if (ngx_file_info(test_dir.data, &fi) == NGX_FILE_ERROR) {
        DEBUG1(cf->log, ngx_errno, "dir '%V' not found, creating it", &test_dir);
        // let's suppose my dir does not exist (may be wrong but we don't care)
        RETURN_CONF_ERROR_IF(ngx_create_dir(test_dir.data, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST, "directory '%V' not found and not creatable!", &test_dir);
    }

    // and belong to user
    RETURN_CONF_ERROR_IF(chown((const char *) test_dir.data, ccf->user, ccf->group) == -1, "chown(\"%V\", %d) failed", &test_dir, ccf->user);

    return NGX_CONF_OK;
}

char *conf_block_item(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    dav_next_loc_conf_t *dlcf = conf;

    // get args
    ngx_str_t *value = cf->args->elts;

    switch (cf->args->nelts) {
    case 1:
        break;
        // return "is unknown";
    case 2:
        if (NGX_STR_CST_EQ(&value[0], "auth")) {
            dlcf->auth_provider = dav_next_auth_find_provider(&value[1]);
            RETURN_CONF_ERROR_IF(dlcf->auth_provider == NULL, "unknown auth provider \"%V\"", &value[1]);

            if (dlcf->auth_provider->prepare_conf != NULL) {
                dlcf->auth_conf = dlcf->auth_provider->prepare_conf(cf);
                RETURN_CONF_ERROR_IF(dlcf->auth_conf == NGX_CONF_ERROR, "could not prepare conf in provider \"%V\"", &value[1]);
            } else {
                dlcf->auth_conf = NULL;
            }

            return NGX_CONF_OK;

        } else if (NGX_STR_CST_EQ(&value[0], "lock_mem")) {
            // parse it nginx size way
            dlcf->shm_size = ngx_parse_size(&value[1]);

            // if wrong
            RETURN_CONF_ERROR_IF(dlcf->shm_size == NGX_ERROR, "invalid lock_mem size '%V'", &value[1]);

            // if too small
            RETURN_CONF_ERROR_IF(dlcf->shm_size < (ssize_t) (8 * ngx_pagesize), "lock_mem size '%V' is too small (< %uiB)", &value[1], 8 * ngx_pagesize);

            return NGX_CONF_OK;
        } else if (NGX_STR_CST_EQ(&value[0], "lock_timeout")) {
            // parse it nginx time way
            dlcf->shm_timeout = ngx_parse_time(&value[1], 1);

            // if wrong
            RETURN_CONF_ERROR_IF(dlcf->shm_timeout == (time_t) NGX_ERROR || dlcf->shm_timeout == 0, "invalid lock_timeout value '%V'", &value[1]);

            return NGX_CONF_OK;
        }

        break;
        // return "is unknown";
    default:
        break;
        // return "is unknown";
    }

    // if we get there, it should be a provider command
    RETURN_CONF_ERROR_IF(dlcf->auth_provider == NULL, "auth provider not set", NULL);

    for (dav_next_directive_t *directive = dlcf->auth_provider->directives; directive->set != NULL ; directive++) {
        if (NGX_STR_EQ(&value[0], &directive->name)) {
            return directive->set(cf, dlcf);
        }
    }

    // if we get there, it is, actually, not a provider command
    CF_ERROR_A(EMERG, cf, 0, "\"%V\" is unknown", &value[0]);

    return NGX_CONF_ERROR;
}

// process `dav_next` configuration block (in SRV+ context)
// TODO: usage: `dav_next <server_name> { … }
char *conf_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    dav_next_loc_conf_t *dlcf = conf;

    // RETURN_CONF_ERROR_IF(dav_next_read_token(cf) != NGX_CONF_BLOCK_START, "expecting \"{\"", NULL);

    // get args
    ngx_str_t *value = cf->args->elts;

    ngx_conf_t save = *cf;

    ngx_pool_t *pool = cf->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    RETURN_CONF_ERROR_IF(cf->pool == NULL, "Could not allocate pool in dav_next \"%V\"", &value[1]);

    // check if we already have seen this one in this server context
    if (dlcf->shm_zone) {
        return "is duplicate 1";
    }

    // extract value (server name)
    dlcf->name = value[1];

    cf->handler = conf_block_item;
    cf->handler_conf = conf;

    char *rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        ngx_destroy_pool(pool);
        return rv;
    }

    // reserve shared memory with that name and size
    dlcf->shm_zone = ngx_shared_memory_add(cf, &dlcf->name, dlcf->shm_size, &dav_next_module);
    if (dlcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    // check if already reserved
    RETURN_CONF_ERROR_IF(dlcf->shm_zone->data, "duplicate name '%V'", &dlcf->name);

    dav_next_lock_t *lock = ngx_pcalloc(cf->pool, sizeof(dav_next_lock_t));
    if (lock == NULL) {
        return NGX_CONF_ERROR;
    }

    lock->timeout = dlcf->shm_timeout;
    // shared memory init
    dlcf->shm_zone->init = dav_next_init_zone;
    dlcf->shm_zone->data = lock;

    return NGX_CONF_OK;
}

// nginx module preinit (called before all configs are created)
ngx_int_t dav_next_preinit(ngx_conf_t *cf)
{
    if (dav_next_auth_preinit_providers(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    dav_next_loc_conf_t *dlcf = ngx_http_conf_get_module_loc_conf(cf, dav_next_module);

    if (dav_next_auth_init_providers(&dlcf->register_provider) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

// nginx module init (called after all configs are read)
ngx_int_t dav_next_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_http_handler_pt *h;

    // install PREACCESS phase handler

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = dav_next_preaccess_handler;

    // install ACCESS phase handler

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = dav_next_access_handler;

    // install PRECONTENT phase handler

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = dav_next_precontent_handler;

    // install CONTENT phase handler

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = dav_next_content_handler;

    return NGX_OK;
}
