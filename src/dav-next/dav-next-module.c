/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-module.c
 * Module configuration and initialization for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#define DAV_NEXT_MODULE_C

#include "dav-next.h"
#include "dav-next-module.h"
#include "dav-next-handlers.h"

// configuration directives
ngx_command_t dav_next_commands[] = {
    {
        ngx_string("dav_next_server_zone"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
        dav_next_server_zone,
        0,
        0,
        NULL
    },
    {
        ngx_string("dav_next_server"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        dav_next_server,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};


// dav-next module directives
ngx_http_module_t dav_next_module_ctx = {
    NULL,                                  // preconfiguration
    dav_next_init,                         // postconfiguration

    NULL,                                  // create main configuration
    NULL,                                  // init main configuration

    NULL,                                  // create server configuration
    NULL,                                  // merge server configuration

    dav_next_create_loc_conf,              // create location configuration
    dav_next_merge_loc_conf,               // merge location configuration
};


#pragma GCC visibility push(default)


// module info, only this symbol is exported from the shared library
ngx_module_t dav_next_module = {
    NGX_MODULE_V1,
    &dav_next_module_ctx,                  // module context
    dav_next_commands,                     // module directives
    NGX_HTTP_MODULE,                       // module type
    NULL,                                  // init master
    NULL,                                  // init module
    NULL,                                  // init process
    NULL,                                  // init thread
    NULL,                                  // exit thread
    NULL,                                  // exit process
    NULL,                                  // exit master
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


// create local conf (called by nginx for each server)
void *dav_next_create_loc_conf(ngx_conf_t *cf)
{
    dav_next_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(dav_next_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    // set by ngx_pcalloc():
    //
    //     conf->shm_zone = NULL;

    return conf;
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


// check and merge loc_conf
char *dav_next_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    dav_next_loc_conf_t       *conf = child;
    dav_next_loc_conf_t       *prev = parent;

    // get shared memory zone pointer if needed
    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    // not given, not our business
    if (conf->shm_zone == NULL) {
        return NGX_CONF_OK;
    }

    // get loc core module conf (to fetch `root` dir and backup `satisfy` policy)
    ngx_http_core_loc_conf_t  *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    conf->satisfy = clcf->satisfy;

    ngx_str_t test_dir;
    ngx_int_t rc;

    // `<root>/files`
    ngx_str_set(&test_dir, "files\0");
    rc = dav_next_get_full_name(cf->pool, &clcf->root, &test_dir);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_file_info_t fi;

    // this directory must exist
    if (ngx_file_info(test_dir.data, &fi) == NGX_FILE_ERROR) {
        ERROR_A(CRIT, cf->log, ngx_errno, " '%s' not found or not reachable!", test_dir.data);

        return NGX_CONF_ERROR;
    }

    // `<root>/uploads`
    ngx_str_set(&test_dir, "uploads\0");
    rc = dav_next_get_full_name(cf->pool, &clcf->root, &test_dir);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // this directory must exist too
    if (ngx_file_info(test_dir.data, &fi) == NGX_FILE_ERROR) {
        ERROR_A(CRIT, cf->log, ngx_errno, " '%s' not found or not reachable!", test_dir.data);

        return NGX_CONF_ERROR;
    }

    // force internal etag processing off (we manage it ourselves)
    clcf->etag = 0;

    return NGX_CONF_OK;
}


// process `dav_next_server_zone` configuration directive (in MAIN context)
// usage: `dav_next_server_zone zone=<zone_name>:<zone_size> timeout=<value>;` with mandatory `<zone_name>:<zone_size>`
// TODO: usage: `dav_next_server_zone name=<zone_name> size=<zone_size> timeout=<value>;` with mandatory `name=<zone_name>` and default size
char *dav_next_server_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // get args
    ngx_str_t *value = cf->args->elts;
    // to check later if arg was present
    ngx_str_t name;
    name.len = 0;

    time_t timeout = 60;
    ssize_t size = 0;

    // parse arg array
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {

        // look for a string starting with `zone=`
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            // extract value (zone name)
            name.data = value[i].data + 5;

            // look for the size
            u_char *p = (u_char *) ngx_strchr(name.data, ':');

            // no size no chocolate
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid zone size '%V'", &value[i]);
                return NGX_CONF_ERROR;
            }

            // set name length
            name.len = p - name.data;

            ngx_str_t s;
            // extract value (zone size)
            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            // parse it nginx size way
            size = ngx_parse_size(&s);

            // if wrong
            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid zone size '%V'", &value[i]);
                return NGX_CONF_ERROR;
            }

            // if too small
            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "zone '%V' is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue; // next!
        }

        // look for a string starting with `timeout=`
        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {

            ngx_str_t s;

            // extract value (lock timeout)
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            // parse it nginx time way
            timeout = ngx_parse_time(&s, 1);

            // if wrong
            if (timeout == (time_t) NGX_ERROR || timeout == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid lock timeout value '%V'", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue; // next!
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter '%V'", &value[i]);
        return NGX_CONF_ERROR;
    }

    // zone_name is mandatory
    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "'%V' must have 'zone' parameter", &cmd->name);
        return NGX_CONF_ERROR;
    }

    dav_next_lock_t *lock = ngx_pcalloc(cf->pool, sizeof(dav_next_lock_t));
    if (lock == NULL) {
        return NGX_CONF_ERROR;
    }

    lock->timeout = timeout;

    // reserve shared memory with that name and size
    ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &name, size, &dav_next_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    // check if already reserved
    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate zone '%V'", &name);
        return NGX_CONF_ERROR;
    }

    // shared memory init
    shm_zone->init = dav_next_init_zone;
    shm_zone->data = lock;

    return NGX_CONF_OK;
}


// process `dav_next_server` configuration directive (in SRV context)
// usage: `dav_next_server zone=<zone_name>;` with mandatory <zone_name>`
char *dav_next_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    dav_next_loc_conf_t  *dlcf = conf;

    // check if we already have seen this one in this server context
    if (dlcf->shm_zone) {
        return "is duplicate";
    }

    // get args
    ngx_str_t *value = cf->args->elts;
    ngx_shm_zone_t *shm_zone = NULL;

    // parse arg array
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {

        // look for a string starting with `zone=`
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            ngx_str_t s;

            // extract value (zone name)
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            // get shared memory with that name
            shm_zone = ngx_shared_memory_add(cf, &s, 0, &dav_next_module);
            // no memory no chocolate
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue; // next!
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter '%V'", &value[i]);
        return NGX_CONF_ERROR;
    }

    // check if the arg was correct and the named shared memory found
    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "'%V' must have 'zone' parameter", &cmd->name);
        return NGX_CONF_ERROR;
    }

    // remember it
    dlcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


// nginx module init (called after all configs are read)
ngx_int_t dav_next_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

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
