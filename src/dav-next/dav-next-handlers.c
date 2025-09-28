/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-handlers.c
 * Request handlers for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#include "dav-next.h"
#include "dav-next-handlers.h"
#include "dav-next-utils.h"
#include "dav-next-locks.h"
#include "dav-next-webdav.h"
#include "dav-next-module.h"
#include "dav-next-fileops.h"

// rewrite the given URI
// - remove the <user> part (we have already checked it is present)
// - check if in user in user (inception!)
// - check if in group in user (cached from previous call, or in LDAP attr list)
// - create user / group subdirectory if needed
// return the new URI or `null_uri` if failed
ngx_str_t dav_next_in_user_rewrite(ngx_http_request_t *r, dav_next_ctx_t *ctx, ngx_str_t uri)
{
    ngx_str_t null_uri = {
        .len = 0,
        .data = NULL
    };

    ngx_uint_t uri_user_offset;
    ngx_int_t path_offset;

    switch (ctx->uri_type) {
    case DAV_NEXT_URI_DAV_FILES:
        uri_user_offset = DAV_NEXT_URI_DAV_FILES_LEN - ctx->alias;
        path_offset = sizeof("files") - 1;
        break;
    case DAV_NEXT_URI_DAV_UPLOADS:
        uri_user_offset = DAV_NEXT_URI_DAV_UPLOADS_LEN - ctx->alias;
        path_offset = sizeof("uploads") - 1;
        break;
    default: // not relevant for other types, should not happen
        return null_uri;
    }

    ctx->in_group = 0;

    // prepare return URI
    ngx_str_t new_uri;
    new_uri.len = 1 + path_offset + 1 + uri.len - (uri_user_offset + r->headers_in.user.len + 1);
    u_char *p = new_uri.data = ngx_pnalloc(r->pool, new_uri.len);
    if (new_uri.data == NULL) {
        return null_uri;
    }

    DEBUG4(r->connection->log, 0, "REWRITE 1: uri=%V, len=%d, off=%d, user_len=%d", &uri, uri.len, uri_user_offset, r->headers_in.user.len);

    // copy the return URI without the first occurrence of /<user>/
    p = ngx_cpymem(p,
                   uri.data + uri_user_offset - (1 + path_offset + 1),
                   1 + path_offset);
    p = ngx_cpymem(p,
                   uri.data + uri_user_offset + r->headers_in.user.len,
                   uri.len - (uri_user_offset + r->headers_in.user.len));

    DEBUG4(r->connection->log, 0, "REWRITE 2: new_uri=%V, len=%d, off=%d, user_len=%d", &new_uri, new_uri.len, uri_user_offset, r->headers_in.user.len);

    // if the original URI was under /<user>/<user>/
    if (new_uri.len >= 1 + path_offset + 1 + r->headers_in.user.len &&
        ngx_strncmp(r->headers_in.user.data, new_uri.data + 1 + path_offset + 1, r->headers_in.user.len) == 0 &&
        (new_uri.len == 1 + path_offset + 1 + r->headers_in.user.len ||
         new_uri.data[1 + path_offset + 1 + r->headers_in.user.len] == '/')) {

        DEBUG0(r->connection->log, 0, "IN USER IN USER");

        // and if it was the root (= nothing after except a '/')
        if (new_uri.len == 1 + path_offset + 1 + r->headers_in.user.len ||
            (new_uri.len == 1 + path_offset + 1 + r->headers_in.user.len + 1 &&
             new_uri.data[1 + path_offset + 1 + r->headers_in.user.len] == '/')) {

            DEBUG0(r->connection->log, 0, "IS USER ROOT");

            // flag it as dav_root in case the client issues a GET
            ctx->is_dav_root = 1;
        }

        ctx->in_group = 1;

        // map URI to path to create user dir if needed
        ngx_str_t save_uri = r->uri;
        r->uri = new_uri;
        ngx_str_t path;
        size_t root;
        if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            r->uri = save_uri;
            return null_uri;
        }
        r->uri = save_uri;

        // remove anything after user root directory
        path.len = root + 1 + path_offset + 1 + r->headers_in.user.len;
        path.data[path.len] = '\0';

        DEBUG1(r->connection->log, 0, "DEBUG: path to CREATE_DIR=%V (user dir)", &path);
        // create the root dir, of fail silently if it already exists
        if (ngx_create_dir(path.data, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST) {
            ERROR(CRIT, r->connection->log, ngx_errno, "BUG: create user dir");
            return null_uri;
        }

        ctx->in_group = 1;

        return new_uri;

    }

    DEBUG1(r->connection->log, 0, "r = %p getting attrs", r);

    // check if we have access to the (patched) ngx_http_auth_ldap module through getter function
    if (auth_ldap_get_attributes == NULL) {
        DEBUG0(r->connection->log, 0, "attrs NOT FOUND? → no LDAP no GROUP");

        // if not, ignore LDAP groups and return bad news
        return null_uri;
    }

    // check if we have already fetched groups
    if (ctx->in_user.len && ctx->virtual_dir.nalloc) {
        for (ngx_uint_t i = 0; i < ctx->virtual_dir.nelts; i++) {
            ngx_str_t *group = &((ngx_str_t *) ctx->virtual_dir.elts)[i];

            DEBUG3(r->connection->log, 0, "TRYING (CACHED) %V %d/%d?", group, new_uri.len, path_offset + group->len);

            // if the original URI was under /<user>/<group>/
            if (new_uri.len >= 1 + path_offset + 1 + group->len &&
                ngx_strncmp(group->data, new_uri.data + 1 + path_offset + 1, group->len) == 0 &&
                (new_uri.len == 1 + path_offset + 1 + group->len ||
                 new_uri.data[1 + path_offset + 1 + group->len] == '/')) {

                // and if it was the root (= nothing after except a '/')
                if (new_uri.len == 1 + path_offset + 1 + group->len ||
                    (new_uri.len == 1 + path_offset + 1 + group->len + 1 &&
                     new_uri.data[1 + path_offset + 1 + group->len] == '/')) {

                    DEBUG1(r->connection->log, 0, "(CACHED) IS GROUP ROOT (%v)", group);

                    // do nothing for now?
                }

                // map URI to path to create group dir if needed
                ngx_str_t save_uri = r->uri;
                r->uri = new_uri;
                ngx_str_t path;
                size_t root;
                if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
                    r->uri = save_uri;
                    return null_uri;
                }
                r->uri = save_uri;

                // remove anything after group root directory
                path.len = root + 1 + path_offset + 1 + group->len;
                path.data[path.len] = '\0';

                DEBUG1(r->connection->log, 0, "DEBUG: path to CREATE_DIR=%V", &path);
                // create the root dir, of fail silently if it already exists
                if (ngx_create_dir(path.data, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST) {
                    ERROR(CRIT, r->connection->log, ngx_errno, "BUG: create user dir");
                    return null_uri;
                }

                ctx->in_group = 1;

                return new_uri;
            }
        }

        DEBUG2(r->connection->log, 0, "(CACHED) IS GROUP (%v) = %d", &new_uri, ctx->in_group);

        if (ctx->in_group) {
            return new_uri;
        } else {
            // if not found above, return bad news
            return null_uri;
        }
    }

    // prepare virtual dir array
    if (ngx_array_init(&ctx->virtual_dir, r->pool, 40, sizeof(ngx_str_t)) != NGX_OK) {
        return null_uri;
    }

    // get (patched) auth_ldap fetched attributes
    ngx_array_t *attrs = auth_ldap_get_attributes(r);
    DEBUG2(r->connection->log, 0, "r = %p, attrs = %p", r, attrs);

    if (attrs == NULL) {
        DEBUG1(r->connection->log, 0, "r = %p, attrs = NULL", r);
        return null_uri;
    }

    for (ngx_uint_t i = 0; i < attrs->nelts; i++) {
        ldap_search_attribute_t *elt = (ldap_search_attribute_t *) attrs->elts + i;

        DEBUG2(r->connection->log, 0, "%V: %V", &elt->attr_name, &elt->attr_value);

        // if not the attribute we are looking for
        // TODO: make the string "X-LDAP-ATTR-gid" constant or better, make a generic dav_next_strcmp(ngx_str, uchar *) function
        if (elt->attr_name.len != sizeof("X-LDAP-ATTR-gid") - 1 ||
            ngx_strncmp(elt->attr_name.data, "X-LDAP-ATTR-gid", sizeof("X-LDAP-ATTR-gid") - 1) != 0) {

            continue; // next!
        }

        // point to the beginning
        u_char *gid, *next_gid;
        gid = next_gid = elt->attr_value.data;

        do {
            // if there is a ',', then there is another gid after
            next_gid = (u_char *) ngx_strchr(gid, ',');

            // calc len according to the above
            size_t len;
            if (next_gid == NULL) {
                len = ngx_strlen(gid);
            } else {
                len = next_gid - gid;
            }

            // push onto the array
            ngx_str_t *group = ngx_array_push(&ctx->virtual_dir);
            if (group == NULL) {
                return null_uri;
            }

            // fill the group value
            group->len = len;
            group->data = gid;

            DEBUG3(r->connection->log, 0, "TRYING %V %d/%d?", group, new_uri.len, path_offset + len);

            // if the original URI was under /<user>/<group>/
            if (new_uri.len >= 1 + path_offset + 1 + len &&
               ngx_strncmp(gid, new_uri.data + 1 + path_offset + 1, len) == 0 &&
                (new_uri.len == 1 + path_offset + 1 + len || new_uri.data[1 + path_offset + 1 + len] == '/')) {

                // and if it was the root (= nothing after except a '/')
                if (new_uri.len == 1 + path_offset + 1 + len ||
                    (new_uri.len == 1 + path_offset + 1 + len + 1 && new_uri.data[1 + path_offset + 1 + len] == '/')) {

                    // flag it as dav_root in case the client issues a GET
                    ctx->is_dav_root = 1;
                    DEBUG1(r->connection->log, 0, "%V IS GROUP ROOT", group);
                }

                // map URI to path to create group dir if needed
                ngx_str_t save_uri = r->uri;
                r->uri = new_uri;
                ngx_str_t path;
                size_t root;
                if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
                    r->uri = save_uri;
                    return null_uri;
                }
                r->uri = save_uri;

                // remove anything after group root directory
                path.len = root + 1 + path_offset + 1 + len;
                path.data[path.len] = '\0';

                DEBUG1(r->connection->log, 0, "DEBUG: path to CREATE_DIR=%V", &path);
                // create the root dir, of fail silently if it already exists
                if (ngx_create_dir(path.data, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST) {
                    ERROR(CRIT, r->connection->log, ngx_errno, "BUG: create user dir");
                    return null_uri;
                }

                ctx->in_group = 1;
            }

            // point to next group, if any
            if (next_gid != NULL) {
                gid = next_gid + 1;
            }
        } while (next_gid != NULL); // no more, we're finished for this one
    }

    DEBUG1(r->connection->log, 0, "END %V", &new_uri);

    // found a group? return its new_uri, else bad news
    return ctx->in_group ? new_uri : null_uri;
}


// Access check macro
#define DAV_NEXT_ACCESS_USER_CHECK(debug_str)                   \
    if (ctx->access_needed) {                                   \
        if (dav_next_user_check(r, r->uri, 0) != NGX_OK) {      \
            return NGX_HTTP_FORBIDDEN;                          \
        }                                                       \
    }                                                           \
    DEBUG0(r->connection->log, 0, debug_str)

// check if URI is in user or group path
// sets:
//   ctx->is_virtual_root = if URI is virtual root of user
//   ctx->is_dav_root     = if URI is DAV root of user / group
//   ctx->in_user         = possibly rewritten URI (in group) or NULL if uri is not in user / group
// create user root directory if needed
ngx_int_t dav_next_user_check(ngx_http_request_t *r, ngx_str_t uri, ngx_int_t reset_flag)
{
    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    // no reset and already checked, return previous value
    if (!reset_flag && ctx->access_checked) {
        return ctx->access_checked_ret;
    }

    // reset return value
    ctx->access_checked_ret = NGX_ERROR;

    // not already checked, verify we have a user
    if (!ctx->access_checked) {
        ngx_int_t rc = ngx_http_auth_basic_user(r);
        ctx->access_checked = 1;

        if (rc != NGX_OK) {

            ERROR_A(CRIT, r->connection->log, 0, "DAV_NEXT BUG! no user / password was provided, rc=%d", rc);

            return NGX_ERROR; // default ctx->access_checked_ret value
        }
    }

    // if aliased
    if (ctx->alias != 0) {
        // offset current URI
        uri.data += ctx->alias;
        uri.len  -= ctx->alias;
    }

    ngx_uint_t uri_user_offset;
    ngx_int_t path_offset;

    // define user and path offsets according to URI type
    switch (ctx->uri_type) {
        case DAV_NEXT_URI_DAV_FILES:
            uri_user_offset = DAV_NEXT_URI_DAV_FILES_LEN - ctx->alias;
            path_offset = sizeof("files") - 1;
            break;
        case DAV_NEXT_URI_DAV_UPLOADS:
            uri_user_offset = DAV_NEXT_URI_DAV_UPLOADS_LEN - ctx->alias;
            path_offset = sizeof("uploads") - 1;
            break;
        default:
            return (ctx->access_checked_ret = NGX_OK); // not our business
    }

    DEBUG4(r->connection->log, 0, "DAV_NEXT DEBUG *: uri=%V, len=%d, off=%d, user_len=%d", &uri, uri.len, uri_user_offset, r->headers_in.user.len);
    DEBUG2(r->connection->log, 0, "DAV_NEXT DEBUG *: alias=%d, uri_type=%d", ctx->alias, ctx->uri_type);

    // (re-)set of flags + rewritten user / group URI
    ctx->is_virtual_root = 0;
    ctx->is_dav_root = 0;
    ctx->in_user.len = 0;
    ctx->in_user.data = NULL;

    // not in user path?
    if (uri.len < uri_user_offset + r->headers_in.user.len ||
        ngx_strncmp(r->headers_in.user.data,
                    uri.data + uri_user_offset,
                    r->headers_in.user.len) != 0) {

        DEBUG0(r->connection->log, 0, "NOT IN USER");

        return NGX_ERROR; // default ctx->access_checked_ret value
    }

    DEBUG0(r->connection->log, 0, "IN USER");

    ctx->in_user = uri;

    // virtual root? (= root of user)
    if (uri.len == uri_user_offset + r->headers_in.user.len ||
        (uri.len == uri_user_offset + r->headers_in.user.len + 1
         && uri.data[uri_user_offset + r->headers_in.user.len] == '/')) {

        if (ctx->webdav_rewritten != NULL) {
            ctx->is_dav_root = 1;
        }
        ctx->is_virtual_root = 1;

        DEBUG0(r->connection->log, 0, "IS VIRTUAL ROOT");
    }

    // map to path to create user dir if needed
    ngx_str_t save_uri = r->uri;
    r->uri = uri;
    ngx_str_t path;
    size_t root;
    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        r->uri = save_uri;
        return NGX_ERROR; // default ctx->access_checked_ret value
    }
    r->uri = save_uri;

    // get root of user dir
    path.len = root + 1 + path_offset + 1 + r->headers_in.user.len;
    path.data[path.len] = '\0';

    DEBUG1(r->connection->log, 0, "DEBUG: path to CREATE_DIR=%V", &path);
    // create the user dir and ignore if it already exists
    if (ngx_create_dir(path.data, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST) {
        ERROR(CRIT, r->connection->log, ngx_errno, "BUG: create user dir");
        return NGX_ERROR; // default ctx->access_checked_ret value
    }

    ngx_str_t new_uri = dav_next_in_user_rewrite(r, ctx, uri);

    DEBUG1(r->connection->log, 0, "new_uri.len: %d ======================", new_uri.len);

    if (new_uri.len) { // actually in a user / group directory, but do this only when no RESET = 1st time
        DEBUG1(r->connection->log, 0, "IN SUBROOT, so new_uri: %V ======================", &new_uri);

        ctx->in_user = new_uri;

        ctx->access_checked_ret = NGX_OK;
    } else if (ctx->is_virtual_root || (ctx->uri_type == DAV_NEXT_URI_DAV_UPLOADS && ctx->in_user.len)) {
        ctx->access_checked_ret = NGX_OK;
    }
    // }

    return ctx->access_checked_ret;
}


// nginx PREACCESS handler
ngx_int_t dav_next_preaccess_handler(ngx_http_request_t *r)
{
    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    // is this location under dav-next control? no shm_zone means "no"
    if (dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    // restore clcf->satisfy value in case it has been modified in a previous call (see below)
    ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    clcf->satisfy = dlcf->satisfy;

    return NGX_DECLINED;
}

// parse location
ngx_int_t dav_next_location_parser(ngx_http_request_t *r)
{
    dav_next_ctx_t  *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    // init URI related ctx fields
    ctx->uri_type = DAV_NEXT_URI_NONE;
    ctx->alias = 0;

    // user info
    if (r->uri.len == DAV_NEXT_URI_CLOUD_USER_LEN &&
        (ngx_strncmp(r->uri.data,
                     DAV_NEXT_URI_CLOUD_USER_STR,
                     DAV_NEXT_URI_CLOUD_USER_LEN) == 0 ||
         ngx_strncmp(r->uri.data,
                     DAV_NEXT_URI_CLOUD_USER_STR_2,
                     DAV_NEXT_URI_CLOUD_USER_LEN) == 0)) {

        ctx->uri_type = DAV_NEXT_URI_CLOUD_USER;
        ctx->access_needed = 1; // no user → no info

        return NGX_OK;
    }

    // server capabilities
    if (r->uri.len == DAV_NEXT_URI_CLOUD_CAPABILITIES_LEN &&
        (ngx_strncmp(r->uri.data,
                     DAV_NEXT_URI_CLOUD_CAPABILITIES_STR,
                     DAV_NEXT_URI_CLOUD_CAPABILITIES_LEN) == 0 ||
         ngx_strncmp(r->uri.data,
                     DAV_NEXT_URI_CLOUD_CAPABILITIES_STR_2,
                     DAV_NEXT_URI_CLOUD_CAPABILITIES_LEN) == 0)) {

        ctx->uri_type = DAV_NEXT_URI_CLOUD_CAPABILITIES;
        ctx->access_needed = 0;

        return NGX_OK;
    }

    // status
    if (r->uri.len == DAV_NEXT_URI_STATUS_LEN &&
        ngx_strncmp(r->uri.data,
                    DAV_NEXT_URI_STATUS_STR,
                    DAV_NEXT_URI_STATUS_LEN) == 0) {

        ctx->uri_type = DAV_NEXT_URI_STATUS;
        ctx->access_needed = 0;

        return NGX_OK;
    }

    // DAV_NEXT_URI_SLASH_LEN == 1 and DAV_NEXT_URI_SLASH_STR == "/"
    if (r->uri.len == 1 && r->uri.data[0] == '/') {

        ctx->uri_type = DAV_NEXT_URI_SLASH;
        ctx->access_needed = 1; // to say Basic Auth (instead of OAuth)

        return NGX_OK;
    }

    // DAV URI (for initial Android client check to "detect authentication method")
    //  request done without trailing '/' and we must return 401 for Basic Auth
    if (r->uri.len == DAV_NEXT_URI_DAV_LEN - 1 &&
        ngx_strncmp(r->uri.data,
                    DAV_NEXT_URI_DAV_STR,
                    DAV_NEXT_URI_DAV_LEN - 1 ) == 0) {

        ctx->uri_type = DAV_NEXT_URI_DAV;
        ctx->access_needed = 1;

        return NGX_OK;
    }

    // login flow v1
    if (r->uri.len == DAV_NEXT_URI_LOGIN_FLOW_LEN &&
        ngx_strncmp(r->uri.data,
                    DAV_NEXT_URI_LOGIN_FLOW_STR,
                    DAV_NEXT_URI_LOGIN_FLOW_LEN ) == 0) {

        ctx->uri_type = DAV_NEXT_URI_LOGIN_FLOW;
        ctx->access_needed = 0;

        return NGX_OK;
    }

    // WebDAV standard URI (for compatibility)
    //  early access may be done without trailing '/'
    if (r->uri.len >= DAV_NEXT_URI_WEBDAV_LEN - 1 &&
        ngx_strncmp(r->uri.data,
                    DAV_NEXT_URI_WEBDAV_STR,
                    DAV_NEXT_URI_WEBDAV_LEN - 1 ) == 0) {

        ctx->uri_type = DAV_NEXT_URI_WEBDAV;
        ctx->access_needed = 1;
        ctx->alias = DAV_NEXT_URI_WEBDAV_ALIAS_LEN;

        return NGX_OK;
    }

    // CONNECTIVITY_CHECK_ROUTE
    if (r->uri.len == DAV_NEXT_URI_CONNECTIVITY_CHECK_LEN &&
        ngx_strncmp(r->uri.data,
                    DAV_NEXT_URI_CONNECTIVITY_CHECK_STR,
                    DAV_NEXT_URI_CONNECTIVITY_CHECK_LEN) == 0) {

        ctx->uri_type = DAV_NEXT_URI_CONNECTIVITY_CHECK;
        ctx->access_needed = 0;

        return NGX_OK;
    }

    // main NC DAV URI
    if (r->uri.len >= DAV_NEXT_URI_DAV_FILES_LEN &&
        ngx_strncmp(r->uri.data,
                    DAV_NEXT_URI_DAV_FILES_STR,
                    DAV_NEXT_URI_DAV_FILES_LEN) == 0) {

        // delete password "bug"
        if (r->uri.len > DAV_NEXT_URI_DELETE_APPPASSWORD_LEN_1 + DAV_NEXT_URI_DELETE_APPPASSWORD_LEN_2 &&
            ngx_strncmp(r->uri.data,
                        DAV_NEXT_URI_DELETE_APPPASSWORD_STR_1,
                        DAV_NEXT_URI_DELETE_APPPASSWORD_LEN_1) == 0 &&
            ngx_strncmp(r->uri.data + r->uri.len - DAV_NEXT_URI_DELETE_APPPASSWORD_LEN_2,
                        DAV_NEXT_URI_DELETE_APPPASSWORD_STR_2,
                        DAV_NEXT_URI_DELETE_APPPASSWORD_LEN_2) == 0) {

            ctx->uri_type = DAV_NEXT_URI_DELETE_APPPASSWORD;
            // with username but no auth!
            ctx->access_needed = 0;

            return NGX_OK;
        }

        // normal NC DAV access
        ctx->uri_type = DAV_NEXT_URI_DAV_FILES;
        ctx->alias = DAV_NEXT_URI_DAV_ALIAS_LEN;
        ctx->access_needed = 1;

        return NGX_OK;
    }

    // NC upload NG DAV URI
    if (r->uri.len > DAV_NEXT_URI_DAV_UPLOADS_LEN &&
        ngx_strncmp(r->uri.data,
                    DAV_NEXT_URI_DAV_UPLOADS_STR,
                    DAV_NEXT_URI_DAV_UPLOADS_LEN) == 0) {

        ctx->uri_type = DAV_NEXT_URI_DAV_UPLOADS;
        ctx->alias = DAV_NEXT_URI_DAV_ALIAS_LEN;
        ctx->access_needed = 1;

        return NGX_OK;
    }

    // "free-style" URL
    ctx->uri_type = DAV_NEXT_URI_OTHER;
    ctx->access_needed = 1;

    return NGX_OK;
}


// simple checks for allowed methods per location
ngx_int_t
dav_next_location_checker(ngx_http_request_t *r)
{
    dav_next_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, dav_next_module);

    switch (ctx->uri_type) {
    case DAV_NEXT_URI_SLASH:
        if (r->method & (NGX_HTTP_GET | NGX_HTTP_PROPFIND)) {
            return NGX_OK;
        }
        break;
    case DAV_NEXT_URI_CLOUD_USER:
    case DAV_NEXT_URI_CLOUD_CAPABILITIES:
    case DAV_NEXT_URI_STATUS:
    case DAV_NEXT_URI_CONNECTIVITY_CHECK:
        if (r->method == NGX_HTTP_GET) {
            return NGX_OK;
        }
        break;
    case DAV_NEXT_URI_LOGIN_FLOW:
        if (r->method & (NGX_HTTP_GET    |
                         NGX_HTTP_POST)) {
            return NGX_OK;
        }
        break;
    case DAV_NEXT_URI_DELETE_APPPASSWORD:
        if (r->method == NGX_HTTP_DELETE) {
            return NGX_OK;
        }
        break;
    case DAV_NEXT_URI_DAV_FILES:
    case DAV_NEXT_URI_WEBDAV:
    case DAV_NEXT_URI_OTHER:
        if (r->method & (NGX_HTTP_GET      |
                         NGX_HTTP_HEAD     |
                         NGX_HTTP_MOVE     |
                         NGX_HTTP_COPY     |
                         NGX_HTTP_PUT      |
                         NGX_HTTP_DELETE   |
                         NGX_HTTP_MKCOL    |
                         NGX_HTTP_PROPFIND |
                         NGX_HTTP_LOCK     |
                         NGX_HTTP_UNLOCK)) {
            return NGX_OK;
        }
        break;
    case DAV_NEXT_URI_DAV_UPLOADS:
        if (r->method & (NGX_HTTP_GET     |
                         NGX_HTTP_HEAD    |
                         NGX_HTTP_MOVE    |
                         NGX_HTTP_PUT     |
                         NGX_HTTP_DELETE  |
                         NGX_HTTP_MKCOL)) {
            return NGX_OK;
        }
        break;
    case DAV_NEXT_URI_DAV:
        if (r->method == NGX_HTTP_HEAD) {
            return NGX_OK;
        }
    default:
        break;
    }

    return NGX_ERROR;
}


// nginx ACCESS handler
ngx_int_t dav_next_access_handler(ngx_http_request_t *r)
{
    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    // is this location under dav-next control? no shm_zone means "no"
    if (dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    // allocate and set our req context
    dav_next_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(dav_next_ctx_t));
    ngx_http_set_ctx(r, ctx, dav_next_module);
    ctx->access_checked = 0;

    // nothing to do for OPTIONS here
    if (r->method == NGX_HTTP_OPTIONS) {
        return NGX_DECLINED;
    }

    // parse location
    RETURN_RC_IF_NOK(dav_next_location_parser(r));

    // check location access rules
    if (dav_next_location_checker(r) != NGX_OK) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // check if must not be auth'ed
    if (ctx->access_needed == 0) {

        r->access_code = 0;
        if (r->headers_out.www_authenticate) {
            r->headers_out.www_authenticate->hash = 0;
        }

        // HACK:
        //  force `satisfy any;` in http core loc conf
        //  in order to unconditionally allow access
        ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        clcf->satisfy = NGX_HTTP_SATISFY_ANY;

        return NGX_OK;
    }

    // must be auth'ed, check if creds are provided
    ngx_int_t rc;
    if ((rc = ngx_http_auth_basic_user(r)) != NGX_OK) {
        if (r->headers_out.www_authenticate == NULL) {
            return NGX_DECLINED;
        }

        return NGX_HTTP_UNAUTHORIZED;
    }

    // security check: if auth'ed and DAV_NEXT_URI_DAV,
    //  no need to go further: 403
    if (ctx->uri_type == DAV_NEXT_URI_DAV) {
        return NGX_HTTP_FORBIDDEN;
    }

    // rewrite stuff
    RETURN_RC_IF_NOK(dav_next_webdav_rewrite(r, ctx));

    // if offset set in dav_next_location_parser() = r->uri is rewritten
    if (ctx->alias != 0) {

        ngx_str_t save_uri;

        if (ctx->webdav_rewritten != NULL) {
            save_uri = *ctx->webdav_rewritten;
        } else {
            save_uri = r->uri;
        }

        // save original request URI
        ctx->rewritten = ngx_pnalloc(r->pool, sizeof(*ctx->rewritten));
        RETURN_500_IF(ctx->rewritten == NULL);

        ctx->rewritten->data = ngx_pnalloc(r->pool, save_uri.len);
        RETURN_500_IF(ctx->rewritten->data == NULL);

        ctx->rewritten->len = save_uri.len;
        ngx_memcpy(ctx->rewritten->data, save_uri.data, save_uri.len);
    } else {
        // no rewrite needed
        ctx->rewritten = NULL;
    }

    return NGX_DECLINED;
}

// nginx PRECONTENT handler
ngx_int_t dav_next_precontent_handler(ngx_http_request_t *r)
{
    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    // is this location under dav-next control? no shm_zone means "no"
    if (dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    if (ctx->access_needed) {
        // check that the user can actually access

        ngx_int_t rc = dav_next_user_check(r, r->uri, 0);
        if (rc != NGX_OK && rc != NGX_ERROR) {
            return rc;
        }

        if (rc == NGX_ERROR) {
            return NGX_DECLINED;
        }
    } else {
        // HACK: restore `satisfy` in case it has been changed in access handler

        ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        clcf->satisfy = dlcf->satisfy;
    }

    ngx_str_t save_uri;

    // HACK: use URI routines on user URI
    if (ctx->in_user.len) {
        save_uri = r->uri;
        r->uri = ctx->in_user;
    }

    // check if resource locked for these methods
    //  and allow access if token is OK
    //  and delete lock too for DELETE & MOVE
    if (r->method & (NGX_HTTP_PUT|NGX_HTTP_DELETE|NGX_HTTP_MKCOL|NGX_HTTP_MOVE)) {
        ngx_uint_t delete_lock = (r->method & (NGX_HTTP_DELETE|NGX_HTTP_MOVE)) ? 1 : 0;

        ngx_int_t rc = dav_next_verify_lock(r, &r->uri, delete_lock);
        if (rc != NGX_OK) {
            if (ctx->in_user.len) {
                r->uri = save_uri;
            }

            return rc;
        }
    }

    // if MOVE or COPY, check header "destination"
    if (r->method & (NGX_HTTP_MOVE|NGX_HTTP_COPY)) {
        ngx_table_elt_t *dest = r->headers_in.destination;
        if (dest == NULL) {
            if (ctx->in_user.len) {
                r->uri = save_uri;
            }

            return NGX_DECLINED;
        }

        ngx_str_t uri = dest->value;

        // remove scheme:host from destination URI
        if (dav_next_strip_uri(r, &uri) != NGX_OK) {
            if (ctx->in_user.len) {
                r->uri = save_uri;
            }

            return NGX_DECLINED;
        }

        // check if destination resource is locked
        ngx_int_t rc = dav_next_verify_lock(r, &uri, 0);
        if (rc != NGX_OK) {
            if (ctx->in_user.len) {
                r->uri = save_uri;
            }

            return rc;
        }
    }

    // preparation of GET, we'll then decline to let nginx manage it
    if (r->method == NGX_HTTP_GET) {

        // should not happen
        if (r->headers_out.etag != NULL) {
            DEBUG0(r->connection->log, 0, "GET => etag != NULL");
            if (ctx->in_user.len) {
                r->uri = save_uri;
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_t path;
        size_t root;
        u_char *last = ngx_http_map_uri_to_path(r, &path, &root, 0);

        // restore URI if needed
        if (ctx->in_user.len) {
            r->uri = save_uri;
        }

        // no match = not our business
        if (last == NULL) {
            return NGX_DECLINED;
        }

        // match = read file info
        ngx_file_info_t fi;
        if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
            return NGX_DECLINED;
        }

        // HACK: OC-FileID = inode number in hex (see README.md)

        ngx_file_uniq_t id = ngx_file_uniq(&fi);

        ngx_table_elt_t *fileid = ngx_list_push(&r->headers_out.headers);
        RETURN_500_IF(fileid == NULL);

        fileid->hash = 1;
        ngx_str_set(&fileid->key, "OC-FileID");

        u_char *p = ngx_pnalloc(r->pool, 8 + DAV_NEXT_HEX_ID_LEN);
        RETURN_500_IF(p == NULL);

        ngx_sprintf(p, "00000001%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", id);

        fileid->value.len = 8 + DAV_NEXT_HEX_ID_LEN;
        fileid->value.data = p;

        // HACK: ETag = mtime in hex (see README.md)

        uint64_t mtime = ngx_dav_next_file_mtime(&fi);

        ngx_table_elt_t *etag = ngx_list_push(&r->headers_out.headers);
        RETURN_500_IF(etag == NULL);

        etag->hash = 1;
        ngx_str_set(&etag->key, "ETag");

        p = ngx_pnalloc(r->pool, DAV_NEXT_HEX_ID_LEN);
        RETURN_500_IF(p == NULL);

        ngx_sprintf(p, "%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", mtime);

        etag->value.len = DAV_NEXT_HEX_ID_LEN;
        etag->value.data = p;
        r->headers_out.etag = etag;

        DEBUG2(r->connection->log, 0, "GET %uxL => %uxL", id, mtime);
    } else {
        // restore URI if needed
        if (ctx->in_user.len) {
            r->uri = save_uri;
        }
    }

    // if GET or not / partially managed by dav-next, leave it to nginx
    return NGX_DECLINED;
}

// PUT handler
void dav_next_put_handler(ngx_http_request_t *r)
{
    // no body no PUT
    FINALIZE_500_IF(r->request_body == NULL);

    // no body in file = no PUT
    FINALIZE_500_IF(r->request_body->temp_file == NULL);

    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    ngx_str_t save_uri;

    // we're in user dir, temp replace URI with rewritten URI
    if (ctx->in_user.len) {
        save_uri = r->uri;
        r->uri = ctx->in_user;
    }

    // map URI to path
    ngx_str_t path;
    size_t root;
    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        r->uri = save_uri;
        ERROR(CRIT, r->connection->log, 0, "ngx_http_map_uri_to_path == ERROR");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    // put back saved URI (if any)
    r->uri = save_uri;

    path.len--; // remove final '\0'

    DEBUG1(r->connection->log, 0, "filename: '%s'", path.data);

    // get request body filename
    ngx_str_t *temp = &r->request_body->temp_file->file.name;

    ngx_file_info_t fi;
    ngx_uint_t status;
    uint64_t date_etag;

    // dest does not exists → creation
    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        status = NGX_HTTP_CREATED;

        date_etag = 0;
    } else { // else overwrite

        // unless it is a dir

        if (ngx_is_dir(&fi)) {
            ERROR_A(ERR, r->connection->log, NGX_EISDIR, "'%s' could not be created", path.data);

            // delete request body
            if (ngx_delete_file(temp->data) == NGX_FILE_ERROR) {
                ERROR_A(ALERT, r->connection->log, ngx_errno, ngx_delete_file_n " '%s' failed", temp->data);
            }

            ngx_http_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }

        status = NGX_HTTP_NO_CONTENT;

        // old file mtime / ETag
        date_etag = ngx_dav_next_file_mtime(&fi);
    }

    // fill ngx_ext_rename_file() ext struct
    ngx_ext_rename_file_t ext = {
        .time = -1,
        .access = 0600,
        .path_access = 0600,
        .create_path = 0,
        .delete_file = 1,
        .log = r->connection->log
    };

    // get new file mtime / ETag
    time_t date = dav_next_get_mtime(r);

    // if date (mtime) given in request, fill info to set it on renamed file
    if (date > 0) {
        ext.time = date;
        ext.fd = r->request_body->temp_file->file.fd;
    }

    // do the renaming
    FINALIZE_500_IF(ngx_ext_rename_file(temp, &path, &ext) != NGX_OK);

    // get new file info
    FINALIZE_500_IF(ngx_file_info(path.data, &fi) == NGX_FILE_ERROR);

    // duplicate path
    ngx_str_t cur_path = {
        .data = ngx_pstrdup(r->pool, &path),
        .len = path.len
    };

    // find parent dir
    while (cur_path.len > root && LAST_CHAR_OF(cur_path) != '/') {
         cur_path.len--;
    }
    cur_path.len--; // ignore final '/'

    // if both mtime are equal, increment new file (1ns should be harmless)
    if (date_etag > 0 && date > 0 && date_etag / 100000 == (uint64_t) date * 10000) {
        date_etag++;
        dav_next_set_file_time(path.data, date_etag);
    } else if (date > 0) { // if date given and no overwritten file
        date_etag = date * _1G; // set mtime / ETag (in ns)
    } else {
        date_etag = ngx_time() * _1G; // else current time
    }

    // update etags of directories up to root
    FINALIZE_500_IF(dav_next_update_etags(r, &cur_path, root, date_etag) != NGX_OK);

    // return new "ETag:" header

    u_char *p = ngx_pnalloc(r->pool, DAV_NEXT_HEX_ID_LEN);
    FINALIZE_500_IF(p == NULL);

    // hexified
    ngx_sprintf(p, "%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", date_etag);

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    FINALIZE_500_IF(h == NULL);
    h->hash = 1;
    ngx_str_set(&h->key, "ETag");
    h->value.len = DAV_NEXT_HEX_ID_LEN;
    h->value.data = p;
    r->headers_out.etag = h;

    // return OC-FileID (inode ID)

    ngx_file_uniq_t id = ngx_file_uniq(&fi);

    p = ngx_pnalloc(r->pool, 8 + DAV_NEXT_HEX_ID_LEN);
    FINALIZE_500_IF(p == NULL);

    // hexified
    ngx_sprintf(p, "00000001%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", id);

    h = ngx_list_push(&r->headers_out.headers);
    FINALIZE_500_IF(h == NULL);
    h->hash = 1;
    ngx_str_set(&h->key, "OC-FileID");
    h->value.len = 8 + DAV_NEXT_HEX_ID_LEN;
    h->value.data = p;

    // tell client we accepted the mtime

    h = ngx_list_push(&r->headers_out.headers);
    FINALIZE_500_IF(h == NULL);
    h->hash = 1;
    ngx_str_set(&h->key, "X-OC-MTime");
    ngx_str_set(&h->value, "accepted");

    DEBUG2(r->connection->log, 0, "PUT %uxL => %uxL", id, date_etag);

    // if it was a creation
    if (status == NGX_HTTP_CREATED) {
        // give URI in "Location:" header
        FINALIZE_500_IF(dav_next_location(r) != NGX_OK);

        // nothing more to say
        r->headers_out.content_length_n = 0;
    }

    r->headers_out.status = status;
    r->header_only = 1;

    ngx_http_finalize_request(r, dav_next_send_header(r));
}

// POST handler
void dav_next_post_handler(ngx_http_request_t *r)
{
    DEBUG0(r->connection->log, 0, "entering");

    off_t len = 0;

    // loop on request body

    ngx_str_t buf;
    buf.len = 0;

    // FIXME: we only process the last buffer
    for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        // body in file is not good
        FINALIZE_500_IF(b->in_file);

        // not for us
        if (ngx_buf_special(b)) {
            continue;
        }

        len += b->last - b->pos;

        // parse the current buf

        buf.len = len;
        buf.data = b->pos;
        DEBUG1(r->connection->log, 0, "buf=[%V]", &buf);
    }

    FINALIZE_500_IF(dav_next_nc_location(r, &buf) != NGX_OK);

    r->headers_out.content_length_n = 0;
    r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
    r->header_only = 1;

    ngx_http_finalize_request(r, dav_next_send_header(r));
}

// nginx CONTENT handler
ngx_int_t dav_next_content_handler(ngx_http_request_t *r)
{
    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    // this location is not for us
    if (dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);
    ngx_int_t rc;
    size_t b_len;
    ngx_file_info_t fi;
    ngx_str_t save_uri;

    switch (r->method) {

    case NGX_HTTP_POST:

        DAV_NEXT_ACCESS_USER_CHECK("POST");

        rc = ngx_http_read_client_request_body(r, dav_next_post_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_PROPFIND:

        DAV_NEXT_ACCESS_USER_CHECK("PROPFIND");

        // pass request body to PROPFIND handler
        rc = ngx_http_read_client_request_body(r, dav_next_propfind_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_OPTIONS:

        DEBUG0(r->connection->log, 0, "OPTIONS");

        // we don't need request body
        rc = ngx_http_discard_request_body(r);

        if (rc != NGX_OK) {
            return rc;
        }

        // add correct "DAV:" header to response

        ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
        RETURN_500_IF(h == NULL);

        ngx_str_set(&h->key, "DAV");

        // if we manage…
        if (dlcf->shm_zone) {
            h->value.len = 3;
            h->value.data = (u_char *) "1,2";
        }
        else { // or not
            h->value.len = 1;
            h->value.data = (u_char *) "1";
        }

        h->hash = 1;

        // add "Allow:" header to tell what verbs we manage

        h = ngx_list_push(&r->headers_out.headers);
        RETURN_500_IF(h == NULL);

        ngx_str_set(&h->key, "Allow");
        ngx_str_set(&h->value, "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,PROPFIND,OPTIONS,LOCK,UNLOCK");
        h->hash = 1;

        // everything is OK

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = 0;

        // send headers
        rc = dav_next_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        // and only headers in any case
        return ngx_http_send_special(r, NGX_HTTP_LAST);

    case NGX_HTTP_LOCK:

        DAV_NEXT_ACCESS_USER_CHECK("dav-next (CONTENT) LOCK");

        /*
         * Body is expected to carry the requested lock type, but
         * since we only support write/exclusive locks, we ignore it.
         * Ideally we could throw an error if a lock of another type
         * is requested, but the amount of work required for that is
         * not worth it.
         */

        // we don't need request body
        rc = ngx_http_discard_request_body(r);

        if (rc != NGX_OK) {
            return rc;
        }

        // manage LOCK
        return dav_next_lock_handler(r);

    case NGX_HTTP_UNLOCK:

        DAV_NEXT_ACCESS_USER_CHECK("dav-next (CONTENT) UNLOCK");

        // we don't need request body
        rc = ngx_http_discard_request_body(r);

        if (rc != NGX_OK) {
            return rc;
        }

        // manage UNLOCK
        return dav_next_unlock_handler(r);

    case NGX_HTTP_MOVE:
    case NGX_HTTP_COPY:

        DAV_NEXT_ACCESS_USER_CHECK("dav-next (CONTENT) COPY / MOVE");

        // manage COPY or MOVE
        return dav_next_copy_move_handler(r, dlcf);

    case NGX_HTTP_PUT:

        DAV_NEXT_ACCESS_USER_CHECK("dav-next (CONTENT) PUT");

        // sanity check: ending '/' is a collection
        if (LAST_CHAR_OF(r->uri) == '/') {
            ERROR(ERR, r->connection->log, 0, "cannot PUT to a collection");
            return NGX_HTTP_CONFLICT;
        }

        // TODO: ranges
        if (r->headers_in.content_range) {
            ERROR(ERR, r->connection->log, 0, "PUT with range is unsupported");
            return NGX_HTTP_NOT_IMPLEMENTED;
        }

        // prepare request fields for management of PUT verb
        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        // process request body through PUT handler
        rc = ngx_http_read_client_request_body(r, dav_next_put_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_DELETE:

        // HACK: NextCloud bug? Only with Basic Auth?
        if (ctx->uri_type == DAV_NEXT_URI_DELETE_APPPASSWORD) {
            return NGX_HTTP_NO_CONTENT;
        }

        /* fall through */

    case NGX_HTTP_MKCOL:

        DAV_NEXT_ACCESS_USER_CHECK("dav-next (CONTENT) DELETE / MKCOL");

        // if in user, get original URI
        save_uri = r->uri;
        if (ctx->in_user.len) {
            r->uri = ctx->in_user;
        }

        // get mapped path
        ngx_str_t path;
        size_t root;
        u_char *last = ngx_http_map_uri_to_path(r, &path, &root, 0);
        if (last == NULL) {
            r->uri = save_uri;
            ERROR(CRIT, r->connection->log, 0, "first last == NULL");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // get back (possibly) rewritten URI
        r->uri = save_uri;

        ngx_str_t path_update = path;

        // avoid potential last '/'
        if (LAST_CHAR_OF(path_update) == '/') {
            --path_update.len;
        }

        // find previous '/' (or root)
        while (path_update.len > root && LAST_CHAR_OF(path_update) != '/') {
            --path_update.len;
        }

        // no request body allowed
        if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
            ERROR(ERR, r->connection->log, 0, "MKCOL / DELETE with body is unsupported");
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        // truncate last '/' if any
        if (LAST_CHAR_OF(r->uri) == '/') {
            *(last - 1) = '\0';
        }

        DEBUG1(r->connection->log, 0, "MKCOL / DELETE path: '%s'", path.data);

        // update etags of directories up to root
        RETURN_500_IF(dav_next_update_etags(r, &path_update, root, ngx_time() * _1G) != NGX_OK);

        rc = NGX_ERROR;

        // MKCOL here
        if (r->method == NGX_HTTP_MKCOL) {
            // try to create the directory (collection)
            if (ngx_create_dir(path.data, ngx_dir_access(0770)) == NGX_FILE_ERROR) {
                return dav_next_error(r->connection->log, ngx_errno, NGX_HTTP_CONFLICT, ngx_create_dir_n, path.data);
            }

            // set "Location:" header to r->uri
            RETURN_500_IF(dav_next_location(r) != NGX_OK);

            // get newly created dir infos
            RETURN_500_IF(ngx_file_info(path.data, &fi) == NGX_FILE_ERROR);

            // OC-FileID (actually the inode ID)

            ngx_file_uniq_t id = ngx_file_uniq(&fi);

            u_char *p = ngx_pnalloc(r->pool, 8 + DAV_NEXT_HEX_ID_LEN);
            RETURN_500_IF(p == NULL);

            // hexify it
            ngx_sprintf(p, "00000001%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", id);

            h = ngx_list_push(&r->headers_out.headers);
            RETURN_500_IF(h == NULL);
            h->hash = 1;
            ngx_str_set(&h->key, "OC-FileID");
            h->value.len = 8 + DAV_NEXT_HEX_ID_LEN;
            h->value.data = p;

            rc = NGX_HTTP_CREATED;
        } else { // DELETE here
            if (ctx->is_virtual_root || ctx->is_dav_root) {
                return NGX_HTTP_FORBIDDEN;
            }

            // stat on path, do not follow links
            if (ngx_link_info(path.data, &fi) == NGX_FILE_ERROR) {
                // ENOTDIR == wrong path == special HTTP code
                rc = (ngx_errno == NGX_ENOTDIR) ? NGX_HTTP_CONFLICT : NGX_HTTP_NOT_FOUND;

                return dav_next_error(r->connection->log, ngx_errno, rc, ngx_link_info_n, path.data);
            }

            ngx_int_t dir;

            // leaf is a dir
            if (ngx_is_dir(&fi)) {

                // omit final '\0'
                --path.len;

                // remove any final '/'
                if (LAST_CHAR_OF(r->uri) == '/') {
                    --path.len;
                }

                // depth, if present, must be infinity (what else?)
                ngx_int_t depth = dav_next_depth(r, DAV_NEXT_INFINITY_DEPTH);

                if (depth != DAV_NEXT_INFINITY_DEPTH) {
                    ERROR(ERR, r->connection->log, 0, "'Depth' header must be infinity");
                    return NGX_HTTP_BAD_REQUEST;
                }

                dir = 1;

            } else { // not a dir

                // depth, if present (default to 0), must be 0 or infinity (what else?)
                ngx_int_t depth = dav_next_depth(r, 0);

                if (depth != 0 && depth != DAV_NEXT_INFINITY_DEPTH) {
                    ERROR(ERR, r->connection->log, 0, "'Depth' header must be 0 or infinity");
                    return NGX_HTTP_BAD_REQUEST;
                }

                dir = 0;
            }

            // do delete
            rc = dav_next_delete_path(r, &path, dir);

            if (rc == NGX_OK) {
                return NGX_HTTP_NO_CONTENT;
            }
        }

        return rc;

    case NGX_HTTP_HEAD:

        // if we're not in DAV directory, let other handlers do the job
        if (ctx->uri_type != DAV_NEXT_URI_DAV_FILES) {
            return NGX_DECLINED;
        }

        DAV_NEXT_ACCESS_USER_CHECK("dav-next (CONTENT) HEAD");

        // if in user directory (should always be the case)
        if (ctx->in_user.len) {
            // temp URI to original value
            save_uri = r->uri;
            r->uri = ctx->in_user;

            // get this URI mapped path
            ngx_str_t path;
            size_t root;
            if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
                r->uri = save_uri;
                ERROR(ERR, r->connection->log, 0, "ngx_http_map_uri_to_path == ERROR");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            // put back saved URI
            r->uri = save_uri;

            if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
                // resource does not exist
                return NGX_HTTP_NOT_FOUND;
            }

            // it's OK
            r->headers_out.status = NGX_HTTP_OK;

            // give "Content-Length:" only if not a dir
            if (!ngx_is_dir(&fi)) {
                r->headers_out.content_length_n = ngx_file_size(&fi);
            }
            r->header_only = 1;

            return dav_next_send_header(r);
        }

        // BUG if this is reached
        ERROR(CRIT, r->connection->log, 0, "DAV_NEXT internal HEAD BUG!");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    case NGX_HTTP_GET:

        DAV_NEXT_ACCESS_USER_CHECK("GET");

        // prepare response body length according to the URI

        switch (ctx->uri_type) {
        case DAV_NEXT_URI_CLOUD_USER:
            b_len = DAV_NEXT_CONTENT_CLOUD_USER_LEN + r->headers_in.user.len * 2;
            break;
        case DAV_NEXT_URI_CLOUD_CAPABILITIES:
            b_len = DAV_NEXT_CONTENT_CLOUD_CAPABILITIES_LEN;
            break;
        case DAV_NEXT_URI_SLASH:
        case DAV_NEXT_URI_CONNECTIVITY_CHECK:
            b_len = 0;
            r->header_only = 1;
            break;
        case DAV_NEXT_URI_LOGIN_FLOW:
            b_len = DAV_NEXT_CONTENT_LOGIN_FLOW_LEN;
            break;
        case DAV_NEXT_URI_STATUS:
            b_len = DAV_NEXT_CONTENT_STATUS_LEN;
            break;
        case DAV_NEXT_URI_DAV_FILES:
            // test if URI is the dav root
            if (ctx->is_dav_root) {
                b_len = DAV_NEXT_CONTENT_INDEX_LEN;
                break;
            }

            DEBUG1(r->connection->log, 0, "GET DAV_FILES, r->uri = %V", &r->uri);
            if (ctx->in_user.len) {
                // rewrite the current URI
                r->uri = ctx->in_user;
                DEBUG1(r->connection->log, 0, "GET DAV_FILES, r->uri now = %V", &r->uri);
            }

            // let nginx handler manage this case

            return NGX_DECLINED;
        default:
            return NGX_DECLINED;
        }

        // create response buffer
        ngx_buf_t *b = ngx_create_temp_buf(r->pool, b_len);
        RETURN_500_IF(b == NULL);

        rc = NGX_HTTP_OK; // default status code

        // buffer = response body according to the URI
        switch (ctx->uri_type) {
        case DAV_NEXT_URI_CLOUD_USER:
            ngx_sprintf(b->start, DAV_NEXT_CONTENT_CLOUD_USER_STR, &r->headers_in.user, &r->headers_in.user);
            break;
        case DAV_NEXT_URI_CLOUD_CAPABILITIES:
            (void) ngx_cpymem(b->start,
                              DAV_NEXT_CONTENT_CLOUD_CAPABILITIES_STR,
                              DAV_NEXT_CONTENT_CLOUD_CAPABILITIES_LEN);
            break;
        case DAV_NEXT_URI_SLASH:
            break;
        case DAV_NEXT_URI_CONNECTIVITY_CHECK:
            rc = NGX_HTTP_NO_CONTENT;
            break;
        case DAV_NEXT_URI_LOGIN_FLOW:
            (void) ngx_cpymem(b->start,
                              DAV_NEXT_CONTENT_LOGIN_FLOW_STR,
                              DAV_NEXT_CONTENT_LOGIN_FLOW_LEN);
            break;
        case DAV_NEXT_URI_STATUS:
            (void) ngx_cpymem(b->start,
                              DAV_NEXT_CONTENT_STATUS_STR,
                              DAV_NEXT_CONTENT_STATUS_LEN);
            break;
        case DAV_NEXT_URI_DAV_FILES:
            // no need to test if URI is the DAV root (other cases are DECLINED)
            (void) ngx_cpymem(b->start,
                              DAV_NEXT_CONTENT_INDEX_STR,
                              DAV_NEXT_CONTENT_INDEX_LEN);
            break;
        default:
            return NGX_DECLINED;
        }

        b->last = b->pos + b_len;
        b->last_buf = 1;
        b->memory = 1;

        // set "Content-Length:" header
        r->headers_out.content_length_n = b_len;

        // XXX: in DAV we don't care about the "Content-Type:", so set text/plain
        if (ctx->uri_type == DAV_NEXT_URI_DAV_FILES) {
            // no need to test if URI is the DAV root
            r->headers_out.content_type_len = sizeof("text/plain") - 1;
            ngx_str_set(&r->headers_out.content_type, "text/plain");
        } else if (ctx->uri_type == DAV_NEXT_URI_LOGIN_FLOW) {
            r->headers_out.content_type_len = sizeof("text/html") - 1;
            ngx_str_set(&r->headers_out.content_type, "text/html");
        } else {
            // other cases → JSON
            r->headers_out.content_type_len = sizeof("application/json") - 1;
            ngx_str_set(&r->headers_out.content_type, "application/json");
        }

        // other header stuffs
        r->headers_out.content_type_lowcase = NULL;
        ngx_str_set(&r->headers_out.charset, "utf-8");

        r->headers_out.status = rc;

        // send the headers ourselves
        rc = dav_next_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        // if OK, then send the body too

        ngx_chain_t out = {
            .buf = b,
            .next = NULL
        };

        return ngx_http_output_filter(r, &out);
    }

    // not our business
    return NGX_DECLINED;
}
