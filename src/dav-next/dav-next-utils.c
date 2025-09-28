/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-utils.c
 * Utility functions for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#include "dav-next.h"
#include "dav-next-utils.h"

// HACK: like ngx_http_send_header(), but not if already sent
ngx_int_t dav_next_send_header(ngx_http_request_t *r)
{
    if (r->header_sent) {
        return NGX_OK;
    }

    return ngx_http_send_header(r);
}


// strip scheme://host:port part from an URI
ngx_int_t dav_next_strip_uri(ngx_http_request_t *r, ngx_str_t *uri)
{
    // if it starts with a '/': already stripped
    if (uri->data[0] == '/') {
        DEBUG1(r->connection->log, 0, "'%V' unchanged", uri);
        return NGX_OK;
    }

    size_t len = r->headers_in.server.len;

    // no "Host:" = too bad
    if (len == 0) {
        goto failed;
    }

    u_char *host;

#if (NGX_HTTP_SSL)

    // if in SSL mode
    if (r->connection->ssl) {
        // check if correct scheme
        if (ngx_strncmp(uri->data, "https://", sizeof("https://") - 1) != 0) {
            goto failed;
        }

        // point to host part
        host = uri->data + sizeof("https://") - 1;

    } else
#endif
    { // not in SSL mode

        // check if correct scheme
        if (ngx_strncmp(uri->data, "http://", sizeof("http://") - 1) != 0) {
            goto failed;
        }

        // point to host part
        host = uri->data + sizeof("http://") - 1;
    }

    // check if "Host:" header and host match
    if (ngx_strncmp(host, r->headers_in.server.data, len) != 0) {
        goto failed;
    }

    u_char *last = uri->data + uri->len;

    // lookup next '/'
    for (u_char *p = host + len; p != last; p++) {
        if (*p == '/') {
            DEBUG3(r->connection->log, 0, "'%V' '%*s'", uri, last - p, p);
            uri->data = p;
            uri->len = last - p;

            return NGX_OK;
        }
    }

failed:

    DEBUG1(r->connection->log, 0, "'%V' failed", uri);
    return NGX_DECLINED;
}


// parse "Depth:" header
ngx_int_t dav_next_depth(ngx_http_request_t *r, ngx_int_t dflt)
{
    ngx_table_elt_t *depth = r->headers_in.depth;

    // header not present, return default value
    if (depth == NULL) {
        return dflt;
    }

    // one char long
    if (depth->value.len == 1) {

        // 0 or 1, kinda atoi()

        if (depth->value.data[0] == '0') {
            return 0;
        }

        if (depth->value.data[0] == '1') {
            return 1;
        }

        // else: wrong character

    } else {

        // infinity (and beyond)
        if (depth->value.len == sizeof("infinity") - 1
            && ngx_strcmp(depth->value.data, "infinity") == 0)
        {
            return DAV_NEXT_INFINITY_DEPTH;
        }
    }

    ERROR_A(ERR, r->connection->log, 0, "client sent invalid 'Depth' header: '%V'", &depth->value);

    return NGX_ERROR;
}


// update ETag (= mtime) of dirs up to root
ngx_int_t dav_next_update_etags(ngx_http_request_t *r, ngx_str_t *orig_path, size_t root, uint64_t mtime)
{
    ngx_str_t        path;

    // dup orig_path
    path.data = ngx_pstrdup(r->pool, orig_path);
    path.len = orig_path->len;

    // while not root
    while (path.len > root) {
        // look for previous '/'
        for (--path.len;
             path.len > root && LAST_CHAR_OF(path) != '/';
             --path.len) {
            /* void */
        }
        --path.len; // one char before '/'

        path.data[path.len] = '\0'; // overwrite '/' with '\0'

        ngx_file_info_t  fi;

        // get path info
        RETURN_500_IF(ngx_file_info(path.data, &fi) == NGX_FILE_ERROR);

        // get its current mtime
        uint64_t cur_mtime = ngx_dav_next_file_mtime(&fi);

        // uh oh, same time, let's increment it by 100µs
        if (cur_mtime / 100000 == mtime / 100000) { /* 10000 groups allowed */
            cur_mtime++;
        } else { // otherwise set it
            cur_mtime = mtime;
        }

        // set new mtime on file
        if (dav_next_set_file_time(path.data, cur_mtime) != NGX_OK) {
            ERROR_A(ALERT, r->connection->log, ngx_errno, "update (%s, %uL) => ERROR", path.data, cur_mtime);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


// parse mtime header
time_t dav_next_get_mtime(ngx_http_request_t *r)
{
    u_char name[] = "x-oc-mtime";

    // loop on headers

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;

    for (ngx_uint_t i = 0; /* void */ ; i++) {

        // end of array
        if (i >= part->nelts) {
            // end of list?
            if (part->next == NULL) {
                break;
            }

            // no, go to next
            part = part->next;
            header = part->elts;

            i = 0; // and restart counter
        }

        // if not same length, then not equal
        if (header[i].key.len != sizeof(name) - 1)
            continue;

        ngx_uint_t n;

        // fast strcasecmp() for header name
        for (n = 0; n < sizeof(name) - 1 && n < header[i].key.len; n++) {
            u_char ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;
            }

            if (name[n] != ch) {
                break;
            }
        }

        // if header correct, do ascii to int parsing on header value
        if (n == sizeof(name) - 1 && n == header[i].key.len) {
            return (time_t) ngx_atoi(header[i].value.data, header[i].value.len);
        }
    }

    return 0;
}


// set "Location:" response header to r->uri
ngx_int_t dav_next_location(ngx_http_request_t *r)
{
    // alloc header
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");

    // fake escape(URI) to get number of escaped chars
    uintptr_t escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len, NGX_ESCAPE_URI);

    // if there are some
    if (escape) {
        // get new length
        size_t len = r->uri.len + escape;

        // alloc it
        u_char *p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            ngx_http_clear_location(r);
            return NGX_ERROR;
        }

        // prepare header
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = p;

        // escape URI in it
        ngx_escape_uri(p, r->uri.data, r->uri.len, NGX_ESCAPE_URI);

    } else { // no escape!
        r->headers_out.location->value = r->uri;
    }

    return NGX_OK;
}


ngx_int_t dav_next_nc_location(ngx_http_request_t *r, ngx_str_t *buf)
{
    size_t len = sizeof("nc://login/server:") - 1 + sizeof("&user:") - 1 + sizeof("&password:") - 1;

    // alloc header
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_ERROR;
    }

    ngx_str_t user;
    user.data = NULL;
    user.len = 0;

    ngx_str_t pass;
    pass.data = NULL;
    pass.len = 0;

    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");

    // parse POST data
    size_t d;
    u_char *p;
    for (d = 0, p = buf->data; d < buf->len; d++, p++) {
        if (buf->len >= d + sizeof("username=") &&
            ngx_strncmp(p, "username=", sizeof("username=") - 1) == 0) {

            p += sizeof("username=") - 1;
            user.data = p;
            user.len = 0;

            while (d <= buf->len && *p != '&') {
                d++;
                p++;
                user.len++;
            }

            continue;
        }

        if (buf->len >= d + sizeof("password=") &&
            ngx_strncmp(p, "password=", sizeof("password=") - 1) == 0) {

            p += sizeof("password=") - 1;
            pass.data = p;
            pass.len = 0;

            while (d <= buf->len && *p != '&') {
                d++;
                p++;
                pass.len++;
            }

            continue;
        }
    }

    len += r->headers_in.server.len + user.len + pass.len;

    // alloc it
    p = ngx_pnalloc(r->pool, len + 1); // + 1 for '\0'
    if (p == NULL) {
        ngx_http_clear_location(r);
        return NGX_ERROR;
    }

    // prepare header
    r->headers_out.location->value.len = len;
    r->headers_out.location->value.data = p;

    p = ngx_cpymem(p, "nc://login/server:", sizeof("nc://login/server:") - 1);
    p = ngx_cpymem(p, r->headers_in.server.data, r->headers_in.server.len);
    p = ngx_cpymem(p, "&user:", sizeof("&user:") - 1);
    p = ngx_cpymem(p, user.data, user.len);
    p = ngx_cpymem(p, "&password:", sizeof("&password:") - 1);
    p = ngx_cpymem(p, pass.data, pass.len);
    *p = '\0';

    DEBUG1(r->connection->log, 0, "Location: '%V'", &r->headers_out.location->value);

    return NGX_OK;
}


// get quota info
// TODO: for now, filesystem sizes, not real quotas
ngx_int_t dav_next_fs_get_quota(u_char *name, off_t *used, off_t *avail)
{
    struct statvfs fs;

    if (statvfs((char *) name, &fs) == -1) {
        return NGX_ERROR;
    }

    *used  = (off_t) (fs.f_blocks - fs.f_bfree) * fs.f_frsize;
    *avail = (off_t) fs.f_bfree * fs.f_frsize;

    return NGX_OK;
}


// update file atime (to now) and mtime (in ns)
ngx_int_t dav_next_set_file_time(u_char *name, uint64_t ns)
{
    struct timeval tv[2];

    tv[0].tv_sec = ngx_time();
    tv[0].tv_usec = 0;
    tv[1].tv_sec = ns / _1G;
    tv[1].tv_usec = ns % _1G / 1000;

    if (utimes((char *) name, tv) != -1) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


// log and return error statuses according to ngx_errno
ngx_int_t dav_next_error(ngx_log_t *log, ngx_err_t err, ngx_int_t not_found, char *failed, u_char *path)
{
    ngx_uint_t level;
    ngx_int_t rc;

    if (err == NGX_ENOENT || err == NGX_ENOTDIR || err == NGX_ENAMETOOLONG) {
        level = NGX_LOG_ERR;
        rc = not_found;

    } else if (err == NGX_EACCES || err == NGX_EPERM) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_FORBIDDEN;

    } else if (err == NGX_EEXIST) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_NOT_ALLOWED;

    } else if (err == NGX_ENOSPC) {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INSUFFICIENT_STORAGE;

    } else {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(level, log, err, "%s:%d: %s '%s' failed", __FUNCTION__, __LINE__, failed, path);

    return rc;
}
