/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-fileops.c
 * File operations for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#include "dav-next.h"
#include "dav-next-fileops.h"
#include "dav-next-utils.h"
#include "dav-next-handlers.h"
#include "dav-next-webdav.h"

// copy context struct (for ngx_walk_tree())
typedef struct {
    ngx_str_t path;
    size_t    len;
} dav_next_copy_ctx_t;

// delete a path and, if a dir, all files / dirs below
ngx_int_t dav_next_delete_path(ngx_http_request_t *r, ngx_str_t *path, ngx_uint_t dir)
{
    char *failed;

    // is it a dir?
    if (dir) {
        ngx_tree_ctx_t tree = {
            .init_handler = NULL,
            .file_handler = dav_next_delete_file,
            .pre_tree_handler = dav_next_noop,
            .post_tree_handler = dav_next_delete_dir,
            .spec_handler = dav_next_delete_file,
            .data = NULL,
            .alloc = 0,
            .log = r->connection->log
        };

        // TODO: 207?

        // delete all that's under the dir
        RETURN_500_IF(ngx_walk_tree(&tree, path) != NGX_OK);

        // then delete dir
        if (ngx_delete_dir(path->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        failed = ngx_delete_dir_n;

    } else { // it's a file

        if (ngx_delete_file(path->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        failed = ngx_delete_file_n;
    }

    return dav_next_error(r->connection->log, ngx_errno, NGX_HTTP_NOT_FOUND, failed, path->data);
}


// delete dir handler for some ngx_walk_tree() operations
ngx_int_t dav_next_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    DEBUG1(ctx->log, 0, "deleting dir '%V'", path);

    if (ngx_delete_dir(path->data) == NGX_FILE_ERROR) {

        // TODO: add to 207

        (void) dav_next_error(ctx->log, ngx_errno, 0, ngx_delete_dir_n, path->data);
    }

    return NGX_OK;
}


// delete file handler for some ngx_walk_tree() operations
ngx_int_t dav_next_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    DEBUG1(ctx->log, 0, "deleting '%V'", path);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {

        // TODO: add to 207

        (void) dav_next_error(ctx->log, ngx_errno, 0, ngx_delete_file_n, path->data);
    }

    return NGX_OK;
}


// NO OP handler for some ngx_walk_tree() operations
ngx_int_t dav_next_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}


// modified version of ngx_copy_file() to append a file to another
ngx_int_t dav_next_append_file(ngx_http_request_t *r, u_char *from, u_char *to, ngx_uint_t first)
{
    ngx_int_t rc = NGX_ERROR;
    char *buf = NULL;
    ngx_fd_t nfd = NGX_INVALID_FILE;

    // get info of "from" file to get size
    ngx_file_info_t fi;
    RETURN_500_IF(ngx_file_info(from, &fi) == NGX_FILE_ERROR);

    // open the "from" file to read
    ngx_fd_t fd = ngx_open_file(from, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ERROR_A(CRIT, r->connection->log, ngx_errno, ngx_open_file_n " '%s' failed", from);
        goto failed;
    }

    // buffer size is 64k
    size_t len = 65536;
    off_t size = ngx_file_size(&fi);

    // adjust buffer size if file size is smaller
    if ((off_t) len > size) {
        len = (size_t) size;
    }

    // allocate buffer
    buf = ngx_alloc(len, r->connection->log);
    if (buf == NULL) {
        goto failed;
    }

    // first file to open = TRUNCATE
    if (first) {
        nfd = ngx_open_file(to, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, ngx_file_access(&fi));
    } else { // or else APPEND
        nfd = ngx_open_file(to, NGX_FILE_APPEND, 0, ngx_file_access(&fi));
    }

    if (nfd == NGX_INVALID_FILE) {
        ERROR_A(CRIT, r->connection->log, ngx_errno, ngx_open_file_n " '%s' failed", to);
        goto failed;
    }

    DEBUG1(r->connection->log, 0, " ------------ APPENDING '%s'", from);

    // while there is something to copy
    while (size > 0) {

        // read size = buffer size or less for remaining size
        if ((off_t) len > size) {
            len = (size_t) size;
        }

        // read data
        ssize_t n = ngx_read_fd(fd, buf, len);

        if (n < 0) {
            ERROR_A(ALERT, r->connection->log, ngx_errno, ngx_read_fd_n " '%s' failed", from);
            goto failed;
        }

        if ((size_t) n != len) {
            ERROR_A(ALERT, r->connection->log, 0, ngx_read_fd_n " has read only %z of %O from %s", n, size, from);
            goto failed;
        }

        // then write them to "to" file
        n = ngx_write_fd(nfd, buf, len);

        if (n < 0) {
            ERROR_A(ALERT, r->connection->log, ngx_errno, ngx_write_fd_n " '%s' failed", to);
            goto failed;
        }

        if ((size_t) n != len) {
            ERROR_A(ALERT, r->connection->log, 0, ngx_write_fd_n " has written only %z of %O to %s", n, size, to);
            goto failed;
        }

        // subtract read / written size
        size -= n;
    }

    rc = NGX_OK;

failed:

    // close "to" file if opened
    if (nfd != NGX_INVALID_FILE) {
        if (ngx_close_file(nfd) == NGX_FILE_ERROR) {
            ERROR_A(ALERT, r->connection->log, ngx_errno, ngx_close_file_n " '%s' failed", to);
        }
    }

    if (buf) {
        ngx_free(buf);
    }

    // close "from" file if opened
    if (fd != NGX_INVALID_FILE) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ERROR_A(ALERT, r->connection->log, ngx_errno, ngx_close_file_n " '%s' failed", from);
        }
    }

    return rc;
}


// callback of ngx_qsort(chunk_entries.elts)
int ngx_libc_cdecl dav_next_cmp_chunk_entries(const void *one, const void *two)
{
    dav_next_chunk_entry_t *first = (dav_next_chunk_entry_t *) one;
    dav_next_chunk_entry_t *second = (dav_next_chunk_entry_t *) two;

    // comparison based on string in structs
    return (int) ngx_strcmp(first->data, second->data);
}


// COPY / MOVE handlers
ngx_int_t dav_next_copy_move_handler(ngx_http_request_t *r, dav_next_loc_conf_t *dlcf)
{
    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    // no body
    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        ERROR(ERR, r->connection->log, 0, "COPY and MOVE with body are unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    // get dest URI

    ngx_table_elt_t *dest_elt = r->headers_in.destination;

    if (dest_elt == NULL) {
        ERROR(ERR, r->connection->log, 0, "client sent no 'Destination' header");
        return NGX_HTTP_BAD_REQUEST;
    }

    u_char *p = dest_elt->value.data;
    u_char *last;
    if (p[0] == '/') { // there is always '\0' even after empty header value
        last = p + dest_elt->value.len;
        goto destination_done;
    }

    // get "Host:" header len
    size_t len = r->headers_in.server.len;

    if (len == 0) {
        ERROR(ERR, r->connection->log, 0, "client sent no 'Host' header");
        return NGX_HTTP_BAD_REQUEST;
    }

    u_char *p_goa, *host;

#if (NGX_HTTP_SSL)

    // SSL scheme
    if (r->connection->ssl) {
        // sanity check
        if (ngx_strncmp(dest_elt->value.data, "https://", sizeof("https://") - 1) != 0) {
            goto invalid_destination;
        }

        // get ptr to hostname
        p_goa = host = dest_elt->value.data + sizeof("https://") - 1;

    } else
#endif
    { // SSL or no SSL scheme (in case of TLS termination in reverse proxy)

        // check if correct scheme
        if (ngx_strncmp(dest_elt->value.data, "http://", sizeof("http://") - 1) != 0) {
            if (ngx_strncmp(dest_elt->value.data, "https://", sizeof("https://") - 1) != 0) {
                goto invalid_destination;
            }
            // get ptr to hostname
            p_goa = host = dest_elt->value.data + sizeof("https://") - 1;
        } else {
            // get ptr to hostname
            p_goa = host = dest_elt->value.data + sizeof("http://") - 1;
        }
    }

    // Workaround bug in some GOA that sends "username@host" instead of "host" in "Destination:" header
    while (*p_goa && *p_goa != '/' && *p_goa != '@') {
        p_goa++;
    }

    if (*p_goa == '@') {
        host = p_goa + 1;
    }

    // check host is same on source and destination
    if (ngx_strncmp(host, r->headers_in.server.data, len) != 0) {
        ERROR_A(ERR, r->connection->log, 0, "'Destination' URI '%V' is handled by different repository than the source URI", &dest_elt->value);
        return NGX_HTTP_BAD_REQUEST;
    }

    // get dest URI
    last = dest_elt->value.data + dest_elt->value.len;

    // it is first '/' after host
    for (p = host + len; p < last; p++) {
        if (*p == '/') {
            goto destination_done;
        }
    }

invalid_destination:

    ERROR_A(ERR, r->connection->log, 0, "client sent invalid 'Destination' header: '%V'", &dest_elt->value);
    return NGX_HTTP_BAD_REQUEST;

destination_done:

    ngx_str_t duri = {
        .len = last - p,
        .data = p
    };
    ngx_str_t args;
    ngx_uint_t flags = NGX_HTTP_LOG_UNSAFE;

    // check / parse dest URI
    if (ngx_http_parse_unsafe_uri(r, &duri, &args, &flags) != NGX_OK) {
        goto invalid_destination;
    }

    // fix NC client not ending a dest dir with a slash:
    //   remove all final slashes
    if (LAST_CHAR_OF(r->uri) == '/') {
        r->uri.data[--r->uri.len] = '\0';
    }
    if (*(last - 1) == '/') {
        duri.data[--duri.len] = '\0';
    }

    // check "Depth:" header
    ngx_int_t depth = dav_next_depth(r, DAV_NEXT_INFINITY_DEPTH);

    if (depth != DAV_NEXT_INFINITY_DEPTH) {

        // COPY requires infinity or 0
        if (r->method == NGX_HTTP_COPY) {
            if (depth != 0) {
                ERROR(ERR, r->connection->log, 0, "'Depth' header must be 0 or infinity");
                return NGX_HTTP_BAD_REQUEST;
            }

        // MOVE requires infinity only
        } else {
            ERROR(ERR, r->connection->log, 0, "'Depth' header must be infinity");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    // can we overwrite dest if it exists?
    // overwrite by default
    ngx_uint_t overwrite = 1;

    ngx_table_elt_t *over = r->headers_in.overwrite;

    if (over) {
        if (over->value.len == 1) {
            u_char ch = over->value.data[0];

            // "T"rue, so yes
            if (ch == 'T' || ch == 't') {
                overwrite = 1;
                goto overwrite_done;
            }

            // "F"alse, so no
            if (ch == 'F' || ch == 'f') {
                overwrite = 0;
                goto overwrite_done;
            }

        }

        ERROR_A(ERR, r->connection->log, 0, "client sent invalid 'Overwrite' header: '%V'", &over->value);
        return NGX_HTTP_BAD_REQUEST;
    }

overwrite_done:

    ngx_str_t save_uri = r->uri;

    // HACK: use URI routines on (possibly rewritten) source URI
    if (ctx->in_user.len) {
        r->uri = ctx->in_user;
    }

    // get source path
    ngx_str_t path;
    size_t root;
    RETURN_500_IF(ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL);

    DEBUG2(r->connection->log, 0, "http copy from: '%s' to URI='%V'", path.data, &duri);

    // get only URI path
    if (dav_next_strip_uri(r, &duri) != NGX_OK) {
        return NGX_DECLINED;
    }

    // no need
    // if (ctx->in_user.len) {
    //     r->uri = save_uri;
    // }
    // save_uri = r->uri;

    // HACK: use URI routines on destination URI
    r->uri = duri;

    // webdav / simple dav special case: rewrite destination
    if (ctx->orig_uri_type == DAV_NEXT_URI_WEBDAV || ctx->orig_uri_type == DAV_NEXT_URI_OTHER) {

        ctx->uri_type = ctx->orig_uri_type;

        ngx_int_t rc = dav_next_webdav_rewrite(r, ctx);

        if (rc != NGX_OK && rc != NGX_DECLINED) {
            r->uri = save_uri;
            return rc;
        }

        if (dav_next_user_check(r, r->uri, 1) != NGX_OK) {
            r->uri = save_uri;
            return NGX_HTTP_FORBIDDEN;
        }

    } else if (r->method == NGX_HTTP_MOVE &&
               ctx->uri_type == DAV_NEXT_URI_DAV_UPLOADS &&
               ngx_strncmp(save_uri.data + save_uri.len - (sizeof("/.file") - 1), "/.file", sizeof("/.file") - 1) == 0) {

        ctx->uri_type = DAV_NEXT_URI_DAV_FILES;
        // check if dest is in user / group paths
        if (dav_next_user_check(r, r->uri, 1) != NGX_OK) {
            r->uri = save_uri;
            return NGX_HTTP_FORBIDDEN;
        }
        ctx->uri_type = DAV_NEXT_URI_DAV_UPLOADS;

    } else if (dav_next_user_check(r, r->uri, 1) != NGX_OK) {
        r->uri = save_uri;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->uri = ctx->in_user; // change URI to user / group dest URI

    // get mapped dest path
    dav_next_copy_ctx_t copy;
    if (ngx_http_map_uri_to_path(r, &copy.path, &root, 0) == NULL) {
        r->uri = save_uri;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // back to original request uri
    r->uri = save_uri;

    ngx_uint_t chunked = 0;

    if (r->method == NGX_HTTP_MOVE &&
        ctx->uri_type == DAV_NEXT_URI_DAV_UPLOADS &&
        ngx_strncmp(save_uri.data + save_uri.len - (sizeof("/.file") - 1), "/.file", sizeof("/.file") - 1) == 0) {

        // special MOVE for NC chunked uploads
        chunked = 1;
        path.len -= sizeof("/.file") - 1;
        path.data[path.len] = '\0';

        DEBUG2(r->connection->log, 0, "chunk move from: '%V' to: '%V'", &path, &copy.path);

        // if (ctx->access_needed) {
        //     ctx->uri_type = DAV_NEXT_URI_DAV_FILES;

        //     if (dav_next_user_check(r, r->uri, 0) != NGX_OK) {
        //         r->uri = uri;
        //         return NGX_HTTP_BAD_REQUEST;
        //     }

        //     ctx->uri_type = DAV_NEXT_URI_DAV_UPLOADS;
        // }

    } else {
        DEBUG1(r->connection->log, 0, "move/copy to: '%V'", &copy.path);
    }

    copy.path.len--; // omit "\0"

    ngx_file_info_t fi;
    ngx_uint_t dir;
    ngx_uint_t dest_exists = 0;

    // destination exists?
    if (ngx_link_info(copy.path.data, &fi) == NGX_FILE_ERROR) {
        if (ngx_errno != NGX_ENOENT) {
            return dav_next_error(r->connection->log, ngx_errno, NGX_HTTP_NOT_FOUND, ngx_link_info_n, copy.path.data);
        }

        // destination does not exist

        overwrite = 0;
        dir = 0;

    } else {

        // destination exists

        dest_exists = 1;

        // can we overwrite?
        if (!overwrite) {
            ERROR_A(ERR, r->connection->log, NGX_EEXIST, "'%s' exists and is won't be overwritten", copy.path.data);
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        // is it a dir?
        dir = ngx_is_dir(&fi);
    }

    // get info on source
    if (ngx_link_info(path.data, &fi) == NGX_FILE_ERROR) {
        return dav_next_error(r->connection->log, ngx_errno, NGX_HTTP_NOT_FOUND, ngx_link_info_n, path.data);
    }

    // if dir, not from a chunked upload and overwrite destination asked (thus dest exists)
    if (ngx_is_dir(&fi) && !chunked && overwrite) {
        DEBUG1(r->connection->log, 0, "delete: '%s'", copy.path.data);

        // delete destination
        RETURN_RC_IF_NOK(dav_next_delete_path(r, &copy.path, dir));
    }

    // when moving, update source dirs ETags (set them to now)
    RETURN_500_IF(r->method == NGX_HTTP_MOVE && dav_next_update_etags(r, &path, root, ngx_time() * _1G) != NGX_OK);

    // update dest dirs ETags (set them to now)
    RETURN_500_IF(dav_next_update_etags(r, &copy.path, root, ngx_time() * _1G) != NGX_OK);

    // if dir, and not from a chunked upload
    if (ngx_is_dir(&fi) && !chunked) {

        path.len--;  // remove "\0"

        // if MOVE
        if (r->method == NGX_HTTP_MOVE) {
            DEBUG2(r->connection->log, ngx_errno, "MOVE '%V' => '%V'", &path, &copy.path);

            // just "rename()" the dir to dest path
            if (ngx_rename_file(path.data, copy.path.data) != NGX_FILE_ERROR) {
                // response code depend on dest was existing or not
                return dest_exists == 1 ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
            }

            ERROR_A(CRIT, r->connection->log, ngx_errno, "MOVE '%V' => '%V' FAILED!", &path, &copy.path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // COPY

        // create the dest dir
        if (ngx_create_dir(copy.path.data, ngx_file_access(&fi)) == NGX_FILE_ERROR)
        {
            return dav_next_error(r->connection->log, ngx_errno, NGX_HTTP_NOT_FOUND, ngx_create_dir_n, copy.path.data);
        }

        // ngx_walk_tree() fields init

        copy.len = path.len;

        ngx_tree_ctx_t tree = {
            .init_handler = NULL,
            .file_handler = dav_next_copy_tree_file,
            .pre_tree_handler = dav_next_copy_dir,
            .post_tree_handler = dav_next_copy_dir_time,
            .spec_handler = dav_next_noop,
            .data = &copy,
            .alloc = 0,
            .log = r->connection->log
        };

        // do the walk
        if (ngx_walk_tree(&tree, &path) == NGX_OK) {

            // if MOVEd, then remove the source
            // FIXME: comment this for now, should not be necessary with the rename() above

            // if (r->method == NGX_HTTP_MOVE) {
            //     rc = dav_next_delete_path(r, &path, 1);

            //     if (rc != NGX_OK) {
            //         return rc;
            //     }
            // }

            return NGX_HTTP_CREATED;
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    }

    // not dir, or from a chunked upload

    // if MOVEd
    if (r->method == NGX_HTTP_MOVE) {

        // if from a chunked upload
        if (chunked) {

            ngx_array_t chunk_entries;

            // init a chunk array
            RETURN_500_IF(ngx_array_init(&chunk_entries, r->pool, 40, sizeof(dav_next_chunk_entry_t)) != NGX_OK);

            ngx_dir_t dir_h;

            // open the source dir
            RETURN_500_IF(ngx_open_dir(&path, &dir_h) == NGX_ERROR);

            // loop on files in source dir, avoid those starting with '.' (only '.' and '..' should)
            //   and fill the array with full paths of files in the source dir

            ngx_set_errno(0);
            while (ngx_read_dir(&dir_h) != NGX_ERROR) {
                if (ngx_de_name(&dir_h)[0] == '.') {
                    continue;
                }

                len = ngx_de_namelen(&dir_h);

                dav_next_chunk_entry_t *chunk_entry = ngx_array_push(&chunk_entries);
                RETURN_500_IF(chunk_entry == NULL);

                chunk_entry->len = path.len + len + 1;

                chunk_entry->data = ngx_pnalloc(r->pool, chunk_entry->len + 1);
                RETURN_500_IF(chunk_entry->data == NULL);

                last = ngx_cpystrn(chunk_entry->data, path.data, path.len);
                *last++ = '/';
                last = ngx_cpystrn(last, ngx_de_name(&dir_h), len + 1);
                *last = '\0';

                DEBUG3(r->connection->log, 0, " ------------ FOUND '%s' = %d, %d", chunk_entry->data, chunk_entry->len, len);
            }

            RETURN_500_IF(ngx_errno != NGX_ENOMOREFILES);

            RETURN_500_IF(ngx_close_dir(&dir_h) == NGX_ERROR);

            // if we have more than one file in the array, sort it
            if (chunk_entries.nelts > 1) {
                ngx_qsort(chunk_entries.elts, (size_t) chunk_entries.nelts,
                          sizeof(dav_next_chunk_entry_t),
                          dav_next_cmp_chunk_entries);
            }

            // append all source files in sorted array to the destination

            dav_next_chunk_entry_t *chunk_entry = chunk_entries.elts;

            for (ngx_uint_t n = 0; n < chunk_entries.nelts; n++) {
                RETURN_RC_IF_NOK(dav_next_append_file(r, chunk_entry[n].data, copy.path.data, n == 0));
            }

            // get info on newly created file
            RETURN_500_IF(ngx_file_info(copy.path.data, &fi) == NGX_FILE_ERROR);

            // define ETag header (= mtime)

            uint64_t mtime = ngx_dav_next_file_mtime(&fi);

            p = ngx_pnalloc(r->pool, DAV_NEXT_HEX_ID_LEN);
            RETURN_500_IF(p == NULL);
            ngx_sprintf(p, "%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", mtime);

            ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
            RETURN_500_IF(h == NULL);
            h->hash = 1;
            ngx_str_set(&h->key, "ETag");
            h->value.len = DAV_NEXT_HEX_ID_LEN;
            h->value.data = p;
            // r->headers_out.etag = h; TODO: check why I commented this line
            DEBUG1(r->connection->log, 0, "headers_out ETag = %V", &h->value);

            // define OC-FileID header (= node ID)

            ngx_file_uniq_t id = ngx_file_uniq(&fi);

            p = ngx_pnalloc(r->pool, 8 + DAV_NEXT_HEX_ID_LEN);
            RETURN_500_IF(p == NULL);

            ngx_sprintf(p, "00000001%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", id);

            h = ngx_list_push(&r->headers_out.headers);
            RETURN_500_IF(h == NULL);
            h->hash = 1;
            ngx_str_set(&h->key, "OC-FileID");
            h->value.len = 8 + DAV_NEXT_HEX_ID_LEN;
            h->value.data = p;

            // delete source upload dir
            RETURN_500_IF(dav_next_delete_path(r, &path, 1) != NGX_OK);

            // response code depend on dest was existing or not
            return dest_exists == 1 ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;

        } else { // not from a chunked upload = rename the file

            ngx_ext_rename_file_t ext = {
                .access = 0,
                .path_access = 0600,
                .time = -1,
                .create_path = 1,
                .delete_file = 0,
                .log = r->connection->log
            };

            RETURN_500_IF(ngx_ext_rename_file(&path, &copy.path, &ext) != NGX_OK);

            // response code depend on dest was existing or not
            return dest_exists == 1 ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
        }

        // never reached
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // if COPYed, just copy the file

    ngx_copy_file_t cf = {
        .size = ngx_file_size(&fi),
        .buf_size = 0,
        .access = ngx_file_access(&fi),
        .time = ngx_file_mtime(&fi),
        .log = r->connection->log
    };

    RETURN_500_IF(ngx_copy_file(path.data, copy.path.data, &cf) != NGX_OK);

    // response code depend on dest was existing or not
    return dest_exists == 1 ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}


// copy dir handler for ngx_walk_tree()
// just create the dest dir, no recursivity in this handler
ngx_int_t dav_next_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    DEBUG1(ctx->log, 0, "copy dir: '%s'", path->data);

    // "copy" is destination dir, src dir is "path"
    dav_next_copy_ctx_t *copy = ctx->data;

    // dest dir filename

    size_t len = copy->path.len + path->len;

    u_char *dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    u_char *p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    DEBUG1(ctx->log, 0, "copy dir to: '%s'", dir);

    // create the dest dir
    if (ngx_create_dir(dir, ngx_dir_access(ctx->access)) == NGX_FILE_ERROR) {
        (void) dav_next_error(ctx->log, ngx_errno, 0, ngx_create_dir_n, dir);
    }

    ngx_free(dir);

    return NGX_OK;
}


// set file time handler for ngx_walk_tree()
ngx_int_t dav_next_copy_dir_time(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    DEBUG1(ctx->log, 0, "copy dir time: '%s'", path->data);

    // "copy" is parent of dir to set mtime
    dav_next_copy_ctx_t *copy = ctx->data;

    // dest dir

    size_t len = copy->path.len + path->len;

    u_char *dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    u_char *p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    DEBUG1(ctx->log, 0, "copy dir time to: '%s'", dir);

    // set mtime
    if (dav_next_set_file_time(dir, ctx->mtime) != NGX_OK) {
        ERROR_A(ALERT, ctx->log, ngx_errno, "dav_next_set_file_time '%s' failed", dir);
    }

    ngx_free(dir);

    return NGX_OK;
}


// copy file handler for ngx_walk_tree()
ngx_int_t dav_next_copy_tree_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    DEBUG1(ctx->log, 0, "copy file: '%s'", path->data);

    // "copy" is destination dir, src is "path"
    dav_next_copy_ctx_t *copy = ctx->data;

    // dest filename

    size_t len = copy->path.len + path->len;

    u_char *file = ngx_alloc(len + 1, ctx->log);
    if (file == NULL) {
        return NGX_ABORT;
    }

    u_char *p = ngx_cpymem(file, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    DEBUG1(ctx->log, 0, "copy file to: '%s'", file);

    // context data for actual copy
    ngx_copy_file_t cf = {
        .size = ctx->size,
        .buf_size = 0,
        .access = ctx->access,
        .time = ctx->mtime,
        .log = ctx->log
    };

    // copy
    (void) ngx_copy_file(path->data, file, &cf);

    ngx_free(file);

    return NGX_OK;
}
