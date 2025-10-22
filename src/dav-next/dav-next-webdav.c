/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-webdav.c
 * WebDAV protocol implementation for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#include "dav-next.h"
#include "dav-next-webdav.h"
#include "dav-next-locks.h"
#include "dav-next-module.h"
#include "dav-next-utils.h"

// format (or get size of) a propfind response for an entry
//  function source code has been copied from… ngx_http_dav_ext_module.c? and then modified
// HACK: fix the return value hack (uintptr_t instead of size_t)
uintptr_t dav_next_format_propfind(ngx_http_request_t *r, u_char *dst, dav_next_entry_t *entry, ngx_uint_t props)
{
    u_char head[] =
        "<D:response>\n"
        "<D:href>";

    // HERE: uri

    u_char prop[] =
        "</D:href>\n"
        "<D:propstat>\n"
        "<D:prop>\n";

    //  HERE: properties

    u_char tail[] =
        "</D:prop>\n"
        "<D:status>HTTP/1.1 200 OK</D:status>\n"
        "</D:propstat>\n"
        "</D:response>\n";

    u_char names[] =
        "<D:displayname/>\n"
        "<D:getcontentlength/>\n"
        "<D:getlastmodified/>\n"
        "<D:getetag/>\n"
        "<O:id/>\n"
        "<O:permissions/>\n"
        "<D:resourcetype/>\n"
        "<D:quota-available-bytes/>\n"
        "<D:quota-used-bytes/>\n"
        "<D:lockdiscovery/>\n"
        "<D:supportedlock/>\n";

    u_char supportedlock[] =
        "<D:lockentry>\n"
        "<D:lockscope><D:exclusive/></D:lockscope>\n"
        "<D:locktype><D:write/></D:locktype>\n"
        "</D:lockentry>\n";

    // if we just want the length
    if (dst == NULL) {
        // constant strings
            size_t len = sizeof(head) - 1
                + sizeof(prop) - 1
                + sizeof(tail) - 1;

        // add URI
        len += entry->uri.len + ngx_escape_html(NULL, entry->uri.data, entry->uri.len);

        // we only want names
        if (props & DAV_NEXT_PROP_NAMES) {
            len += sizeof(names) - 1;
        } else {

            // else we want names and content lengths
            len += sizeof("<D:displayname>"
                          "</D:displayname>\n"

                          "<D:getcontentlength>"
                          "</D:getcontentlength>\n"

                          "<D:getlastmodified>"
                          "Sun, 16 May 1971 02:45:00 GMT" // (arbitrary date)
                          "</D:getlastmodified>\n"

                          "<D:getetag>"
                          "</D:getetag>\n"

                          "<O:id>"
                          "</O:id>\n"

                          "<O:permissions>"
                          "</O:permissions>\n"

                          "<D:resourcetype>"
                          "<D:collection/>"
                          "</D:resourcetype>\n"

                          "<D:quota-available-bytes>"
                          "</D:quota-available-bytes/>\n"

                          "<D:quota-used-bytes>"
                          "</D:quota-used-bytes>\n"

                          "<D:supportedlock>\n"
                          "</D:supportedlock>\n") - 1;

            // displayname
            len += entry->name.len + ngx_escape_html(NULL, entry->name.data, entry->name.len);

            // getcontentlength
            len += NGX_OFF_T_LEN;

            // getetag
            len += DAV_NEXT_HEX_ID_LEN;

            // fileid
            len += 8 + DAV_NEXT_HEX_ID_LEN;

            // permissions
            len += entry->read_only ? 2 : (entry->is_group ? sizeof("GSWCKDNV") : sizeof("GWCKDNV")) - 1;

            // quota-available-bytes
            len += NGX_OFF_T_LEN;

            // quota-used-bytes
            len += NGX_OFF_T_LEN;

            // lockdiscovery
            len += dav_next_format_lockdiscovery(r, NULL, entry);

            // supportedlock
            if (entry->lock_supported) {
                len += sizeof(supportedlock) - 1;
            }
        }

        return len;
    }

    // head of the response
    dst = ngx_cpymem(dst, head, sizeof(head) - 1);
    // encoded URI
    dst = (u_char *) ngx_escape_html(dst, entry->uri.data, entry->uri.len);
    // prop start
    dst = ngx_cpymem(dst, prop, sizeof(prop) - 1);

    // only prop names
    if (props & DAV_NEXT_PROP_NAMES) {
        dst = ngx_cpymem(dst, names, sizeof(names) - 1);
    } else {

        // else check and provide each wanted property

        if (props & DAV_NEXT_PROP_DISPLAYNAME) {
            dst = ngx_cpymem(dst, "<D:displayname>", sizeof("<D:displayname>") - 1);
            dst = (u_char *) ngx_escape_html(dst, entry->name.data, entry->name.len);
            dst = ngx_cpymem(dst, "</D:displayname>\n", sizeof("</D:displayname>\n") - 1);
        }

        if (props & DAV_NEXT_PROP_GETCONTENTLENGTH) {
            if (!entry->dir) {
                dst = ngx_sprintf(dst, "<D:getcontentlength>%O</D:getcontentlength>\n", entry->size);
            }
        }

        if (props & DAV_NEXT_PROP_GETLASTMODIFIED) {
            dst = ngx_cpymem(dst, "<D:getlastmodified>", sizeof("<D:getlastmodified>") - 1);
            dst = ngx_http_time(dst, entry->mtime / _1G);
            dst = ngx_cpymem(dst, "</D:getlastmodified>\n", sizeof("</D:getlastmodified>\n") - 1);
        }

        if (props & DAV_NEXT_PROP_GETETAG) {
            dst = ngx_cpymem(dst, "<D:getetag>", sizeof("<D:getetag>") - 1);
            dst = ngx_sprintf(dst, "%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", entry->mtime);
            dst = ngx_cpymem(dst, "</D:getetag>\n", sizeof("</D:getetag>\n") - 1);

            DEBUG3(r->connection->log, 0, "id=%xuL => mtime=%xuL (name=%V)", entry->id, entry->mtime, &entry->name);
        }

        if (props & DAV_NEXT_PROP_FILEID) {
            dst = ngx_cpymem(dst, "<O:id>", sizeof("<O:id>") - 1);
            dst = ngx_sprintf(dst, "00000001%0" QQ(DAV_NEXT_HEX_ID_LEN) "uxL", entry->id);
            dst = ngx_cpymem(dst, "</O:id>\n", sizeof("</O:id>\n") - 1);
        }

        if (props & DAV_NEXT_PROP_PERMISSIONS) {
            if (entry->read_only) {
                dst = ngx_sprintf(dst, "<O:permissions>GM</O:permissions>\n");
            } else if (entry->is_group) {
                dst = ngx_sprintf(dst, "<O:permissions>GSWCKDNV</O:permissions>\n");
            } else {
                dst = ngx_sprintf(dst, "<O:permissions>GWCKDNV</O:permissions>\n");
            }
        }

        if (props & DAV_NEXT_PROP_RESOURCETYPE) {
            dst = ngx_cpymem(dst, "<D:resourcetype>", sizeof("<D:resourcetype>") - 1);

            if (entry->dir) {
                dst = ngx_cpymem(dst, "<D:collection/>", sizeof("<D:collection/>") - 1);
            }

            dst = ngx_cpymem(dst, "</D:resourcetype>\n", sizeof("</D:resourcetype>\n") - 1);
        }

        if (entry->dir && entry->fs_used != 0 && entry->fs_avail != NGX_MAX_OFF_T_VALUE) { // quota info only for dirs and not default values
            if (props & DAV_NEXT_PROP_QUOTA_AVAIL) {
                dst = ngx_sprintf(dst, "<D:quota-available-bytes>%O</D:quota-available-bytes>\n", entry->fs_avail);
            }

            if (props & DAV_NEXT_PROP_QUOTA_USED) {
                dst = ngx_sprintf(dst, "<D:quota-used-bytes>%O</D:quota-used-bytes>\n", entry->fs_used);
            }
        }

        if (props & DAV_NEXT_PROP_LOCKDISCOVERY) {
            dst = (u_char *) dav_next_format_lockdiscovery(r, dst, entry);
        }

        if (props & DAV_NEXT_PROP_SUPPORTEDLOCK) {
            dst = ngx_cpymem(dst, "<D:supportedlock>\n", sizeof("<D:supportedlock>\n") - 1);

            if (entry->lock_supported) {
                dst = ngx_cpymem(dst, supportedlock, sizeof(supportedlock) - 1);
            }

            dst = ngx_cpymem(dst, "</D:supportedlock>\n", sizeof("</D:supportedlock>\n") - 1);
        }
    }

    // add tail
    dst = ngx_cpymem(dst, tail, sizeof(tail) - 1);

    return (uintptr_t) dst;
}


// PROPFIND response
ngx_int_t dav_next_propfind_response(ngx_http_request_t *r, ngx_array_t *entries, ngx_uint_t props)
{
    // header and footer

    u_char head[] =
        "<?xml version='1.0' encoding='utf-8' ?>\n"
        "<D:multistatus xmlns:D='DAV:' xmlns:O='http://owncloud.org/ns'>\n";

    u_char tail[] = "</D:multistatus>\n";

    // loop on entries to escape URIs

    dav_next_entry_t *entry = entries->elts;

    for (ngx_uint_t n = 0; n < entries->nelts; n++) {
        uintptr_t escape = 2 * ngx_escape_uri(NULL, entry[n].uri.data, entry[n].uri.len, NGX_ESCAPE_URI_COMPONENT);

        // only if needed
        if (escape == 0) {
            continue;
        }

        u_char *p = ngx_pnalloc(r->pool, entry[n].uri.len + escape);
        RETURN_500_IF(p == NULL);

        entry[n].uri.len = (u_char *) ngx_escape_uri(p, entry[n].uri.data, entry[n].uri.len, NGX_ESCAPE_URI_COMPONENT) - p;
        entry[n].uri.data = p;

        for (ngx_uint_t i = 0; entry[n].uri.len > 2 && i <= entry[n].uri.len - 3; i++){
            if (p[i] == '%' && p[i + 1] == '2' && p[i + 2] == 'F'){
                ngx_cpystrn(p + i + 1, p + i + 3, entry[n].uri.len - i);

                p[i] = '/';
                p[entry[n].uri.len--] = 0;
                p[entry[n].uri.len--] = 0;
            }
        }

        entry[n].uri.data = p;
    }

    // first pass on lengths

    size_t len = sizeof(head) - 1 + sizeof(tail) - 1;

    for (ngx_uint_t n = 0; n < entries->nelts; n++) {
        len += dav_next_format_propfind(r, NULL, &entry[n], props);
    }

    // alloc temp buffer
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
    RETURN_500_IF(b == NULL);

    // header
    b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);

    // formatted entries
    for (ngx_uint_t n = 0; n < entries->nelts; n++) {
        b->last = (u_char *) dav_next_format_propfind(r, b->last, &entry[n], props);
    }

    // footer
    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    // buffer flags
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    // set up for output
    ngx_chain_t cl = {
        .buf = b,
        .next = NULL
    };

    // status, content-length, content-type and charset standard headers

    r->headers_out.status = 207;
    ngx_str_set(&r->headers_out.status_line, "207 Multi-Status");

    r->headers_out.content_length_n = b->last - b->pos;

    r->headers_out.content_type_len = sizeof("application/xml") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/xml");
    r->headers_out.content_type_lowcase = NULL;

    ngx_str_set(&r->headers_out.charset, "utf-8");

    // send the headers
    ngx_int_t rc = dav_next_send_header(r);

    // only if body is present, correct and needed
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    // output body
    return ngx_http_output_filter(r, &cl);
}


// = "do_propfind()": actually do the PROPFIND job
ngx_int_t dav_next_propfind(ngx_http_request_t *r, ngx_uint_t props)
{
    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    ngx_array_t entries;
    RETURN_500_IF(ngx_array_init(&entries, r->pool, 40, sizeof(dav_next_entry_t)) != NGX_OK);

    ngx_int_t rc = dav_next_depth(r, 0);

    if (rc == NGX_ERROR) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (rc == DAV_NEXT_INFINITY_DEPTH) {

        /*
         * RFC4918:
         * 403 Forbidden -  A server MAY reject PROPFIND requests on
         * collections with depth header of "Infinity", in which case
         * it SHOULD use this error with the precondition code
         * 'propfind-finite-depth' inside the error body.
         */

        return NGX_HTTP_FORBIDDEN;
    }

    ngx_uint_t depth = rc;

    ngx_str_t save_uri;

    // get rewritten URI if any
    if (ctx->in_user.len) {
        save_uri = r->uri;
        r->uri = ctx->in_user;
    }

    DEBUG1(r->connection->log, 0, "orig URI: '%V'", &r->uri);

    ngx_str_t path;
    size_t root;

    // get path for original URI
    u_char *last = ngx_http_map_uri_to_path(r, &path, &root, DAV_NEXT_PREALLOCATE);
    RETURN_500_IF(last == NULL);

    size_t allocated = path.len;
    path.len = last - path.data;

    DEBUG3(r->connection->log, 0, "111 path: '%V', %d=%c", &path, path.len, LAST_CHAR_OF(path));

    // remove last '/' if any
    if (path.len > 1 && LAST_CHAR_OF(path) == '/') {
        path.len--;
    }

    ngx_str_t parent_path = {
        .data = path.data,
        .len = path.len - (1 + r->headers_in.user.len)
    };

    DEBUG3(r->connection->log, 0, "222 path: '%V', %d=%c", &path, path.len, LAST_CHAR_OF(path));

    // end string with '\0'
    path.data[path.len] = '\0';

    DEBUG3(r->connection->log, 0, "333 path: '%V', %d=%c", &path, path.len, LAST_CHAR_OF(path));

    DEBUG1(r->connection->log, 0, "path: '%s'", path.data);

    ngx_file_info_t fi;

    // check that resource exists
    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        return NGX_HTTP_NOT_FOUND;
    }

    DEBUG1(r->connection->log, 0, "path: '%s'", path.data);

    ngx_str_t name;

    // find basename of resource
    // 2 chars or less, URI is resource (and 1st char is '/')
    if (r->uri.len < 2) {
        name = r->uri;
    } else {
        // init name to at least 2nd character or URI
        name.data = &(LAST_CHAR_OF(r->uri));
        // remove last '/' if any
        name.len = (name.data[0] == '/') ? 0 : 1;

        // loop while not beg of URI or '/'
        while (name.data != r->uri.data) {
            if (*(--name.data) == '/') {
                name.data++;
                break;
            }

            name.len++;
        }
    }

    // alloc main (depth == 0) entry
    dav_next_entry_t *main_entry = ngx_array_push(&entries);
    RETURN_500_IF(main_entry == NULL);

    ngx_memzero(main_entry, sizeof(dav_next_entry_t));

    // get original URI back if any
    if (ctx->in_user.len) {
        r->uri = save_uri;
    }

    if (ctx->rewritten) {
        // if really rewritten (including webdav URI): make main_entry point to the original URI
        main_entry->uri = *ctx->rewritten;
    } else {
        // make main_entry point to the original URI
        main_entry->uri = r->uri;
    }

    // fill entry fields
    main_entry->name = name;
    main_entry->dir = ngx_is_dir(&fi);
    main_entry->mtime = ngx_dav_next_file_mtime(&fi);
    main_entry->size = ngx_file_size(&fi);
    main_entry->id = ngx_file_uniq(&fi);
    main_entry->read_only = ctx->is_virtual_root ? 1 : 0; // if virtual root, then don't try to mess with it!
    main_entry->is_group = ctx->in_group ? 1 : 0;         // to set "shared" flag

    if (!main_entry->dir || (dav_next_fs_get_quota(path.data, &main_entry->fs_used, &main_entry->fs_avail) != NGX_OK)) {
        // not dir or error in getting data = maximal (default) values
        ERROR_A(ERR, r->connection->log, ngx_errno, "vfstat('%s') != NGX_OK ", path.data);
        main_entry->fs_used = 0;
        main_entry->fs_avail = NGX_MAX_OFF_T_VALUE;
    } else {
        DEBUG3(r->connection->log, 0, "vfstat('%s') → %O / %O", path.data, main_entry->fs_used, main_entry->fs_avail);
    }

    // set locking state on main entry
    RETURN_500_IF(dav_next_set_locks(r, main_entry) != NGX_OK);

    DEBUG2(r->connection->log, 0, "name: '%V', uri: '%V'", &main_entry->name, &main_entry->uri);

    // check if only main entry is needed
    if (depth == 0 || !main_entry->dir) {
        // send response in that case
        return dav_next_propfind_response(r, &entries, props);
    }

    ngx_str_t uri;

    // set temp URI to requested dir
    if (ctx->rewritten != NULL) {
        // either rewritten
        uri = *ctx->rewritten;
    } else {
        // or original
        uri = r->uri;
    }

    // if we're at virtual root
    if (ctx->is_virtual_root) {
        // take my name
        name = r->headers_in.user;

        // alloc my filename
        u_char *filename = ngx_pnalloc(r->pool, parent_path.len + 1 + name.len + 1);
        RETURN_500_IF(filename == NULL);

        // build my filename
        last = ngx_cpystrn(filename, parent_path.data, parent_path.len + 1);
        *last++ = '/';

        ngx_cpystrn(last, name.data, name.len + 1);

        DEBUG1(r->connection->log, 0, "my filename = '%s'", filename);

        // if stat() == ERROR
        if (ngx_file_info(filename, &fi) == NGX_FILE_ERROR) {
            DEBUG1(r->connection->log, ngx_errno, "my dir '%s' not found, creating it", filename);
            // let's suppose my dir does not exist (may be wrong but we don't care)
            if (ngx_create_dir(filename, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST) {
                // only fail if my dir creation is in error (and not because it already exists)
                ERROR(CRIT, r->connection->log, ngx_errno, "BUG: create my dir");
                return NGX_HTTP_NOT_FOUND;
            }

            // redo a stat() on my new dir
            if (ngx_file_info(filename, &fi) == NGX_FILE_ERROR) {
                return NGX_HTTP_NOT_FOUND;
            }
        }

        main_entry->id = 1;

        if (depth != 0) {
            // alloc new entry for my resource
            dav_next_entry_t *entry = ngx_array_push(&entries);
            RETURN_500_IF(entry == NULL);
            ngx_memzero(entry, sizeof(dav_next_entry_t));

            // fill my entry fields
            entry->name = name;
            entry->dir = ngx_is_dir(&fi);
            entry->mtime = ngx_dav_next_file_mtime(&fi);
            entry->size = ngx_file_size(&fi);
            entry->id = ngx_file_uniq(&fi);
            entry->read_only = 0;
            entry->is_group = 0;
            entry->fs_used = 0;
            entry->fs_avail = NGX_MAX_OFF_T_VALUE;

            // fill my entry URI field
            u_char *p = ngx_pnalloc(r->pool, uri.len + 1 + name.len + 1);
            RETURN_500_IF(p == NULL);
            entry->uri.data = p;

            // concat root directory…
            p = ngx_cpymem(p, uri.data, uri.len);
            if (uri.len && LAST_CHAR_OF(uri) != '/') {
                *p++ = '/';
            }

            // …with my name
            p = ngx_cpymem(p, name.data, name.len);
            *p++ = '/';

            entry->uri.len = p - entry->uri.data;

            // fill locking state
            RETURN_500_IF(dav_next_set_locks(r, entry) != NGX_OK);
        }

        time_t virtual_sum = 0;

        // now loop on virtual content (groups)
        for (ngx_int_t i = 0; i < (ngx_int_t) ctx->virtual_dir.nelts; i++) {

            // take name
            name = ((ngx_str_t *) ctx->virtual_dir.elts)[i];

            DEBUG2(r->connection->log, 0, "parent_path = %V, name = %V", &parent_path, &name);

            // alloc filename
            filename = ngx_pnalloc(r->pool, parent_path.len + 1 + name.len + 1);
            RETURN_500_IF(filename == NULL);

            // build filename
            last = ngx_cpystrn(filename, parent_path.data, parent_path.len + 1);
            *last++ = '/';

            ngx_cpystrn(last, name.data, name.len + 1);

            DEBUG1(r->connection->log, 0, "filename = '%s'", filename);

            // if stat() == ERROR
            if (ngx_file_info(filename, &fi) == NGX_FILE_ERROR) {
                DEBUG1(r->connection->log, ngx_errno, "dir '%s' not found, creating it", filename);
                // let's suppose the dir does not exist (may be wrong but we don't care)
                if (ngx_create_dir(filename, 0770) == NGX_FILE_ERROR && ngx_errno != NGX_EEXIST) {
                    // only fail if the dir creation is in error (and not because it already exists)
                    ERROR(ALERT, r->connection->log, ngx_errno, "BUG: create dir");
                    return NGX_HTTP_NOT_FOUND;
                }

                // redo a stat() on the new dir
                if (ngx_file_info(filename, &fi) == NGX_FILE_ERROR) {
                    return NGX_HTTP_NOT_FOUND;
                }
            }

            // virtual_sum hack-ish computation
            virtual_sum++;

            if (depth == 0) {
                continue;
            }

            // alloc new entry for resource
            dav_next_entry_t *entry = ngx_array_push(&entries);
            RETURN_500_IF(entry == NULL);
            ngx_memzero(entry, sizeof(dav_next_entry_t));

            // fill entry fields
            entry->name = name;
            entry->dir = ngx_is_dir(&fi);
            entry->mtime = ngx_dav_next_file_mtime(&fi);
            entry->size = ngx_file_size(&fi);
            entry->id = ngx_file_uniq(&fi);
            entry->read_only = 0;
            entry->is_group = 1;
            entry->fs_used = 0;
            entry->fs_avail = NGX_MAX_OFF_T_VALUE;

            // fill entry URI field
            u_char *p = ngx_pnalloc(r->pool, uri.len + 1 + name.len + 1);
            RETURN_500_IF(p == NULL);
            entry->uri.data = p;

            // concat root directory…
            p = ngx_cpymem(p, uri.data, uri.len);
            if (uri.len && LAST_CHAR_OF(uri) != '/') {
                *p++ = '/';
            }

            // …with name
            p = ngx_cpymem(p, name.data, name.len);
            *p++ = '/';

            entry->uri.len = p - entry->uri.data;

            // fill locking state
            RETURN_500_IF(dav_next_set_locks(r, entry) != NGX_OK);
        }

        // virtual_sum hack-ish computation
        //  (main_entry->mtime += "virtual dir number" * 10000 + mtime of entry,
        //  should allow for 10000 virtual dirs in ns resolution mtime FS)
        main_entry->mtime += virtual_sum * 10000;

        // send response
        return dav_next_propfind_response(r, &entries, props);
    }

    ngx_dir_t dir;

    // open the dir to read its content
    RETURN_500_IF(ngx_open_dir(&path, &dir) == NGX_ERROR);

    rc = NGX_OK;

    // loop on dir content
    for ( ;; ) {
        ngx_set_errno(0);

        // read next entry
        if (ngx_read_dir(&dir) == NGX_ERROR) {
            // test if error is not end of content
            RETURN_500_IF(ngx_errno != NGX_ENOMOREFILES);

            // if end of content, let's break the loop
            break;
        }

        // get filename
        name.len = ngx_de_namelen(&dir);
        name.data = ngx_de_name(&dir);

        DEBUG1(r->connection->log, 0, ngx_read_dir_n " '%V' found", &name);

        // filter out useless usual suspects
        if ((name.len == 1 && name.data[0] == '.') ||
            (name.len == 2 && name.data[0] == '.' && name.data[1] == '.')) {

            continue;
        }

        DEBUG1(r->connection->log, 0, ngx_read_dir_n " '%V' found", &name);

        // // if we're in virtual dir, let's ignore resources with same name as virtual resource
        // // TODO: change that to ignore ALL files if the virtual dir
        // if (ctx->is_virtual_root) {
        //     for (i = 0; i < (ngx_int_t) ctx->virtual_dir.nelts; i++) {
        //         if (name.len == ((ngx_str_t *) ctx->virtual_dir.elts)[i].len &&
        //             ngx_strncmp(name.data,
        //                         ((ngx_str_t *) ctx->virtual_dir.elts)[i].data,
        //                         name.len)) {
        //             break;
        //         }
        //     }
        //     if (i < (ngx_int_t) ctx->virtual_dir.nelts) {
        //         continue;
        //     }
        // }

        // alloc entry
        dav_next_entry_t *entry = ngx_array_push(&entries);
        RETURN_500_IF(entry == NULL);
        ngx_memzero(entry, sizeof(dav_next_entry_t));

        // do we need to fetch infos? (unix should always need that)
        if (!dir.valid_info) {
            // alloc enough room for dir + '/' + filename + '\0'
            u_char *filename = ngx_pnalloc(r->pool, path.len + 1 + name.len + 1);
            RETURN_500_IF(filename == NULL);

            // then copy dir path
            last = ngx_cpystrn(filename, path.data, path.len + 1);

            // add separator
            *last++ = '/';

            // add filename
            ngx_cpystrn(last, name.data, name.len + 1);

            DEBUG1(r->connection->log, ngx_errno, ngx_de_info_n " '%s' tested 12345", filename);

            // do get infos on direntry
            if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                ERROR_A(CRIT, r->connection->log, ngx_errno, ngx_de_info_n " '%s' failed", filename);
                continue;
            }
        }

        // entry name
        u_char *p = ngx_pnalloc(r->pool, name.len);
        if (p == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        ngx_memcpy(p, name.data, name.len);
        entry->name.data = p;
        entry->name.len = name.len;

        // alloc entry URI
        p = ngx_pnalloc(r->pool, uri.len + 1 + name.len + 1);
        if (p == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }
        entry->uri.data = p;

        // copy parent URI
        p = ngx_cpymem(p, uri.data, uri.len);

        // maybe add separator
        if (uri.len && LAST_CHAR_OF(uri) != '/') {
            *p++ = '/';
        }

        // copy filename
        p = ngx_cpymem(p, name.data, name.len);

        // add final '/' if entry is dir (collection)
        if (ngx_de_is_dir(&dir)) {
            *p++ = '/';
        }

        // fill remaining fields
        entry->uri.len = p - entry->uri.data;
        entry->dir = ngx_de_is_dir(&dir);
        entry->mtime = ngx_dav_next_de_mtime(&dir);
        entry->size = ngx_de_size(&dir);
        entry->id = ngx_file_uniq(&dir.info);
        entry->read_only = 0;
        entry->is_group = 0;
        entry->fs_used = 0;
        entry->fs_avail = NGX_MAX_OFF_T_VALUE;

        // fill entry locking state
        if (dav_next_set_locks(r, entry) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        DEBUG2(r->connection->log, 0, "child name: '%V', uri: '%V'", &entry->name, &entry->uri);
    }

    // end of dir reading
    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ERROR_A(ALERT, r->connection->log, ngx_errno, ngx_close_dir_n " '%V' failed", &path);
    }

    // if there was an error
    if (rc != NGX_OK) {
        return rc;
    }

    // else send response
    return dav_next_propfind_response(r, &entries, props);
}


// rewrite "/remote.php/webdav" to "/remote.php/dav/files/$remote_user"
// rewrite "/" to "/remote.php/dav/files/$remote_user"
ngx_int_t dav_next_webdav_rewrite(ngx_http_request_t *r, dav_next_ctx_t *ctx)
{
    ngx_int_t  root;
    size_t     len;

    // prepare to rewrite "/remote.php/webdav" to "/remote.php/dav/files/$remote_user"
    if (ctx->uri_type == DAV_NEXT_URI_WEBDAV) {

        // test if a trailing slash is present and remove it
        if (r->uri.len > 0 && LAST_CHAR_OF(r->uri) == '/') {
            r->uri.len--;
        }

        root = (r->uri.len == DAV_NEXT_URI_WEBDAV_LEN - 1);

        // calc rewritten length
        len = r->uri.len + (root ? 1 : 0) - DAV_NEXT_URI_WEBDAV_LEN + DAV_NEXT_URI_DAV_FILES_LEN + r->headers_in.user.len + 1;

    } else if (ctx->uri_type == DAV_NEXT_URI_SLASH || ctx->uri_type == DAV_NEXT_URI_OTHER) { // prepare to rewrite "/…" to "/remote.php/dav/files/$remote_user/…"

        // test if a trailing (and not alone) slash is present and remove it
        if (r->uri.len > 1 && LAST_CHAR_OF(r->uri) == '/') {
            r->uri.len--;
        }

        root = (r->uri.len == 1);

        // calc rewritten length
        len = r->uri.len - DAV_NEXT_URI_SLASH_LEN + DAV_NEXT_URI_DAV_FILES_LEN + r->headers_in.user.len + 1;
    } else {

        // no rewritten webdav request URI
        ctx->webdav_rewritten = NULL;

        return NGX_OK;
    }

    // save rewritten webdav request URI
    ctx->webdav_rewritten = ngx_pnalloc(r->pool, sizeof(*ctx->webdav_rewritten));
    RETURN_500_IF(ctx->webdav_rewritten == NULL);

    ctx->webdav_rewritten->len = r->uri.len;

    ctx->webdav_rewritten->data = ngx_pnalloc(r->pool, r->uri.len);
    RETURN_500_IF(ctx->webdav_rewritten->data == NULL);

    ngx_memcpy(ctx->webdav_rewritten->data, r->uri.data, r->uri.len);

    u_char *p = ngx_pnalloc(r->pool, len + 1);
    RETURN_500_IF(p == NULL);

    ngx_str_t uri = {
        .data = p,
        .len = len
    };

    p = ngx_cpymem(p,
                   DAV_NEXT_URI_DAV_FILES_STR,
                   DAV_NEXT_URI_DAV_FILES_LEN);
    // add $remote_user
    p = ngx_cpymem(p,
                   r->headers_in.user.data,
                   r->headers_in.user.len);
    *p++ = '/';

    if (!root) {
        // add remaining part of URI
        if (ctx->uri_type == DAV_NEXT_URI_WEBDAV) {
            p = ngx_cpymem(p,
                           r->uri.data + DAV_NEXT_URI_WEBDAV_LEN,
                           r->uri.len - DAV_NEXT_URI_WEBDAV_LEN);
        } else if (ctx->uri_type == DAV_NEXT_URI_SLASH || ctx->uri_type == DAV_NEXT_URI_OTHER) {
            p = ngx_cpymem(p,
                           r->uri.data + DAV_NEXT_URI_SLASH_LEN,
                           r->uri.len - DAV_NEXT_URI_SLASH_LEN);
        }
    }

    *p = '\0';

    // set rewritten URI type to main NC DAV dir
    ctx->orig_uri_type = ctx->uri_type;
    ctx->uri_type = DAV_NEXT_URI_DAV_FILES;
    // remember offset
    ctx->alias = DAV_NEXT_URI_DAV_ALIAS_LEN;

    // do replace
    r->uri.data = uri.data;
    r->uri.len  = uri.len;

    return NGX_OK;
}


// PROPFIND handler
void dav_next_propfind_handler(ngx_http_request_t *r)
{
    xmlSAXHandler        sax;
    dav_next_xml_ctx_t   xctx;

    DEBUG0(r->connection->log, 0, "entering");

    // init and create XML SAX parser

    ngx_memzero(&xctx, sizeof(dav_next_xml_ctx_t));
    ngx_memzero(&sax, sizeof(xmlSAXHandler));

    sax.initialized = XML_SAX2_MAGIC;
    sax.startElementNs = dav_next_propfind_xml_start;
    sax.endElementNs = dav_next_propfind_xml_end;

    xmlParserCtxtPtr pctx = xmlCreatePushParserCtxt(&sax, &xctx, NULL, 0, NULL);
    FINALIZE_500_IF(pctx == NULL);

    off_t len = 0;

    // loop on request body

    for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        // body in file is not good
        if (b->in_file) {
            ERROR(ALERT, r->connection->log, 0, "client body is in file, you may want to increase client_body_buffer_size");
            xmlFreeParserCtxt(pctx);
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        // not for us
        if (ngx_buf_special(b)) {
            continue;
        }

        len += b->last - b->pos;

        // parse the current buf

#ifdef NGX_DEBUG
        ngx_str_t buf;
        buf.len = b->last - b->pos;
        buf.data = b->pos;
        DEBUG1(r->connection->log, 0, "buf=[%V]", &buf);
#endif

        if (xmlParseChunk(pctx, (const char *) b->pos, b->last - b->pos,
                          b->last_buf))
        {
            ERROR(ALERT, r->connection->log, 0, "xmlParseChunk() failed");
            xmlFreeParserCtxt(pctx);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return;
        }
    }

    xmlFreeParserCtxt(pctx);

    if (len == 0) {

        /*
         * For easier debugging treat bodiless requests
         * as if they expect all properties.
         */

        xctx.props = DAV_NEXT_PROP_ALL;
    }

    // just do it (actual PROPFIND job)
    ngx_http_finalize_request(r, dav_next_propfind(r, xctx.props));
}


// PROPFIND XML element start handler
// also called by xml_end for closing elements (XOR after XOR = back to initial value)
void
dav_next_propfind_xml_start(void *data, const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri, int nb_namespaces, const xmlChar **namespaces, int nb_attributes, int nb_defaulted, const xmlChar **attributes)
{
    dav_next_xml_ctx_t *xctx = data;

    if (ngx_strcmp(localname, "propfind") == 0) {
        xctx->nodes ^= DAV_NEXT_NODE_PROPFIND;
    }

    if (ngx_strcmp(localname, "prop") == 0) {
        xctx->nodes ^= DAV_NEXT_NODE_PROP;
    }

    if (ngx_strcmp(localname, "propname") == 0) {
        xctx->nodes ^= DAV_NEXT_NODE_PROPNAME;
    }

    if (ngx_strcmp(localname, "allprop") == 0) {
        xctx->nodes ^= DAV_NEXT_NODE_ALLPROP;
    }
}


// PROPFIND XML element end handler
void
dav_next_propfind_xml_end(void *data, const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri)
{
    dav_next_xml_ctx_t *xctx = data;

    // are we in PROPFIND?
    if (xctx->nodes & DAV_NEXT_NODE_PROPFIND) {

        // are we in PROP?
        if (xctx->nodes & DAV_NEXT_NODE_PROP) {

            // set flags according to requested props

            if (ngx_strcmp(localname, "displayname") == 0) {
                xctx->props |= DAV_NEXT_PROP_DISPLAYNAME;
            }

            if (ngx_strcmp(localname, "getcontentlength") == 0) {
                xctx->props |= DAV_NEXT_PROP_GETCONTENTLENGTH;
            }

            if (ngx_strcmp(localname, "getlastmodified") == 0) {
                xctx->props |= DAV_NEXT_PROP_GETLASTMODIFIED;
            }

            if (ngx_strcmp(localname, "getetag") == 0) {
                xctx->props |= DAV_NEXT_PROP_GETETAG;
            }

            if (ngx_strcmp(localname, "resourcetype") == 0) {
                xctx->props |= DAV_NEXT_PROP_RESOURCETYPE;
            }

            if (ngx_strcmp(localname, "lockdiscovery") == 0) {
                xctx->props |= DAV_NEXT_PROP_LOCKDISCOVERY;
            }

            if (ngx_strcmp(localname, "supportedlock") == 0) {
                xctx->props |= DAV_NEXT_PROP_SUPPORTEDLOCK;
            }

            if (ngx_strcmp(localname, "permissions") == 0) {
                xctx->props |= DAV_NEXT_PROP_PERMISSIONS;
            }

            if (ngx_strcmp(localname, "fileid") == 0) {
                xctx->props |= DAV_NEXT_PROP_FILEID;
            }

            if (ngx_strcmp(localname, "quota-available-bytes") == 0) {
                xctx->props |= DAV_NEXT_PROP_QUOTA_AVAIL;
            }

            if (ngx_strcmp(localname, "quota-used-bytes") == 0) {
                xctx->props |= DAV_NEXT_PROP_QUOTA_USED;
            }
        }

        // are we in PROPNAME?
        if (xctx->nodes & DAV_NEXT_NODE_PROPNAME) {
            xctx->props |= DAV_NEXT_PROP_NAMES;
        }

        // do we need to send all props?
        if (xctx->nodes & DAV_NEXT_NODE_ALLPROP) {
            xctx->props = DAV_NEXT_PROP_ALL;
        }
    }

    // call xml_start to end (XOR again) node processing when closing element found
    dav_next_propfind_xml_start(data, localname, prefix, uri, 0, NULL, 0, 0, NULL);
}
