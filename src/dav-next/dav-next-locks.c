/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-locks.c
 * Locking system for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#include "dav-next.h"
#include "dav-next-locks.h"
#include "dav-next-utils.h"

// parse "If:" header, return uint32 binary token
uint32_t dav_next_if(ngx_http_request_t *r, ngx_str_t *uri)
{
    u_char name[] = "if";

    DEBUG1(r->connection->log, 0, "'if' '%V'", uri);

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;

    // loop on header list
    for (ngx_uint_t i = 0; /* void */ ; i++) {

        // if we're finished
        if (i >= part->nelts) {
            // and there is no more
            if (part->next == NULL) {
                break;
            }

            // else get next and restart
            part = part->next;
            header = part->elts;
            i = 0;
        }

        ngx_uint_t n;

        // loop on header name to test
        for (n = 0; n < sizeof(name) - 1 && n < header[i].key.len; n++) {
            u_char ch = header[i].key.data[n];

            // force lower case
            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;
            }

            // no match
            if (name[n] != ch) {
                break;
            }
        }

        // if matched
        if (n == sizeof(name) - 1 && n == header[i].key.len) {

            // get value
            u_char *p = header[i].value.data;
            // default to current URI
            ngx_str_t tag = r->uri;

            // loop on value list
            while (*p != '\0') {
                DEBUG1(r->connection->log, 0, "'if' list '%s'", p);

                while (*p == ' ') { p++; }

                // if start of tag
                if (*p == '<') {
                    // set tag to start position
                    tag.data = ++p;

                    // look for end of tag
                    while (*p != '\0' && *p != '>') { p++; }

                    // but abort if not found
                    if (*p == '\0') {
                        break;
                    }

                    // set tag length
                    tag.len = p++ - tag.data;

                    // remove scheme if any
                    (void) dav_next_strip_uri(r, &tag);

                    while (*p == ' ') { p++; }
                }

                // abort if no following or starting '('
                if (*p != '(') {
                    break;
                }

                p++;

                // if mismatch (empty tag, longer tag, shorter tag not ending with '/' or URI not starting with tag
                if (tag.len == 0 || tag.len > uri->len ||
                    (tag.len < uri->len && LAST_CHAR_OF(tag) != '/') ||
                    ngx_memcmp(tag.data, uri->data, tag.len)) {

                    DEBUG1(r->connection->log, 0, "'if' tag mismatch '%V'", &tag);

                    // look for closing ')'
                    while (*p != '\0' && *p != ')') { p++; }

                    if (*p == ')') {
                        p++;
                    }

                    continue;
                }

                // loop to the end of string
                while (*p != '\0') {
                    DEBUG1(r->connection->log, 0, "'if' condition '%s'", p);

                    while (*p == ' ') { p++; }

                    // if 'Not', then ignore
                    // TODO: to check
                    if (ngx_strncmp(p, "Not", 3) == 0) {
                        p += 3;
                        while (*p == ' ') { p++; }
                        goto next;
                    }

                    // ignore tags
                    if (*p == '[') {
                        p++;
                        while (*p != '\0' && *p != ']') { p++; }
                        goto next;
                    }

                    // ignore if not starting with "<urn:"
                    if (ngx_strncmp(p, "<urn:", 5)) {
                        goto next;
                    }

                    p += 5;
                    uint32_t token = 0;

                    // hex to uint32 conversion
                    for (n = 0; n < 8; n++) {
                        u_char ch = *p++;

                        if (ch >= '0' && ch <= '9') {
                            token = token * 16 + (ch - '0');
                            continue;
                        }

                        ch = (u_char) (ch | 0x20);

                        if (ch >= 'a' && ch <= 'f') {
                            token = token * 16 + (ch - 'a' + 10);
                            continue;
                        }

                        // ignore if not hex digit
                        goto next;
                    }

                    // ignore if not 8-digit hex number ending with '>'
                    if (*p != '>') {
                        goto next;
                    }

                    DEBUG1(r->connection->log, 0, "'if' token: %uxD", token);

                    return token;

                next:

                    while (*p != '\0' && *p != ' ' && *p != ')') { p++; }

                    if (*p == ')') {
                        p++;
                        break;
                    }
                }
            }

            DEBUG0(r->connection->log, 0, "'if' header mismatch");
        }
    }

    // nothing interesting
    return 0;
}


// check if URI is locked
ngx_int_t dav_next_verify_lock(ngx_http_request_t *r, ngx_str_t *uri, ngx_uint_t delete_lock)
{
    DEBUG1(r->connection->log, 0, "'%V'", uri);

    // get "If:" token
    uint32_t token = dav_next_if(r, uri);

    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);
    dav_next_lock_t *lock = dlcf->shm_zone->data;

    ngx_shmtx_lock(&lock->shpool->mutex);

    // get the matching lock, if any
    dav_next_node_t *node = dav_next_lock_lookup(r, lock, uri, -1);
    // no lock, then OK
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_OK;
    }

    // no token given but locked, so… locked
    if (token == 0) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return 423; /* Locked */
    }

    // wrong token, then error
    if (token != node->token) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    // token is OK, but last check, if the resource is vanishing (DELETEd or MOVEd)
    //   then the lock must vanish too

    // a.k.a.

    // RFC4918:
    // If a request causes the lock-root of any lock to become an
    // unmapped URL, then the lock MUST also be deleted by that request.

    if (delete_lock && node->len == uri->len) {
        ngx_queue_remove(&node->queue);
        ngx_slab_free_locked(lock->shpool, node);
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_OK;
}


// check if URI is included in any lock node
dav_next_node_t *dav_next_lock_lookup(ngx_http_request_t *r, dav_next_lock_t *lock, ngx_str_t *uri, ngx_int_t depth)
{
    DEBUG1(r->connection->log, 0, "'%V'", uri);

    if (uri->len == 0) {
        return NULL;
    }

    time_t now = ngx_time();

    // cleanup the lock queue based on time / expire
    while (!ngx_queue_empty(&lock->sh->queue)) {
        ngx_queue_t *q = ngx_queue_head(&lock->sh->queue);
        dav_next_node_t *node = (dav_next_node_t *) q;

        // as queue is ordered, if node is OK, there won't be more
        if (node->expire >= now) {
            break;
        }

        ngx_queue_remove(q);
        ngx_slab_free_locked(lock->shpool, node);
    }

    // foreach node in queue
    for (ngx_queue_t *q = ngx_queue_head(&lock->sh->queue);
         q != ngx_queue_sentinel(&lock->sh->queue);
         q = ngx_queue_next(q)) {

        dav_next_node_t *node = (dav_next_node_t *) q;

        // if possibly "equals to" or "is in"
        if (uri->len >= node->len) {
            // well, no
            if (ngx_memcmp(uri->data, node->data, node->len)) {
                continue;
            }

            // if URI is longer (is possibly "in")
            if (uri->len > node->len) {
                // but node is not a collection, then no because it is shorter
                if (LAST_CHAR_OF(*node) != '/') {
                    continue;
                }

                // no infinite lock, but with a '/'
                //   between uri[node->len] and uri[uri->len - 1], then no
                if (!node->infinite &&
                    ngx_strlchr(uri->data + node->len,
                                uri->data + uri->len - 1,
                                '/')) {

                    continue;
                }
            }

            // yes, found!

            DEBUG2(r->connection->log, 0, "found '%*s'", node->len, node->data);

            return node;
        }

        // here uri->len < node->len

        // if depth == 0, then no, else
        if (depth >= 0) {
            // if prefixes are not equal, then no
            if (ngx_memcmp(node->data, uri->data, uri->len)) {
                continue;
            }

            // if URI is not a collection, then no because it is shorter
            if (LAST_CHAR_OF(*uri) != '/') {
                continue;
            }

            // if lock has no depth, and there is a '/'
            //   between node[uri->len] and node[node->len - 1], then no
            if (depth == 0 &&
                ngx_strlchr(node->data + uri->len,
                            node->data + node->len - 1,
                            '/')) {

                continue;
            }

            // oh!, found!

            DEBUG2(r->connection->log, 0, "found '%*s'", node->len, node->data);

            return node;
        }
    }

    DEBUG0(r->connection->log, 0, "not found");

    // if here then not found

    return NULL;
}


// LOCK handler
ngx_int_t dav_next_lock_handler(ngx_http_request_t *r)
{
    // just in case
    if (r->uri.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    dav_next_lock_t *lock = dlcf->shm_zone->data;

    // RFC4918:
    // If no Depth header is submitted on a LOCK request, then the request
    // MUST act as if a "Depth:infinity" had been submitted.

    ngx_int_t rc = dav_next_depth(r, DAV_NEXT_INFINITY_DEPTH);

    if (rc == NGX_ERROR || rc == 1) {

        // RFC4918:
        // Values other than 0 or infinity MUST NOT be used with the Depth
        // header on a LOCK method.

        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_int_t depth = rc;
    ngx_str_t save_uri;

    // save / set rewritten URI
    if (ctx->in_user.len) {
        save_uri = r->uri;
        r->uri = ctx->in_user;
    }

    // get "If:" token
    uint32_t token = dav_next_if(r, &r->uri);
    uint32_t new_token = 0;

    // generate new token
    while (new_token == 0) {
        new_token = ngx_random();
    }

    time_t now = ngx_time();

    // lock shared memory access
    ngx_shmtx_lock(&lock->shpool->mutex);

    // get node from lock and URI
    dav_next_node_t *node = dav_next_lock_lookup(r, lock, &r->uri, depth);

    // if found
    if (node) {
        // restore URI
        if (ctx->in_user.len) {
            r->uri = save_uri;
        }

        // no token given = no change
        if (token == 0) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return 423; // Locked
        }

        // wrong token given
        if (node->token != token) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        DEBUG0(r->connection->log, 0, "refresh lock");

        // lock refresh
        node->expire = now + lock->timeout;

        // put it to back of queue
        ngx_queue_remove(&node->queue);
        ngx_queue_insert_tail(&lock->sh->queue, &node->queue);

        ngx_shmtx_unlock(&lock->shpool->mutex);

        // send response
        return dav_next_lock_response(r, NGX_HTTP_OK, lock->timeout, depth, token);
    }

    // not found, create new lock

    // allocate
    size_t n = sizeof(dav_next_node_t) + r->uri.len - 1;

    node = ngx_slab_alloc_locked(lock->shpool, n);
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // init
    ngx_memzero(node, sizeof(dav_next_node_t));

    // fill lock data
    ngx_memcpy(&node->data, r->uri.data, r->uri.len);
    node->len = r->uri.len;
    node->token = new_token;
    node->expire = now + lock->timeout;
    node->infinite = (depth ? 1 : 0);

    // put it to back of queue
    ngx_queue_insert_tail(&lock->sh->queue, &node->queue);

    ngx_shmtx_unlock(&lock->shpool->mutex);

    DEBUG0(r->connection->log, 0, "add lock");

    ngx_str_t path;
    size_t root;
    u_char *last = ngx_http_map_uri_to_path(r, &path, &root, 0);

    // restore URI
    if (ctx->in_user.len) {
        r->uri = save_uri;
    }

    RETURN_500_IF(last == NULL);

    // end path string with '\0'
    *last = '\0';

    ngx_uint_t status;
    ngx_file_info_t fi;

    // if file not found (or worse)
    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {

        /*
         * RFC4918:
         * A successful lock request to an unmapped URL MUST result in the
         * creation of a locked (non-collection) resource with empty content.
         */

        ngx_fd_t fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);

        if (fd == NGX_INVALID_FILE) {

            /*
             * RFC4918:
             * 409 (Conflict) - A resource cannot be created at the destination
             * until one or more intermediate collections have been created.
             * The server MUST NOT create those intermediate collections
             * automatically.
             */

            ERROR_A(ERR, r->connection->log, ngx_errno, ngx_open_file_n " '%s' failed", path.data);

            return NGX_HTTP_CONFLICT;
        }

        RETURN_500_IF(ngx_close_file(fd) == NGX_FILE_ERROR);

        // status if we needed to create the resource (file)
        status = NGX_HTTP_CREATED;
    } else {
        status = NGX_HTTP_OK;
    }

    // send response
    return dav_next_lock_response(r, status, lock->timeout, depth, new_token);
}

// generate response XML to LOCK action
ngx_int_t dav_next_lock_response(ngx_http_request_t *r, ngx_uint_t status, time_t timeout, ngx_uint_t depth, uint32_t token)
{
    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    u_char head[] =
        "<?xml version='1.0' encoding='utf-8' ?>\n"
        "<D:prop xmlns:D='DAV:'>\n";

    u_char tail[] = "</D:prop>\n";

    time_t now = ngx_time();

    dav_next_entry_t entry;

    ngx_memzero(&entry, sizeof(dav_next_entry_t));

    entry.lock_expire = now + timeout;

    // set lock_root (real) URI
    if (ctx->in_user.len) {
        entry.lock_root = ctx->in_user;
    } else {
        entry.lock_root = r->uri;
    }

    entry.lock_infinite = depth ? 1 : 0;
    entry.lock_token = token;

    // calc length
    size_t len = sizeof(head) - 1
        + dav_next_format_lockdiscovery(r, NULL, &entry)
        + sizeof(tail) - 1;

    // allocate buffer
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
    RETURN_500_IF(b == NULL);

    // fill buffer with data
    b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);
    b->last = (u_char *) dav_next_format_lockdiscovery(r, b->last, &entry);
    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    // buffer other init
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    // put buffer in output chain
    ngx_chain_t cl = {
        .buf = b,
        .next = NULL
    };

    // set output headers
    r->headers_out.status = status;
    r->headers_out.content_length_n = b->last - b->pos;

    r->headers_out.content_type_len = sizeof("application/xml") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/xml");
    r->headers_out.content_type_lowcase = NULL;

    ngx_str_set(&r->headers_out.charset, "utf-8");

    // add a custom "Lock-Token" header
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    RETURN_500_IF(h == NULL);

    ngx_str_set(&h->key, "Lock-Token");

    // header value
    u_char *p = ngx_pnalloc(r->pool, dav_next_format_token(NULL, token, 1));
    RETURN_500_IF(p == NULL);

    h->value.data = p;
    h->value.len = (u_char *) dav_next_format_token(p, token, 1) - p;
    h->hash = 1;

    // send headers
    ngx_int_t rc = dav_next_send_header(r);

    // if in error or no body
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    // send body
    return ngx_http_output_filter(r, &cl);
}


// parse "lock-token" header, return uint32 binary token
uint32_t dav_next_lock_token(ngx_http_request_t *r)
{
    u_char name[] = "lock-token";

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;

    // loop on header list
    for (ngx_uint_t i = 0; /* void */ ; i++) {

        // if we're finished
        if (i >= part->nelts) {
            // and there is no more
            if (part->next == NULL) {
                break;
            }

            // else get next and restart
            part = part->next;
            header = part->elts;
            i = 0;
        }

        ngx_uint_t n;

        // loop on header name to test
        for (n = 0; n < sizeof(name) - 1 && n < header[i].key.len; n++) {
            u_char ch = header[i].key.data[n];

            // force lower case
            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;
            }

            // no match
            if (name[n] != ch) {
                break;
            }
        }

        // if matched
        if (n == sizeof(name) - 1 && n == header[i].key.len) {
            u_char *p = header[i].value.data;

            // nothing if not beginning with "<urn:"
            if (ngx_strncmp(p, "<urn:", 5)) {
                return 0;
            }

            p += 5;
            uint32_t token = 0;

            // hex to uint32 conversion
            for (n = 0; n < 8; n++) {
                u_char ch = *p++;

                if (ch >= '0' && ch <= '9') {
                    token = token * 16 + (ch - '0');
                    continue;
                }

                ch = (u_char) (ch | 0x20);

                if (ch >= 'a' && ch <= 'f') {
                    token = token * 16 + (ch - 'a' + 10);
                    continue;
                }

                // ignore if not hex digit
                return 0;
            }

            // ignore if not 8-digit hex number ending with '>'
            if (*p != '>') {
                return 0;
            }

            return token;
        }
    }

    // nothing interesting
    return 0;
}

// UNLOCK handler
ngx_int_t dav_next_unlock_handler(ngx_http_request_t *r)
{
    dav_next_ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_module);

    // get token from headers
    uint32_t token = dav_next_lock_token(r);

    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);
    dav_next_lock_t *lock = dlcf->shm_zone->data;

    // lock shared memory access
    ngx_shmtx_lock(&lock->shpool->mutex);

    ngx_str_t             uri;

    // if URI rewritten
    if (ctx->in_user.len) {
        uri = ctx->in_user;
    } else {
        uri = r->uri;
    }

    // get node from queue
    dav_next_node_t *node = dav_next_lock_lookup(r, lock, &uri, -1);

    // no match
    if (node == NULL || node->token != token) {
        // unlock shared memory access
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    // match = remove lock
    ngx_queue_remove(&node->queue);
    ngx_slab_free_locked(lock->shpool, node);

    // unlock shared memory access
    ngx_shmtx_unlock(&lock->shpool->mutex);

    DEBUG0(r->connection->log, 0, "delete lock");

    return NGX_HTTP_NO_CONTENT;
}


// set locking state on entry
ngx_int_t dav_next_set_locks(ngx_http_request_t *r, dav_next_entry_t *entry)
{
    dav_next_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, dav_next_module);

    // is locking supported?
    // TODO: can this happen?
    if (dlcf->shm_zone == NULL) {
        entry->lock_supported = 0;
        return NGX_OK;
    }

    entry->lock_supported = 1;

    dav_next_lock_t *lock = dlcf->shm_zone->data;

    ngx_shmtx_lock(&lock->shpool->mutex);

    // fetch the possible lock
    dav_next_node_t *node = dav_next_lock_lookup(r, lock, &entry->uri, -1);
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_OK;
    }

    // fill lock fields
    entry->lock_infinite = node->infinite ? 1 : 0;
    entry->lock_expire = node->expire;
    entry->lock_token = node->token;

    // copy root lock data in entry
    entry->lock_root.data = ngx_pnalloc(r->pool, node->len);
    if (entry->lock_root.data == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_ERROR;
    }

    ngx_memcpy(entry->lock_root.data, node->data, node->len);
    entry->lock_root.len = node->len;

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_OK;
}

// format (or get size of) a token in hex
//  copied and modified from… ngx_http_dav_ext_module.c?
// TODO: fix the return value hack (uintptr_t instead of size_t)
uintptr_t dav_next_format_token(u_char *dst, uint32_t token, ngx_uint_t brackets)
{
    const u_char hex[] = "0123456789abcdef";

    // if we just want the length
    if (dst == NULL) {
        return sizeof("<urn:deadbeef>") - 1 + (brackets ? 2 : 0);
    }

    // if we want brackets
    if (brackets) {
        *dst++ = '<';
    }

    // constant string
    dst = ngx_cpymem(dst, "urn:", 4);

    // uint32 to hex
    for (ngx_uint_t n = 0; n < 4; n++) {
        *dst++ = hex[token >> 28];
        *dst++ = hex[(token >> 24) & 0xf];
        token <<= 8;
    }

    // if we want brackets
    if (brackets) {
        *dst++ = '>';
    }

    // return result string
    return (uintptr_t) dst;
}


// format (or get size of) a lockdiscovery response for an entry
//  copied and modified from… ngx_http_dav_ext_module.c?
// TODO: fix the return value hack (uintptr_t instead of size_t)
uintptr_t
dav_next_format_lockdiscovery(ngx_http_request_t *r, u_char *dst, dav_next_entry_t *entry)
{
    // if we just want the length
    if (dst == NULL) {
        // no lock = empty XML element size
        if (entry->lock_token == 0) {
            return sizeof("<D:lockdiscovery/>\n") - 1;
        }

        // size of empty XML elements
        size_t len = sizeof("<D:lockdiscovery>\n"
                            "<D:activelock>\n"
                            "<D:locktype><D:write/></D:locktype>\n"
                            "<D:lockscope><D:exclusive/></D:lockscope>\n"
                            "<D:depth>infinity</D:depth>\n"
                            "<D:timeout>Second-</D:timeout>\n"
                            "<D:locktoken><D:href></D:href></D:locktoken>\n"
                            "<D:lockroot><D:href></D:href></D:lockroot>\n"
                            "</D:activelock>\n"
                            "</D:lockdiscovery>\n") - 1;

        // timeout
        len += NGX_TIME_T_LEN;

        // token
        len += dav_next_format_token(NULL, entry->lock_token, 0);

        // lockroot
        len += entry->lock_root.len + ngx_escape_html(NULL, entry->lock_root.data, entry->lock_root.len);

        return len;
    }

    // no lock = empty XML element
    if (entry->lock_token == 0) {
        dst = ngx_cpymem(dst, "<D:lockdiscovery/>\n", sizeof("<D:lockdiscovery/>\n") - 1);
        return (uintptr_t) dst;
    }

    time_t now = ngx_time();

    dst = ngx_cpymem(dst, "<D:lockdiscovery>\n", sizeof("<D:lockdiscovery>\n") - 1);

    dst = ngx_cpymem(dst, "<D:activelock>\n", sizeof("<D:activelock>\n") - 1);

    dst = ngx_cpymem(dst, "<D:locktype><D:write/></D:locktype>\n", sizeof("<D:locktype><D:write/></D:locktype>\n") - 1);

    dst = ngx_cpymem(dst, "<D:lockscope><D:exclusive/></D:lockscope>\n", sizeof("<D:lockscope><D:exclusive/></D:lockscope>\n") - 1);

    dst = ngx_sprintf(dst, "<D:depth>%s</D:depth>\n", entry->lock_infinite ? "infinity" : "0");

    dst = ngx_sprintf(dst, "<D:timeout>Second-%T</D:timeout>\n", entry->lock_expire - now);

    dst = ngx_cpymem(dst, "<D:locktoken><D:href>", sizeof("<D:locktoken><D:href>") - 1);
    dst = (u_char *) dav_next_format_token(dst, entry->lock_token, 0);
    dst = ngx_cpymem(dst, "</D:href></D:locktoken>\n", sizeof("</D:href></D:locktoken>\n") - 1);

    dst = ngx_cpymem(dst, "<D:lockroot><D:href>", sizeof("<D:lockroot><D:href>") - 1);
    dst = (u_char *) ngx_escape_html(dst, entry->lock_root.data, entry->lock_root.len);
    dst = ngx_cpymem(dst, "</D:href></D:lockroot>\n", sizeof("</D:href></D:lockroot>\n") - 1);

    dst = ngx_cpymem(dst, "</D:activelock>\n", sizeof("</D:activelock>\n") - 1);

    dst = ngx_cpymem(dst, "</D:lockdiscovery>\n", sizeof("</D:lockdiscovery>\n") - 1);

    return (uintptr_t) dst;
}
