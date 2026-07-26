/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-utils.c
 * Utility functions for dav-next
 * © Alexandre Jousset
 */

#include "utils.h"

void sanitize_str(u_char *str) {
    static u_char sanitizeTable[256] = {0xff};

    if (str == NULL || *str == '\0') {
        return;
    }

    // Initialize un-initialized table at first use
    if (sanitizeTable[0] == 0xff) {
        for (ngx_uint_t i = 0; i < sizeof(sanitizeTable); i++) {
            // convert any char other than ALPHA / DIGIT / "-" / "_"  to the "_" char
            sanitizeTable[i] = (isalnum(i) || i == '-' || i == '_') ? i : '_';
        }
    }

    for (u_char *p = str; *p; p++) {
        *p = sanitizeTable[(int)*p];
    }
}

ngx_uint_t hex_digit_value(u_char c)
{
    if (c >= '0' && c <= '9') {
        return (ngx_uint_t)(c - '0');
    }

    if (c >= 'a' && c <= 'f') {
        return (ngx_uint_t)(c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'F') {
        return (ngx_uint_t)(c - 'A' + 10);
    }

    return 0; // Not an hex digit
}

void hex_decode(ngx_str_t *dst, ngx_str_t *src)
{
    u_char *s = src->data;
    u_char *d = dst->data;

    for (ngx_uint_t i = 0; i < src->len - 1; i += 2) {
        d[i] = (u_char)((hex_digit_value(s[i]) << 4) + hex_digit_value(s[i + 1]));
    }
}

// set a complex value in conf, borrowed from `ngx_http_auth_basic_module.c`
char *dav_next_set_complex_value(ngx_conf_t *cf, ngx_http_complex_value_t **where, ngx_str_t *value, ngx_int_t conf_prefix)
{
    if (*where == NGX_CONF_UNSET_PTR || *where == NULL) {
        *where = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        RETURN_CONF_ERROR_IF(*where == NULL, "Could not allocate value", NULL);
    }

    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = *where;
    ccv.zero = conf_prefix;
    ccv.conf_prefix = conf_prefix;

    RETURN_CONF_ERROR_IF(ngx_http_compile_complex_value(&ccv) != NGX_OK, "Could not compile complex value", NULL);

    return NGX_CONF_OK;
}

char *parse_conf_block(ngx_conf_t *cf, ngx_conf_handler_pt handler, void *conf)
{
    ngx_conf_t save = *cf;
    cf->handler = handler;
    cf->handler_conf = conf;
    char *rv = ngx_conf_parse(cf, NULL);
    *cf = save;

    return rv;
}

#pragma GCC visibility push(hidden)

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

    // if in SSL mode
    if (r->connection->ssl) {
        // check if correct scheme
        if (ngx_strncmp(uri->data, "https://", sizeof("https://") - 1) != 0) {
            goto failed;
        }

        // point to host part
        host = uri->data + sizeof("https://") - 1;

    } else { // not in SSL mode

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
    ngx_str_t path;

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

        // uh oh, same time, let's increment it by 1ns
        if (cur_mtime / 1000 == mtime / 1000) {
            cur_mtime += 1000;
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

    ngx_str_t user = ngx_null_string;
    ngx_str_t pass = ngx_null_string;

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

// rewrite "/remote.php/webdav" to "/remote.php/dav/files/$remote_user"
// rewrite "/" to "/remote.php/dav/files/$remote_user"
ngx_int_t dav_next_webdav_rewrite(ngx_http_request_t *r, dav_next_ctx_t *ctx)
{
    ngx_int_t root;
    ngx_int_t ending_slash = 0;
    size_t len;

    // prepare to rewrite "/remote.php/webdav" to "/remote.php/dav/files/$remote_user"
    if (ctx->uri_type == DAV_NEXT_URI_WEBDAV) {

        // test if a trailing slash is present and remove it
        if (r->uri.len > 0 && LAST_CHAR_OF(r->uri) == '/') {
            ending_slash = 1;
            r->uri.len--;
        }

        root = (r->uri.len == DAV_NEXT_URI_WEBDAV_LEN - 1);

        // calc rewritten length
        len = r->uri.len + (root ? 1 : 0) - DAV_NEXT_URI_WEBDAV_LEN + DAV_NEXT_URI_DAV_FILES_LEN + r->headers_in.user.len + 1;

    } else if (ctx->uri_type == DAV_NEXT_URI_SLASH || ctx->uri_type == DAV_NEXT_URI_OTHER) { // prepare to rewrite "/…" to "/remote.php/dav/files/$remote_user/…"

        // test if a trailing (and not alone) slash is present and remove it
        if (r->uri.len > 1 && LAST_CHAR_OF(r->uri) == '/') {
            ending_slash = 1;
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

    // if ending slash removed, put it back temporarily
    if (ending_slash) {
        r->uri.len++;
    }

    ctx->webdav_rewritten->len = r->uri.len;
    ctx->webdav_rewritten->data = ngx_pstrdup(r->pool, &r->uri);

    // if ending slash removed, remove it again
    if (ending_slash) {
        r->uri.len--;
    }

    RETURN_500_IF(ctx->webdav_rewritten->data == NULL);

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
    r->uri = uri;

    return NGX_OK;
}

#define NGX_CONF_BUFFER  4096

ngx_int_t dav_next_read_token(ngx_conf_t *cf)
{
    u_char      *start, ch, *src, *dst;
    off_t        file_size;
    size_t       len;
    ssize_t      n, size;
    ngx_uint_t   found, need_space, last_space, sharp_comment, variable;
    ngx_uint_t   quoted, s_quoted, d_quoted, start_line;
    ngx_str_t   *word;
    ngx_buf_t   *b, *dump;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    variable = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;
    b = cf->conf_file->buffer;
    dump = cf->conf_file->dump;
    start = b->pos;
    start_line = cf->conf_file->line;

    file_size = ngx_file_size(&cf->conf_file->file.info);

    for ( ;; ) {

        if (b->pos >= b->last) {

            if (cf->conf_file->file.offset >= file_size) {

                if (cf->args->nelts > 0 || !last_space) {

                    if (cf->conf_file->file.fd == NGX_INVALID_FILE) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                           "unexpected end of parameter, "
                                           "expecting \";\"");
                        return NGX_ERROR;
                    }

                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unexpected end of file, "
                                       "expecting \";\" or \"}\"");
                    return NGX_ERROR;
                }

                return NGX_CONF_FILE_DONE;
            }

            len = b->pos - start;

            if (len == NGX_CONF_BUFFER) {
                cf->conf_file->line = start_line;

                if (d_quoted) {
                    ch = '"';

                } else if (s_quoted) {
                    ch = '\'';

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "too long parameter \"%*s...\" started",
                                       10, start);
                    return NGX_ERROR;
                }

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "too long parameter, probably "
                                   "missing terminating \"%c\" character", ch);
                return NGX_ERROR;
            }

            if (len) {
                ngx_memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = ngx_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (n != size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   ngx_read_file_n " returned "
                                   "only %z bytes instead of %z",
                                   n, size);
                return NGX_ERROR;
            }

            b->pos = b->start + len;
            b->last = b->pos + n;
            start = b->start;

            if (dump) {
                dump->last = ngx_cpymem(dump->last, b->pos, size);
            }
        }

        ch = *b->pos++;

        if (ch == LF) {
            cf->conf_file->line++;

            if (sharp_comment) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';') {
                return NGX_OK;
            }

            if (ch == '{') {
                return NGX_CONF_BLOCK_START;
            }

            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "unexpected \"%c\"", ch);
                return NGX_ERROR;
            }
        }

        if (last_space) {

            start = b->pos - 1;
            start_line = cf->conf_file->line;

            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            switch (ch) {

            case ';':
            case '{':
                if (cf->args->nelts == 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unexpected \"%c\"", ch);
                    return NGX_ERROR;
                }

                if (ch == '{') {
                    return NGX_CONF_BLOCK_START;
                }

                return NGX_OK;

            case '}':
                if (cf->args->nelts != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unexpected \"}\"");
                    return NGX_ERROR;
                }

                return NGX_CONF_BLOCK_DONE;

            case '#':
                sharp_comment = 1;
                continue;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            case '$':
                variable = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {
            if (ch == '{' && variable) {
                continue;
            }

            variable = 0;

            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (ch == '$') {
                variable = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';' || ch == '{')
            {
                last_space = 1;
                found = 1;
            }

            if (found) {
                word = ngx_array_push(cf->args);
                if (word == NULL) {
                    return NGX_ERROR;
                }

                word->data = ngx_pnalloc(cf->pool, b->pos - 1 - start + 1);
                if (word->data == NULL) {
                    return NGX_ERROR;
                }

                for (dst = word->data, src = start, len = 0;
                     src < b->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

                if (ch == ';') {
                    return NGX_OK;
                }

                if (ch == '{') {
                    return NGX_CONF_BLOCK_START;
                }

                found = 0;
            }
        }
    }
}
