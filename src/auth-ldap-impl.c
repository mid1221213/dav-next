/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-auth-ldap-impl.c
 * Implementation part of the LDAP authentication provider for dav-next
 * © Alexandre Jousset 2022-2026
 *
 * Copyright (C) 2011-2013 Valery Komarov
 * Copyright (C) 2013 Jiri Hruska
 * Copyright (C) 2015-2016 Victor Hahn Castell
 * Copyright (C) 2022-2023 Eric BLANCHARD
*/

#include "dav-next.h"
#include "utils.h"
#include "auth-ldap.h"
#include <ngx_md5.h>

#pragma GCC visibility push(hidden)

extern ngx_module_t dav_next_auth_ldap_module;

void close_connection(connection_t *c, int retry_asap);
void set_pending_reconnection(connection_t *c, ngx_msec_t reconnect_delay);
void read_handler(ngx_event_t *rev);
void lconnect(connection_t *c);
void lconnect_continue(connection_t *c);
void reconnect_handler(ngx_event_t *);
void reconnect_from_connection(connection_t *c);
void resolve_handler(ngx_resolver_ctx_t *ctx);
ngx_int_t authenticate(ngx_http_request_t *r, ctx_t *ctx, loc_conf_t *conf);
ngx_int_t search_user(ngx_http_request_t *r, ctx_t *ctx);
ngx_int_t check_user(ngx_http_request_t *r, ctx_t *ctx);
ngx_int_t search_groups(ngx_http_request_t *r, ctx_t *ctx);
ngx_int_t check_groups(ngx_http_request_t *r, ctx_t *ctx);
ngx_int_t check_bind(ngx_http_request_t *r, ctx_t *ctx);
ngx_int_t recover_bind(ngx_http_request_t *r, ctx_t *ctx);
ngx_int_t restore_handlers(ngx_connection_t *conn);
void my_free_addrs_from_url(ngx_pool_t *pool, ngx_url_t *u);

cache_t cache;

/*** Authentication cache ***/

ngx_int_t init_cache(ngx_cycle_t *cycle)
{
    static const uint16_t primes[] = {
        13, 53, 101, 151, 199, 263, 317, 383, 443, 503,
        577, 641, 701, 769, 839, 911, 983, 1049, 1109
    };

    cache_t *cache_p = &cache;
    cache_p->pool = cycle->pool;

    main_conf_t *conf = (main_conf_t *) ngx_http_cycle_get_module_main_conf(cycle, dav_next_auth_ldap_module);
    if (conf == NULL || !conf->cache_enabled) {
        return NGX_OK;
    }

    ngx_uint_t want = (conf->cache_size + 7) / 8;
    ngx_uint_t count = 0;
    for (ngx_uint_t i = 0; i < sizeof(primes)/sizeof(primes[0]); i++) {
        count = primes[i];
        if (count >= want) {
            break;
        }
    }

    cache_p->expiration_time = conf->cache_expiration_time;
    cache_p->num_buckets = count;
    cache_p->elts_per_bucket = 8;

    DEBUG2(cycle->log, 0, "allocating %ud bytes of LDAP cache (ttl=%dms)", cache_p->num_buckets * cache_p->elts_per_bucket * sizeof(cache_elt_t), cache_p->expiration_time);

    cache_p->buckets = (cache_elt_t *) ngx_calloc(count * 8 * sizeof(cache_elt_t), cycle->log);
    if (cache_p->buckets == NULL) {
        ERROR(ERR, cycle->log, 0, "unable to allocate memory for LDAP cache");
        return NGX_ERROR;
    }

    // initialize the groups array in each cache entry
    cache_elt_t *cache_entry = cache_p->buckets;
    for (ngx_uint_t i = 0; i < cache_p->num_buckets * cache_p->elts_per_bucket; i++, cache_entry++) {
        ngx_array_init(&cache_entry->groups, cache_p->pool, DEFAULT_GROUPS_COUNT, sizeof(ngx_str_t));
    }

    return NGX_OK;
}

ngx_int_t check_cache(ngx_http_request_t *r, ctx_t *ctx, cache_t *cache_p, server_t *server)
{
    ctx->cache_small_hash = ngx_murmur_hash2(r->headers_in.user.data, r->headers_in.user.len) ^ (uint32_t) (ngx_uint_t) server;

    ngx_md5_t md5ctx;
    ngx_md5_init(&md5ctx);
    ngx_md5_update(&md5ctx, r->headers_in.user.data, r->headers_in.user.len);
    ngx_md5_update(&md5ctx, server, offsetof(server_t, free_connections));
    ngx_md5_update(&md5ctx, r->headers_in.passwd.data, r->headers_in.passwd.len);
    ngx_md5_final(ctx->cache_big_hash, &md5ctx);

    ctx->cache_bucket = &cache_p->buckets[ctx->cache_small_hash % cache_p->num_buckets];

    cache_elt_t *elt = ctx->cache_bucket;
    ngx_msec_t time_limit = ngx_current_msec - cache_p->expiration_time;
    for (ngx_uint_t i = 0; i < cache_p->elts_per_bucket; i++, elt++) {

        if (elt->small_hash == ctx->cache_small_hash && elt->time > time_limit &&
            memcmp(elt->big_hash, ctx->cache_big_hash, 16) == 0) {

            if (elt->outcome == OUTCOME_ALLOW || elt->outcome == OUTCOME_CACHED_ALLOW) {

                // restore the cached groups to the current context
                ctx->groups = elt->groups;
                ERROR_A(WARN, r->connection->log, 0, "restoring groups (%ud values) from cache", ctx->groups.nelts);
                DEBUG1(r->connection->log, 0, "restoring groups (%ud values) from cache", ctx->groups.nelts);
            }

            return elt->outcome;
        }
    }

    return -1; // not found
}

void update_cache(ctx_t *ctx, cache_t *cache_p, outcome_t outcome)
{
    cache_elt_t *elt = ctx->cache_bucket;
    cache_elt_t *oldest_elt = elt;

    for (ngx_uint_t i = 1; i < cache_p->elts_per_bucket; i++, elt++) {
        if (elt->time < oldest_elt->time) {
            oldest_elt = elt;
        }
    }

    oldest_elt->time = ngx_current_msec;
    oldest_elt->outcome = outcome;
    oldest_elt->small_hash = ctx->cache_small_hash;
    ngx_memcpy(oldest_elt->big_hash, ctx->cache_big_hash, 16);

    for (ngx_uint_t i = 0; i < oldest_elt->groups.nelts; i++) {
        ngx_pfree(cache.pool, ((ngx_str_t *) oldest_elt->groups.elts) + i);
    }
    ngx_array_init(&oldest_elt->groups, cache.pool, DEFAULT_GROUPS_COUNT, sizeof(ngx_str_t));
    for (ngx_uint_t i = 0; i < ctx->groups.nelts; i++) {
        ngx_str_t *src_group = ((ngx_str_t *) ctx->groups.elts) + i;
        ngx_str_t *dst_group = ngx_array_push(&oldest_elt->groups);

        dst_group->len = src_group->len;
        dst_group->data = ngx_pnalloc(cache.pool, dst_group->len);
        ngx_memcpy(dst_group->data, src_group->data, dst_group->len);
    }
}


/*** OpenLDAP SockBuf implementation over nginx socket functions ***/

int sb_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
    sbiod->sbiod_pvt = arg;

    return 0;
}

int sb_remove(Sockbuf_IO_Desc *sbiod)
{
    connection_t *c = (connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_remove() Cnx[%d]", c->cnx_idx);
    (void)c; /* 'c' would be left unused on debug builds */

    sbiod->sbiod_pvt = NULL;

    return 0;
}

int sb_close(Sockbuf_IO_Desc *sbiod)
{
    connection_t *c = (connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_close() Cnx[%d]", c->cnx_idx);

    if (!c->conn.connection->read->error && !c->conn.connection->read->eof) {
        if (ngx_shutdown_socket(c->conn.connection->fd, SHUT_RDWR) == -1) {
            ngx_connection_error(c->conn.connection, ngx_socket_errno, ngx_shutdown_socket_n " failed");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_close() Cnx[%d] shutdown failed", c->cnx_idx);
            close_connection(c, 0);
            return -1;
        }
    }

    return 0;
}

int sb_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
    connection_t *c = (connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_ctrl(opt=%d) Cnx[%d]", opt, c->cnx_idx);

    switch (opt) {
        case LBER_SB_OPT_DATA_READY:
            if (c->conn.connection->read->ready) {
                return 1;
            }
            return 0;
    }

    return 0;
}

ber_slen_t sb_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    connection_t *c = (connection_t *)sbiod->sbiod_pvt;
    ber_slen_t ret;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_read(len=%d) Cnx[%d]", len, c->cnx_idx);

    ret = c->conn.connection->recv(c->conn.connection, buf, len);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_read Cnx[%d] recv ret=%d", c->cnx_idx, ret);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return -1;
    }

    return ret;
}

ber_slen_t sb_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    connection_t *c = (connection_t *)sbiod->sbiod_pvt;
    ber_slen_t ret;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_write(len=%d) Cnx[%d]", len, c->cnx_idx);

    ret = c->conn.connection->send(c->conn.connection, buf, len);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "sb_write Cnx[%d] ret=%d", c->cnx_idx, ret);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return 0;
    }

    return ret;
}

Sockbuf_IO sbio =
{
    sb_setup,
    sb_remove,
    sb_ctrl,
    sb_read,
    sb_write,
    sb_close
};


/*** Asynchronous LDAP connection handling ***/

void close_connection(connection_t *c, int retry_asap)
{
    ngx_queue_t *q;
    ngx_msec_t reconnect_delay = retry_asap ? RECONNECT_ASAP_MS : c->server->reconnect_timeout; // Default reconnect delay
    connection_state_t saved_state;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "close_connection: Cnx[%d] retry_asap=%d state=%d", c->cnx_idx, retry_asap, c->state);

    if (c->state == STATE_DISCONNECTING) {
        // Already in DISCONNECTING state. break here to avoid recuse in close_connection
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "close_connection: Cnx[%d] Already in DISCONNECTING state", c->cnx_idx);
        return;
    }

    // Temporary DISCONNECTING state to avoid loops in close_connection
    saved_state = c->state;
    c->state = STATE_DISCONNECTING;

    if (c->ld) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "close_connection: Cnx[%d] Unbinding from the server \"%V\")",
            c->cnx_idx, &c->server->users_url.url);
        ldap_unbind_ext(c->ld, NULL, NULL);
        /* Unbind is always synchronous, even though the function name does not end with an '_s'. */
        c->ld = NULL;
    }

    if (c->conn.connection) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "close_connection: Cnx[%d] Closing connection (fd=%d)",
            c->cnx_idx, c->conn.connection->fd);

        if (c->conn.connection->ssl) {
            c->conn.connection->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(c->conn.connection);
        }

        ngx_close_connection(c->conn.connection);
        c->conn.connection = NULL;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "close_connection: Cnx[%d] Closed", c->cnx_idx);

    q = ngx_queue_head(&c->server->free_connections);
    while (q != ngx_queue_sentinel(&c->server->free_connections)) {
        if (q == &c->queue) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                "close_connection: removing cnx [%d] from free queue",
                c->cnx_idx);
            ngx_queue_remove(q);
            break;
        }
        q = ngx_queue_next(q);
    }

    c->rctx = NULL;
    c->state = saved_state; // Restore initial state
    if (c->state != STATE_DISCONNECTED) {
        c->state = STATE_DISCONNECTED;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "close_connection: Cnx[%d] set pending reconnection",
            c->cnx_idx);
        set_pending_reconnection(c, reconnect_delay);
    }
}

void wake_request(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "wake_request: Waking authentication request \"%V\"",
        &r->request_line);
    ngx_http_core_run_phases(r);
}

int get_connection(ctx_t *ctx)
{
    server_t *server;
    ngx_queue_t *q;
    connection_t *c;

    /*
     * If we already have a connection, just say we got them one.
     */
    if (ctx->c != NULL)
        return 1;

    server = ctx->server;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
        "get_connection: Wants a free connection to \"%V\"", &server->alias);

    if (!ngx_queue_empty(&server->free_connections)) {
        q = ngx_queue_last(&server->free_connections);
        ngx_queue_remove(q);
        c = ngx_queue_data(q, connection_t, queue);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
            "get_connection: Got cnx [%d] from free queue", c->cnx_idx);
        c->rctx = ctx;
        ctx->c = c;
        ctx->replied = 0;
        return 1;
    }

    /* Check if we have pending (waiting reconnect) connection */
    if (!ngx_queue_empty(&server->pending_reconnections)) {
        q = ngx_queue_head(&server->pending_reconnections);
        c = ngx_queue_data(q, connection_t, queue_pending);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0,
            "get_connection: Got cnx [%d] from pending queue -> shorten reconnect timer", c->cnx_idx);
        /* Use the shortest the reconnection delay as we really need a new connection here */
        ngx_del_timer(&c->reconnect_event); // Cancel the reconnect timer
        ngx_add_timer(&c->reconnect_event, RECONNECT_ASAP_MS);
    }

    q = ngx_queue_next(&server->waiting_requests);
    while (q != ngx_queue_sentinel(&server->waiting_requests)) {
        if (q == &ctx->queue) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0, "get_connection: Tried to insert a same request");
            return 0;
        }
        q = ngx_queue_next(q);
    }
    ngx_queue_insert_head(&server->waiting_requests, &ctx->queue);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0, "get_connection: No connection available at the moment, waiting...");
    return 0;
}

void return_connection(connection_t *c)
{
    ngx_queue_t *q;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "return_connection: Marking the connection [%d] to \"%V\" as free",
        c->cnx_idx, &c->server->alias);

    if (c->rctx != NULL) {
        c->rctx->c = NULL;
        c->rctx = NULL;
        c->msgid = -1;
        c->state = STATE_READY;
    }

    ngx_queue_insert_head(&c->server->free_connections, &c->queue);
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "return_connectionn: Cnx[%d] Ready", c->cnx_idx);
    if (!ngx_queue_empty(&c->server->waiting_requests)) {
        q = ngx_queue_last(&c->server->waiting_requests);
        ngx_queue_remove(q);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "return_connection: Cnx[%d] Wakeup a waiting request", c->cnx_idx);
        wake_request((ngx_queue_data(q, ctx_t, queue))->r);
    }
}

void set_pending_reconnection(connection_t *c, ngx_msec_t reconnect_delay)
{
    ngx_queue_t *q;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "set_pending_reconnection: Cnx[%d] reconnection scheduled in %d ms", c->cnx_idx, reconnect_delay);
    ngx_add_timer(&c->reconnect_event, reconnect_delay);

    /* Check if connection is already in the pending queue */
    for (q = ngx_queue_head(&c->server->pending_reconnections);
        q != ngx_queue_sentinel(&c->server->pending_reconnections);
        q = ngx_queue_next(q))
    {
        if (q == &c->queue_pending) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "http_auth_ldap: set_pending_reconnection: Connection already in pending queue");
            return;
        }
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "set_pending_reconnection: Connection [%d] inserted in pending queue", c->cnx_idx);
    ngx_queue_insert_tail(&c->server->pending_reconnections, &c->queue_pending);
}

void reply_connection(connection_t *c, int error_code, char* error_msg)
{
    ctx_t *ctx = c->rctx;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "reply_connection: cnx[%d] LDAP request to \"%V\" has finished",
        c->cnx_idx, &c->server->alias);

    ctx->replied = 1;
    ctx->error_code = error_code;
    if (error_msg) {
        ctx->error_msg.len = ngx_strlen(error_msg);
        ctx->error_msg.data = ngx_palloc(ctx->r->pool, ctx->error_msg.len);
        ngx_memcpy(ctx->error_msg.data, error_msg, ctx->error_msg.len);
    } else {
        ctx->error_msg.len = 0;
        ctx->error_msg.data = NULL;
    }

    wake_request(ctx->r);
}

void dummy_write_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http_auth_ldap: Dummy write handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        close_connection(((ngx_connection_t *) wev->data)->data, 0);
    }
}


/* Make sure the event handlers are activated. */
ngx_int_t restore_handlers(ngx_connection_t *conn)
{
    ngx_int_t rc;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, conn->log, 0, "http_auth_ldap: Restoring event handlers. read=%d write=%d", conn->read->active, conn->write->active);

    if (!conn->read->active) {
        rc = ngx_add_event(conn->read, NGX_READ_EVENT, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (!conn->write->active &&
        (conn->write->handler != dummy_write_handler)) {
        rc = ngx_add_event(conn->write, NGX_WRITE_EVENT, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

void connection_established(connection_t *c)
{
    ngx_connection_t *conn;
    Sockbuf *sb;
    ngx_int_t rc;
    struct berval cred;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "connection_established: Cnx[%d] established", c->cnx_idx);

    conn = c->conn.connection;
    ngx_del_timer(conn->read);
    conn->write->handler = dummy_write_handler;


    /* Initialize OpenLDAP on the connection */

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "connection_established: Cnx[%d] initializing LDAP using URL \"%V\"",
        c->cnx_idx, &c->server->users_url.url);
    rc = ldap_init_fd(c->conn.connection->fd, LDAP_PROTO_EXT, (const char *) c->server->users_url.url.data, &c->ld);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "connection_established: ldap_init_fd() failed (%d: %s)", rc, ldap_err2string(rc));
        close_connection(c, 0);
        return;
    }

    if (c->server->referral == 0) {
        rc = ldap_set_option(c->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
        if (rc != LDAP_OPT_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "connection_established: ldap_set_option() failed (%d: %s)", rc, ldap_err2string(rc));
            close_connection(c, 0);
            return;
        }
    }

    rc = ldap_get_option(c->ld, LDAP_OPT_SOCKBUF, (void *) &sb);
    if (rc != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "connection_established: ldap_get_option() failed (%d: %s)", rc, ldap_err2string(rc));
        close_connection(c, 0);
        return;
    }

    ber_sockbuf_add_io(sb, &sbio, LBER_SBIOD_LEVEL_PROVIDER, (void *) c);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "connection_established: Cnx[%d] LDAP initialized", c->cnx_idx);


    /* Perform initial bind to the server */

    cred.bv_val = (char *) c->server->bind_dn_passwd.data;
    cred.bv_len = c->server->bind_dn_passwd.len;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
        "connection_established: Cnx[%d] Initial binding ...", c->cnx_idx);
    rc = ldap_sasl_bind(c->ld, (const char *) c->server->bind_dn.data, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &c->msgid);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "connection_established: [%d] initial ldap_sasl_bind() failed (%d: %s)",
            c->cnx_idx, rc, ldap_err2string(rc));
        close_connection(c, 0);
        return;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "connection_established: [%d] initial ldap_sasl_bind() -> msgid=%d",
        c->cnx_idx, c->msgid);

    c->state = STATE_INITIAL_BINDING;
    ngx_add_timer(c->conn.connection->read, c->server->bind_timeout);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "connection_established: [%d] waiting initial bind response (timeout=%d)",
        c->cnx_idx, c->server->bind_timeout);
}

void ssl_handshake_handler(ngx_connection_t *conn, ngx_flag_t validate)
{
    connection_t *c;
    c = conn->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: SSL handshake handler (validate=%d)", validate);

    if (conn->ssl->handshaked) {
        #if OPENSSL_VERSION_NUMBER >= 0x10002000
        if (validate) { // verify remote certificate if requested
          X509 *cert = SSL_get_peer_certificate(conn->ssl->connection);
          long chain_verified = SSL_get_verify_result(conn->ssl->connection);

          int addr_verified;
          if (c->server->ssl_check_cert == SSL_CERT_VERIFY_CHAIN) {
            // chain_verified is enough, not requiring full name/IP verification
            addr_verified = 1;

          } else {
            // verify hostname/IP
            char *hostname = c->server->users_url.ludpp->lud_host;
            addr_verified = X509_check_host(cert, hostname, 0, 0, 0);

            if (!addr_verified) { // domain not in cert? try IP
              size_t len; // get IP length

              struct sockaddr *conn_sockaddr = NULL;
              if (conn->sockaddr != NULL) conn_sockaddr = conn->sockaddr;
              else if (c->conn.sockaddr != NULL) conn_sockaddr = c->conn.sockaddr;
              else conn_sockaddr = &c->server->users_url.parsed_url.sockaddr.sockaddr;

              if (conn_sockaddr->sa_family == AF_INET) len = 4;
              else if (conn_sockaddr->sa_family == AF_INET6) len = 16;
              else { // very unlikely indeed
                close_connection(c, 0);
                return;
              }
              addr_verified = X509_check_ip(cert, (const unsigned char*)conn_sockaddr->sa_data, len, 0);
            }
          }

          // Find anything fishy?
          if ( !(cert && addr_verified && chain_verified == X509_V_OK) ) {
            if (!addr_verified) {
              ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "http_auth_ldap: Remote side presented invalid SSL certificate: "
                "does not match address (neither server's domain nor IP in certificate's CN or SAN)");
                fprintf(stderr, "DEBUG: SSL cert domain mismatch\n"); fflush(stderr);
            } else {
              ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "http_auth_ldap: Remote side presented invalid SSL certificate: error %l, %s",
                chain_verified, X509_verify_cert_error_string(chain_verified));
            }
            close_connection(c, 0);
            return;
          }
        }
        #endif

        // handshaked validation successful -- or not required in the first place
        conn->read->handler = &read_handler;
        restore_handlers(conn);
        connection_established(c);
        return;
    }
    else { // handshake failed
      ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL handshake failed");
      close_connection(c, 0);
    }
}

void ssl_handshake_validating_handler(ngx_connection_t *conn)
{
    ssl_handshake_handler(conn, 1);
}

void ssl_handshake_non_validating_handler(ngx_connection_t *conn)
{
    ssl_handshake_handler(conn, 0);
}

typedef void (*ssl_callback)(ngx_connection_t *conn);

void ssl_handshake(connection_t *c)
{
    ngx_int_t rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: SSL handshake");

    c->conn.connection->pool = c->pool;
    rc = ngx_ssl_create_connection(c->ssl, c->conn.connection, NGX_SSL_BUFFER | NGX_SSL_CLIENT);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL initialization failed");
        close_connection(c, 0);
        return;
    }

    c->log->action = "SSL handshaking to LDAP server";
    ngx_connection_t *transport = c->conn.connection;

    ssl_callback callback;
    if (c->server->ssl_check_cert) {
      // load CA certificates: custom ones if specified, default ones instead
      if (c->server->ssl_ca_file.data || c->server->ssl_ca_dir.data) {
        int setcode = SSL_CTX_load_verify_locations(transport->ssl->session_ctx,
          (char*)(c->server->ssl_ca_file.data), (char*)(c->server->ssl_ca_dir.data));
        if (setcode != 1) {
          unsigned long error_code = ERR_get_error();
          char *error_msg = ERR_error_string(error_code, NULL);
          ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "http_auth_ldap: SSL initialization failed. Could not set custom CA certificate location. "
            "Error: %lu, %s", error_code, error_msg);
        }
      }
      int setcode = SSL_CTX_set_default_verify_paths(transport->ssl->session_ctx);
      if (setcode != 1) {
        unsigned long error_code = ERR_get_error();
        char *error_msg = ERR_error_string(error_code, NULL);
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
          "http_auth_ldap: SSL initialization failed. Could not use default CA certificate location. "
          "Error: %lu, %s", error_code, error_msg);
      }

      // use validating version of next function
      callback = &ssl_handshake_validating_handler;
    } else {
      // use non-validating version of next function
      callback = &ssl_handshake_non_validating_handler;
    }

    rc = ngx_ssl_handshake(transport);
    if (rc == NGX_AGAIN) {
        transport->ssl->handler = callback;
        return;
    }

    (*callback)(transport);
    return;
}

void connect_handler(ngx_event_t *wev)
{
    ngx_connection_t *conn;
    connection_t *c;
    int keepalive;

    conn = wev->data;
    c = conn->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "connect_handler: Cnx[%d]", c->cnx_idx);

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        close_connection(c, 0);
        return;
    }

    keepalive = 1;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_KEEPALIVE, (const void *) &keepalive, sizeof(int)) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno, "connect_handler: setsockopt(SO_KEEPALIVE) failed");
    }

    if (ngx_strcmp(c->server->users_url.ludpp->lud_scheme, "ldaps") == 0) {
        ssl_handshake(c);
        return;
    }

    connection_established(c);
}

void read_handler(ngx_event_t *rev)
{
    ngx_connection_t *conn;
    connection_t *c;
    ngx_int_t rc;
    struct timeval timeout = {0, 0};
    LDAPMessage *result;
    int error_code;
    char *error_msg;
    char *dn;

    conn = rev->data;
    c = conn->data;

    DEBUG1(rev->log, 0, "Cnx[%d]", c->cnx_idx);

    if (c->ld == NULL) {
        ERROR_A(WARN, rev->log, 0, "Cnx[%d] no ldap handler (already closed)", c->cnx_idx);
        close_connection(c, 0);
        return;
    }

    if (rev->timedout) {
        ERROR_A(ERR, c->log, NGX_ETIMEDOUT, "Cnx[%d] read timed out (state=%d)", c->cnx_idx, c->state);
        conn->timedout = 1;
        close_connection(c, 1);
        return;
    }

    c->log->action = "reading response from LDAP";

    for (;;) {
        rc = ldap_result(c->ld, LDAP_RES_ANY, 0, &timeout, &result);
        if (rc < 0) {
            int reconnect_asap = 0;

            // if LDAP_SERVER_DOWN (usually timeouts or server disconnects)
            if (rc == LDAP_SERVER_DOWN) {
                if (c->server->max_down_retries_count < c->server->max_down_retries) {
                    /**
                        update counter (this is always reset in
                        connect() for a successful ldap
                        connection
                    **/
                    c->server->max_down_retries_count++;
                    ngx_log_error(NGX_LOG_ERR, c->log, 0, "read_handler: Cnx[%d] LDAP_SERVER_DOWN: retry count: %d",
                        c->cnx_idx, c->server->max_down_retries_count);
                    reconnect_asap = 1;
                } else {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "read_handler: Cnx[%d] LDAP_SERVER_DOWN: No more reconnect retry", c->cnx_idx);
                }
                close_connection(c, reconnect_asap);
            } else {
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "read_handler: Cnx[%d] ldap_result() failed (%d: %s)",
                c->cnx_idx, rc, ldap_err2string(rc));
            }

            return;
        }
        if (rc == 0) {
            // Timeout ({0, 0}) => No result message
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "read_handler: Cnx[%d] ldap_result() -> rc=0", c->cnx_idx);
            break;
        }
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0, "read_handler: Cnx[%d] ldap_result() -> rc=%d, msgid=%d, msgtype=%d",
            c->cnx_idx, rc, ldap_msgid(result), ldap_msgtype(result));

        if (ldap_msgid(result) != c->msgid) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                "read_handler: Cnx[%d] Message with unknown ID received, ignoring.", c->cnx_idx);
            ldap_msgfree(result);
            continue;
        }

        rc = ldap_parse_result(c->ld, result, &error_code, NULL, &error_msg, NULL, NULL, 0);
        if (rc == LDAP_NO_RESULTS_RETURNED) {
            error_code = LDAP_NO_RESULTS_RETURNED;
            error_msg = NULL;
        } else if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "read_handler: Cnx[%d] ldap_parse_result() failed (%d: %s)",
                c->cnx_idx, rc, ldap_err2string(rc));
            ldap_msgfree(result);
            close_connection(c, 1);
            return;
        }

        switch (c->state) {
            case STATE_INITIAL_BINDING:
                if (ldap_msgtype(result) != LDAP_RES_BIND) {
                    break;
                }
                ngx_del_timer(conn->read);
                if (error_code == LDAP_SUCCESS) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "read_handler: Cnx[%d] Initial bind successful", c->cnx_idx);
                    c->state = STATE_READY;
                    return_connection(c);
                } else {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0, "read_handler: Cnx[%d] Initial bind failed (%d: %s [%s])",
                        c->cnx_idx, error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                    ldap_memfree(error_msg);
                    ldap_msgfree(result);
                    close_connection(c, 0);
                    return;
                }
                break;

            case STATE_BINDING:
                if (ldap_msgtype(result) != LDAP_RES_BIND) {
                    break;
                }
                ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0, "read_handler: Cnx[%d] Received bind response (%d: %s [%s])",
                    c->cnx_idx, error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                reply_connection(c, error_code, error_msg);
                break;

            case STATE_SEARCHING:
                if (ldap_msgtype(result) == LDAP_RES_SEARCH_ENTRY) {
                    DEBUG1(c->log, 0, "Cnx[%d] received a search entry", c->cnx_idx);
                    ERROR_A(WARN, c->log, 0, "Cnx[%d] received a search entry", c->cnx_idx);

                    if (c->rctx->dn.data == NULL) {
                        dn = ldap_get_dn(c->ld, result);
                        if (dn != NULL) {
                            DEBUG2(c->log, 0, "Cnx[%d] found entry with DN \"%s\"", c->cnx_idx, dn);
                            ERROR_A(WARN, c->log, 0, "Cnx[%d] found entry with DN \"%s\"", c->cnx_idx, dn);
                            c->rctx->dn.len = ngx_strlen(dn);
                            c->rctx->dn.data = ngx_palloc(c->rctx->r->pool, c->rctx->dn.len + 1);
                            ngx_memcpy(c->rctx->dn.data, dn, c->rctx->dn.len + 1);
                            ldap_memfree(dn);
                        }
                    }

                    // iterate through each attribute in the entry.
                    BerElement *ber = NULL;
                    for (char *attr = ldap_first_attribute(c->ld, result, &ber); attr != NULL; attr = ldap_next_attribute(c->ld, result, ber)) {

                        // get all values for each attribute
                        struct berval **vals = ldap_get_values_len(c->ld, result, attr);
                        if (vals != NULL) {

                            sanitize_str((u_char *) attr);

                            // save group values in the context
                            if (ngx_strcmp(c->rctx->server->group_attribute.data, attr) == 0) {
                                struct berval *val;
                                // iterate through each value in the group attribute
                                for (ngx_int_t i = 0; (val = vals[i]) != NULL; i++) {
                                    DEBUG4(c->log, 0, "cnx[%d] received attribute %s#%d: %s", c->cnx_idx, attr, i, val->bv_val);
                                    ERROR_A(WARN, c->log, 0, "cnx[%d] received attribute %s#%d: %s", c->cnx_idx, attr, i, val->bv_val);
                                    ngx_str_t *group = ngx_array_push(&c->rctx->groups);

                                    if (group == NULL) {
                                        ERROR(CRIT, c->log, 0, "internal error");
                                        ldap_value_free_len(vals);
                                        ldap_memfree(attr);
                                        break;
                                    }

                                    group->len = val->bv_len;
                                    group->data = ngx_pnalloc(c->rctx->r->pool, group->len);
                                    ngx_memcpy(group->data, val->bv_val, val->bv_len);
                                }
                            } else {
                                DEBUG2(c->log, 0, "cnx[%d] received NO value for attribute %s", c->cnx_idx, attr);
                            }

                            ldap_value_free_len(vals);
                        }

                        ldap_memfree(attr);
                    }

                    if (ber != NULL) {
                        ber_free(ber, 0);
                    }

                    // reply_connection(c, 0, NULL); // HACK: https://github.com/Ericbla/nginx-auth-ldap/pull/3

                } else if (ldap_msgtype(result) == LDAP_RES_SEARCH_RESULT) {
                    ERROR_A(WARN, c->log, 0, "Cnx[%d] received search end of results (%d: %s [%s])", c->cnx_idx, error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                    reply_connection(c, error_code, error_msg);
                }

                break;

            case STATE_COMPARING:
                if (ldap_msgtype(result) != LDAP_RES_COMPARE) {
                    break;
                }
                ERROR_A(WARN, c->log, 0, "Cnx[%d] received comparison result (%d: %s [%s])", c->cnx_idx, error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                reply_connection(c, error_code, error_msg);
                break;

            default:
                break;
        }

        ldap_memfree(error_msg);
        ldap_msgfree(result);
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        close_connection(c, 1);
        return;
    }
}

void lconnect(connection_t *c)
{
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "connect: Cnx[%d] Server \"%V\" connecting ...",
            c->cnx_idx, &c->server->alias);

    // clear and free any previous addrs from parsed_url, so that we can resolve again the LDAP server hostname
    my_free_addrs_from_url(c->main_cnf->cnf_pool, &c->server->users_url.parsed_url);

    c->server->users_url.parsed_url.no_resolve = 0; // Try to resolve this time
    if (ngx_parse_url(c->pool, &c->server->users_url.parsed_url) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "connect: Hostname \"%V\" not found with system resolver, try with DNS",
                &c->server->users_url.parsed_url.host);
        // Try to resolve the hostname through the resolver
        if (c->main_cnf->resolver == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "connect: No resolver configured");
            return;
        }
        ngx_resolver_ctx_t *resolver_ctx, temp;
        temp.name = c->server->users_url.parsed_url.host;
        resolver_ctx = ngx_resolve_start(c->main_cnf->resolver, &temp);
        if (resolver_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "connect: Unable to start the resolver");
            return;
        }
        if (resolver_ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "connect: No resolver defined to resolve %V",
                    c->server->users_url.parsed_url.host);
            return;
        }
        resolver_ctx->name = c->server->users_url.parsed_url.host;
        resolver_ctx->handler = resolve_handler;
        resolver_ctx->data = c;
        resolver_ctx->timeout = c->main_cnf->resolver_timeout;
        c->resolver_ctx = resolver_ctx;
        if (ngx_resolve_name(resolver_ctx) != NGX_OK) {
            c->resolver_ctx = NULL;
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "connect: Resolve %V failed", c->server->users_url.parsed_url.host);
            return;
        }
        // The DNS Querry has been triggered. Let the resolve_handler now take the control of the flow.
        return;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "connect: server \"%V\" (naddrs is now %d).",
            &c->server->alias, c->server->users_url.parsed_url.naddrs);

    // Continue with the rest of the connection establishement
    lconnect_continue(c);
}

void lconnect_continue(connection_t *c)
{
    ngx_peer_connection_t *pconn;
    ngx_connection_t *conn;
    ngx_addr_t *addr;
    ngx_int_t rc;

    if (c->server->users_url.parsed_url.naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "connect_continue: Cnx[%d] No addr for server", c->cnx_idx);
        return;
    }

    addr = &c->server->users_url.parsed_url.addrs[ngx_random() % c->server->users_url.parsed_url.naddrs];

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "connect_continue: Cnx[%d] Connecting to LDAP server IP@ %V ...",
            c->cnx_idx, &addr->name);

    pconn = &c->conn;
    pconn->sockaddr = addr->sockaddr;
    pconn->socklen = addr->socklen;
    pconn->name = &addr->name;
    pconn->get = ngx_event_get_peer;
    pconn->log = c->log;
    pconn->log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(pconn);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "connect_continue: ngx_event_connect_peer() -> %d.", rc);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "connect_continue: Cnx[%d] Unable to connect to LDAP server \"%V\".",
            c->cnx_idx, &addr->name);
        set_pending_reconnection(c, c->server->reconnect_timeout);
        return;
    }

    conn = pconn->connection;
    conn->data = c;
    conn->pool = c->pool;
    conn->write->handler = connect_handler;
    conn->read->handler = read_handler;
    ngx_add_timer(conn->read, c->server->connect_timeout);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "connect_continue: [%d] Waiting connection response (timeout=%d)",
        c->cnx_idx, c->server->connect_timeout);

    c->server->max_down_retries_count = 0;   /* reset retries count */
    c->state = STATE_CONNECTING;
}

void connection_cleanup(void *data)
{
    close_connection((connection_t *) data, 0);
}

void reconnect_handler(ngx_event_t *ev)
{
    ngx_connection_t *conn = ev->data;
    connection_t *c = conn->data;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ev->log, 0,
        "reconnect_handler: ev=0x%p, conn=0x%p, c=0x%p", ev, conn, c);

    reconnect_from_connection(c);
}

void reconnect_from_connection(connection_t *c)
{
    ngx_queue_t *q;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "reconnect_from_connection: Cnx[%d] c=0x%p", c->cnx_idx, c);

    /* Remove this connection from the pending reconnection queue */
    for (q = ngx_queue_head(&c->server->pending_reconnections);
        q != ngx_queue_sentinel(&c->server->pending_reconnections);
        q = ngx_queue_next(q))
    {
        if (q == &c->queue_pending) {
            ngx_queue_remove(q);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                "reconnect_from_connection: Cnx[%d] removed from pending reconnection queue", c->cnx_idx);
            break;
        }
    }
    lconnect(c);
}

void my_free_addrs_from_url(ngx_pool_t *pool, ngx_url_t *u)
{
    ngx_addr_t       *addr;
    ngx_uint_t        i;

    if (u == NULL || u->addrs == NULL) {
        return;
    }

    for (i = 0; i < u->naddrs; i++) {
        addr = &u->addrs[i];
        if (addr != NULL) {
            if (addr->name.data != NULL) {
                ngx_pfree(pool, addr->name.data);
                addr->name.data = NULL;
                addr->name.len = 0;
            }
            if (addr->sockaddr != NULL) {
                ngx_pfree(pool, addr->sockaddr);
                addr->sockaddr = NULL;
                addr->socklen = 0;
            }
        }
    }

    if (u->addrs != NULL) {
        ngx_pfree(pool, u->addrs);
        u->addrs = NULL;
        u->naddrs = 0;
    }
}

/* Duplicated from ngnx_inet.c (as it is a static function in Nginx) */
ngx_int_t my_ngx_inet_add_addr(ngx_pool_t *pool, ngx_url_t *u, struct sockaddr *sockaddr,
    socklen_t socklen, ngx_uint_t total)
{
    u_char           *p;
    size_t            len;
    ngx_uint_t        i, nports;
    ngx_addr_t       *addr;
    struct sockaddr  *sa;

    nports = u->last_port ? u->last_port - u->port + 1 : 1;
    if (u->addrs == NULL) {
        u->addrs = ngx_palloc(pool, total * nports * sizeof(ngx_addr_t));
        if (u->addrs == NULL) {
            return NGX_ERROR;
        }
    }
    for (i = 0; i < nports; i++) {
        sa = ngx_pcalloc(pool, socklen);
        if (sa == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(sa, sockaddr, socklen);
        ngx_inet_set_port(sa, u->port + i);
        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            len = NGX_INET6_ADDRSTRLEN + sizeof("[]:65536") - 1;
            break;
#endif

        default: /* AF_INET */
            len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
        }
        p = ngx_pnalloc(pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }
        len = ngx_sock_ntop(sa, socklen, p, len, 1);
        addr = &u->addrs[u->naddrs++];
        addr->sockaddr = sa;
        addr->socklen = socklen;
        addr->name.len = len;
        addr->name.data = p;
    }
    return NGX_OK;
}

void resolve_handler(ngx_resolver_ctx_t *ctx)
{
    connection_t *c = ctx->data;
    ngx_uint_t i;
    ngx_resolver_addr_t *res_addr;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "resolve_handler: Cnx[%d] server \"%V\"",
        c->cnx_idx, &c->server->alias);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "http_auth_ldap: resolve_handler: %V could not be resolved (%i: %s)",
            &ctx->name, ctx->state, ngx_resolver_strerror(ctx->state));
        return;
    }
    ngx_resolve_name_done(ctx);
    c->resolver_ctx = NULL;

    // Clear and free any previous addrs in parsed_url
    my_free_addrs_from_url(c->main_cnf->cnf_pool, &c->server->users_url.parsed_url);

    u_char ip_addr_str[INET6_ADDRSTRLEN +1]; // Buffer for IPv4 or IPv6 address strings
    // Update the parsed_url with the addresses resolved by DNS
    for (i = 0, res_addr = ctx->addrs; res_addr != NULL && i < ctx->naddrs; i++, res_addr++) {
        bzero(ip_addr_str, sizeof(ip_addr_str));
        ngx_sock_ntop(res_addr->sockaddr, res_addr->socklen, ip_addr_str, sizeof(ip_addr_str) -1, 0);
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "resolve_handler: Cnx[%d] Found [%d] %V -> %s",
            c->cnx_idx, i, &ctx->name, ip_addr_str);
        my_ngx_inet_add_addr(c->main_cnf->cnf_pool, &c->server->users_url.parsed_url,
            res_addr->sockaddr, res_addr->socklen, ctx->naddrs);
    }

    // Go on the the rest of the connection establishment
    lconnect_continue(c);
}

ngx_int_t init_connections(ngx_cycle_t *cycle)
{
    connection_t *c;
    main_conf_t *halmcf;
    server_t *server;
    ngx_pool_cleanup_t *cleanup;
    ngx_connection_t *dummy_conn;
    ngx_uint_t i, j;
    int option;

    halmcf = ngx_http_cycle_get_module_main_conf(cycle, dav_next_auth_ldap_module);
    if (halmcf == NULL || halmcf->servers == NULL) {
          return NGX_OK;
    }

    option = LDAP_VERSION3;
    ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &option);

    for (i = 0; i < halmcf->servers->nelts; i++) {
        server = &((server_t *) halmcf->servers->elts)[i];
        ngx_queue_init(&server->free_connections);
        ngx_queue_init(&server->waiting_requests);
        ngx_queue_init(&server->pending_reconnections);
        if (server->connections <= 1) {
            server->connections = 1;
        }

        for (j = 0; j < server->connections; j++) {
            c = ngx_pcalloc(cycle->pool, sizeof(connection_t));
            cleanup = ngx_pool_cleanup_add(cycle->pool, 0);
            dummy_conn = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
            if (c == NULL || cleanup == NULL || dummy_conn == NULL) {
                return NGX_ERROR;
            }

            cleanup->handler = &connection_cleanup;
            cleanup->data = c;

            c->log = cycle->log;
            c->main_cnf = halmcf;
            c->server = server;
            c->state = STATE_DISCONNECTED;
            c->cnx_idx = j;

            /* Various debug logging around timer management assume that the field
               'data' in ngx_event_t is a pointer to ngx_connection_t, therefore we
               have a dummy such structure around so that it does not crash etc. */
            dummy_conn->data = c;
            c->reconnect_event.log = c->log;
            c->reconnect_event.data = dummy_conn;
            c->reconnect_event.handler = reconnect_handler;

            c->pool = cycle->pool;
            c->ssl = &halmcf->ssl;

            lconnect(c);
        }
    }

    return NGX_OK;
}

// LDAP Authentication handler
ngx_int_t auth(ngx_http_request_t *r, void *conf)
{
    loc_conf_t *alcf = ngx_http_get_module_loc_conf(r, dav_next_auth_ldap_module);

    if (alcf->servers == NULL || alcf->servers->nelts == 0) {
        // no LDAP servers for the location
        ERROR(EMERG, r->connection->log, 0, "\"auth ldap\" requires one or more \"servers\" in the dav-next block");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (alcf->enabled == 0) {
        DEBUG0(r->connection->log, 0, "auth ldap bypassed");
        return NGX_DECLINED;
    }

    ctx_t *ctx = ngx_http_get_module_ctx(r, dav_next_auth_ldap_module);
    if (ctx == NULL) {
        ngx_int_t rc = ngx_http_auth_basic_user(r);
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        DEBUG1(r->connection->log, 0, "username is \"%V\"", &r->headers_in.user);
        if (r->headers_in.passwd.len == 0) {
            DEBUG0(r->connection->log, 0, "password is empty");
            return NGX_HTTP_FORBIDDEN;
        }

        ctx = ngx_pcalloc(r->pool, sizeof(ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->r = r;

        /* Initialize the groups array */
        ngx_array_init(&ctx->groups, r->pool, DEFAULT_GROUPS_COUNT, sizeof(ngx_str_t));

        /* Other fields have been initialized to zero/NULL */
        ngx_http_set_ctx(r, ctx, dav_next_auth_ldap_module);
    }

    return authenticate(r, ctx, alcf);
}

// iteratively handle all phases of the authentication process, might be called many times
ngx_int_t authenticate(ngx_http_request_t *r, ctx_t *ctx, loc_conf_t *conf)
{
    if (r->connection->write->timedout) {
        ERROR(ERR, r->connection->log, 0, "authentication timed out");
        r->connection->write->timedout = 0;
        if (ctx->c != NULL) {
            if (ctx->server && ctx->server->clean_on_timeout) {
                // authentication response timeouted → close and clean the corresponding LDAP connection
                DEBUG1(r->connection->log, 0, "close timeouted Cnx[%d]", ctx->c->cnx_idx);
                close_connection(ctx->c, 1);
                // clean the connection
                ctx->c->msgid = -1;
                ctx->c = NULL;
            } else {
                DEBUG1(r->connection->log, 0, "return old timedout Cnx[%d]", ctx->c->cnx_idx);
                return_connection(ctx->c);
            }
        }

        // remove ctx from waiting_requests queue if it was added
        if (ngx_queue_next(&ctx->queue)) {
            ngx_queue_remove(&ctx->queue);
        }

        return NGX_HTTP_UNAUTHORIZED; // HACK: https://github.com/Ericbla/nginx-auth-ldap/pull/3 (modified)
    }

    // If we are not starting up a request (ctx->phase != PHASE_START) and we actually already
    // sent a request (ctx->iteration > 0) and didn't receive a reply yet (!ctx->replied) we
    // ask to be called again at a later time when we hopefully have received a reply.
    //
    // It is quite possible that we reach this if while not having sent a request yet (ctx->iteration == 0) -
    // this happens when we are trying to get an LDAP connection but all of them are busy right now.
    if (ctx->iteration > 0 && !ctx->replied && ctx->phase != PHASE_START) {
        DEBUG0(r->connection->log, 0, "the LDAP operation did not finish yet");
        return NGX_AGAIN;
    }

    ngx_int_t rc;
    for (;;) {
        loop:
        DEBUG2(r->connection->log, 0, "authentication loop (phase=%d, iteration=%d)", ctx->phase, ctx->iteration);

        switch (ctx->phase) {
            case PHASE_START:
                ctx->server = ((server_t **) conf->servers->elts)[ctx->server_index];
                ctx->outcome = OUTCOME_UNCERTAIN;

                ngx_add_timer(r->connection->write, ctx->server->request_timeout);
                DEBUG1(r->connection->log, 0, "set request watchdog (timeout=%d)", ctx->server->request_timeout);

                // check cache if enabled
                ERROR_A(WARN, r->connection->log, 0, "cache.buckets = %p, conf->servers->nelts = %d", cache.buckets, conf->servers->nelts);
                if (cache.buckets != NULL) {
                    for (ngx_uint_t i = 0; i < conf->servers->nelts; i++) {
                        server_t *s = ((server_t **) conf->servers->elts)[i];
                        rc = check_cache(r, ctx, &cache, s);
                        ERROR_A(WARN, r->connection->log, 0, "using cached outcome %d from server %d ('%V')", rc, i, &s->alias);
                        DEBUG3(r->connection->log, 0, "using cached outcome %d from server %d ('%V')", rc, i, &s->alias);
                        if (rc == OUTCOME_DENY || rc == OUTCOME_ALLOW) {
                            ctx->outcome = (rc == OUTCOME_DENY ? OUTCOME_CACHED_DENY : OUTCOME_CACHED_ALLOW);
                            ctx->phase = PHASE_NEXT;
                            goto loop;
                        }
                    }
                }

                ctx->phase = PHASE_SEARCH_USER;
                ctx->iteration = 0;
                break;

            case PHASE_SEARCH_USER:
                // search the directory to retrieve full user DN
                rc = search_user(r, ctx);
                if (rc == NGX_AGAIN) {
                    // LDAP operation in progress, wait for the results
                    return NGX_AGAIN;
                }
                if (rc != NGX_OK) {
                    // search failed, try next server
                    ctx->phase = PHASE_NEXT;
                    break;
                }

                // user DN has been found, check user next
                ctx->phase = PHASE_CHECK_USER;
                break;

            case PHASE_CHECK_USER:
                DEBUG1(r->connection->log, 0, "user DN is \"%V\"", &ctx->user_dn);

                if (ctx->server->require_user != NULL) {
                    rc = check_user(r, ctx);
                    if (rc != NGX_OK) {
                        DEBUG0(r->connection->log, 0, "check_user NOK");
                        // user check failed, try next server
                        ctx->phase = PHASE_NEXT;
                        break;
                    }
                }

                if (ctx->server->groups_url.ludpp != NULL) {
                    DEBUG0(r->connection->log, 0, "moving to groups search");
                    ctx->phase = PHASE_SEARCH_GROUPS;
                    ctx->iteration = 0;
                    break;
                }

                // user not yet fully authenticated, check group next
                if ((ctx->outcome == OUTCOME_UNCERTAIN) && (ctx->server->require_group != NULL)) {
                    DEBUG0(r->connection->log, 0, "moving to groups check");
                    ctx->phase = PHASE_CHECK_GROUPS;
                    ctx->iteration = 0;
                    break;
                }

                // no groups to validate, try binding next
                ctx->phase = PHASE_CHECK_BIND;
                ctx->iteration = 0;
                break;

            case PHASE_SEARCH_GROUPS:
                // search the directory to retrieve groups DNs
                rc = search_groups(r, ctx);
                if (rc == NGX_AGAIN) {
                    // LDAP operation in progress, wait for the results
                    return NGX_AGAIN;
                }
                if (rc != NGX_OK) {
                    // search failed, try next server
                    ctx->phase = PHASE_NEXT;
                    break;
                }

                if ((ctx->outcome == OUTCOME_UNCERTAIN) && (ctx->server->require_group != NULL)) {
                    DEBUG0(r->connection->log, 0, "moving to groups check");
                    ctx->phase = PHASE_CHECK_GROUPS;
                    ctx->iteration = 0;
                    break;
                }

                // groups DNs has been found, check binding next
                ctx->phase = PHASE_CHECK_BIND;
                break;

            case PHASE_CHECK_GROUPS:
                DEBUG0(r->connection->log, 0, "checking groups");
                rc = check_groups(r, ctx);
                if (rc == NGX_AGAIN) {
                    // LDAP operation in progress, wait for the results
                    return NGX_AGAIN;
                }
                if (rc != NGX_OK) {
                    // group check failed, try next server
                    ctx->phase = PHASE_NEXT;
                    break;
                }

                // groups validated, try binding next
                ctx->phase = PHASE_CHECK_BIND;
                ctx->iteration = 0;
                break;

            case PHASE_CHECK_BIND:
                if (ctx->outcome == OUTCOME_UNCERTAIN) {
                    // If we're still uncertain when satisfy is 'any' and there
                    // is at least one require user/group rule, it means no
                    // rule has matched.
                    if ((ctx->server->satisfy_all == 0) && ((ctx->server->require_user != NULL) || (ctx->server->require_group != NULL))) {
                        DEBUG0(r->connection->log, 0, "no requirement satisfied");
                        ctx->outcome = OUTCOME_DENY;
                        ctx->phase = PHASE_NEXT;
                        // rc = NGX_DECLINED;
                        break;
                    } else {
                        // so far so good
                        ctx->outcome = OUTCOME_ALLOW;
                    }
                }

                // initiate bind using the found DN and request password
                rc = check_bind(r, ctx);
                if (rc == NGX_AGAIN) {
                    // LDAP operation in progress, wait for the result
                    return NGX_AGAIN;
                }

                // all steps done, finish the processing
                ctx->phase = PHASE_REBIND;
                ctx->iteration = 0;
                break;

            case PHASE_REBIND:
                // initiate bind using the Bind DN and associated password
                rc = recover_bind(r, ctx);
                if (rc == NGX_AGAIN) {
                    // LDAP operation in progress, wait for the result
                    return NGX_AGAIN;
                }
                if (rc != NGX_OK) {
                    // Re-Bind failed, but previous search and bind may have positive outcome
                    // So close the current LDAP connection (that will be restarted ofter reconnect_timeout)
                    // and continue with the next phase
                    if (ctx->c != NULL) {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "authenticate: Flushing [Cnx:%d] after re-bind failure", ctx->c->cnx_idx);
                        close_connection(ctx->c, 0);
                        ctx->c = NULL; // prevent the cnx to be returned in free list in PHASE_NEXT
                    }
                    ctx->phase = PHASE_NEXT;
                    break;
                }

                // all steps done, finish the processing
                ctx->phase = PHASE_NEXT;
                break;

            case PHASE_NEXT:
                if (r->connection->write->timer_set) {
                    ngx_del_timer(r->connection->write);
                }

                if (ctx->c != NULL) {
                    return_connection(ctx->c);
                }

                if (cache.buckets != NULL &&
                    (ctx->outcome == OUTCOME_DENY || ctx->outcome == OUTCOME_ALLOW)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "authenticate: Caching outcome %d", ctx->outcome);
                    update_cache(ctx, &cache, ctx->outcome);
                }

                if (ctx->outcome == OUTCOME_ALLOW || ctx->outcome == OUTCOME_CACHED_ALLOW) {
                    return NGX_OK;
                }

                ctx->server_index++;
                if (ctx->server_index >= conf->servers->nelts) {
                    return set_header_auth(r);
                }

                ctx->phase = PHASE_START;
                break;
        }
    }
}

ngx_int_t search_user(ngx_http_request_t *r, ctx_t *ctx)
{
    // on the first call, initiate the LDAP search operation
    if (ctx->iteration == 0) {
        if (!get_connection(ctx)) {
            return NGX_AGAIN;
        }

        LDAPURLDesc *ludpp = ctx->server->users_url.ludpp;
        u_char *filter = ngx_pcalloc(r->pool, (ludpp->lud_filter != NULL ? ngx_strlen(ludpp->lud_filter) : ngx_strlen("(objectClass=*)")) + ngx_strlen("(&(=))") + ctx->server->user_attribute.len + r->headers_in.user.len + 1);
        ngx_sprintf(filter, "(&%s(%V=%V))", ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)", &ctx->server->user_attribute, &r->headers_in.user);
        ERROR_A(INFO, ctx->c->log, 0, "Cnx[%d] searching (with filter \"%s\") …", ctx->c->cnx_idx, (const char *) filter);

        int rc = ldap_search_ext(ctx->c->ld, ludpp->lud_dn, ludpp->lud_scope, (const char *) filter, ludpp->lud_attrs, 0, NULL, NULL, NULL, 0, &ctx->c->msgid);
        if (rc != LDAP_SUCCESS) {
            ERROR_A(ERR, r->connection->log, 0, "ldap_search_ext() Cnx[%d] failed (%d, %s)", ctx->c->cnx_idx, rc, ldap_err2string(rc));
            return_connection(ctx->c);
            return NGX_ERROR;
        }

        DEBUG2(r->connection->log, 0, "ldap_search_ext() Cnx[%d] -> msgid=%d", ctx->c->cnx_idx, ctx->c->msgid);
        ctx->c->state = STATE_SEARCHING;
        ctx->iteration++;
        return NGX_AGAIN;
    }

    // on the second call, handle the search results
    if (ctx->error_code != LDAP_SUCCESS) {
        ERROR_A(ERR, r->connection->log, 0, "ldap_search_ext() Cnx[%d] request failed (%d: %s)", ctx->c->cnx_idx, ctx->error_code, ldap_err2string(ctx->error_code));
        return NGX_ERROR;
    }

    if (ctx->dn.data == NULL) {
        ERROR_A(ERR, r->connection->log, 0, "Cnx[%d] Could not find user DN", ctx->c->cnx_idx);
        return NGX_ERROR;
    } else {
        ERROR_A(INFO, ctx->c->log, 0, "Cnx[%d] Found dn: \"%V\")", ctx->c->cnx_idx, &ctx->dn);
        ctx->user_dn.len = ngx_strlen(ctx->dn.data);
        ctx->user_dn.data = (u_char *) ngx_palloc(ctx->r->pool, ctx->user_dn.len + 1);
        ngx_memcpy(ctx->user_dn.data, ctx->dn.data, ctx->user_dn.len + 1);
        ctx->dn.data = NULL;
        ctx->dn.len = 0;
    }

    return NGX_OK;
}

ngx_int_t check_user(ngx_http_request_t *r, ctx_t *ctx)
{
    ngx_http_complex_value_t *values = ctx->server->require_user->elts;

    for (ngx_uint_t i = 0; i < ctx->server->require_user->nelts; i++) {
        ngx_str_t val;
        if (ngx_http_complex_value(r, &values[i], &val) != NGX_OK) {
            ctx->outcome = OUTCOME_ERROR;
            return NGX_ERROR;
        }

        DEBUG1(r->connection->log, 0, "comparing HTTP user with \"%V\"", &val);
        if (NGX_STR_EQ(&val, &r->headers_in.user)) {
            if (ctx->server->satisfy_all == 0) {
                ctx->outcome = OUTCOME_ALLOW;

                return NGX_OK;
            }
        } else {
            if (ctx->server->satisfy_all == 1) {
                ctx->outcome = OUTCOME_DENY;

                return NGX_DECLINED;
            }
        }
    }

    return NGX_OK;
}

ngx_int_t search_groups(ngx_http_request_t *r, ctx_t *ctx)
{
    // on the first call, initiate the LDAP search operation
    if (ctx->iteration == 0) {
        if (!get_connection(ctx)) {
            return NGX_AGAIN;
        }

        int rc;
        if (ctx->server->member_attribute.data == NULL) {
            ERROR(CRIT, r->connection->log, 0, "member_attribute.data is NULL, should not happen!");
            rc = !LDAP_SUCCESS;
        } else {
            LDAPURLDesc *ludpp = ctx->server->groups_url.ludpp;
            size_t for_filter = (ludpp->lud_filter != NULL ? ngx_strlen(ludpp->lud_filter) : ngx_strlen("(objectClass=*)")) + ngx_strlen("(&(=))") + ctx->server->member_attribute.len + 1;
            ngx_str_t *value;

            if (ctx->server->member_attribute_dn) {
                for_filter += ctx->user_dn.len;
                value = &ctx->user_dn;
            } else {
                for_filter += r->headers_in.user.len;
                value = &r->headers_in.user;
            }

            u_char *filter = ngx_palloc(r->pool, for_filter);
            ngx_sprintf(filter, "(&%s(%V=%V))", ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)", &ctx->server->member_attribute, value);

            ERROR_A(INFO, ctx->c->log, 0, "Cnx[%d] searching (with filter \"%s\") …", ctx->c->cnx_idx, (const char *) filter);

            rc = ldap_search_ext(ctx->c->ld, ludpp->lud_dn, ludpp->lud_scope, (const char *) filter, ctx->server->groups_url.ludpp->lud_attrs, 0, NULL, NULL, NULL, 0, &ctx->c->msgid);
        }

        if (rc != LDAP_SUCCESS) {
            ERROR_A(ERR, r->connection->log, 0, "ldap_search_ext() Cnx[%d] failed (%d, %s)", ctx->c->cnx_idx, rc, ldap_err2string(rc));
            return_connection(ctx->c);
            return NGX_ERROR;
        }

        DEBUG2(r->connection->log, 0, "ldap_search_ext() Cnx[%d] -> msgid=%d", ctx->c->cnx_idx, ctx->c->msgid);

        ctx->c->state = STATE_SEARCHING;
        ctx->iteration++;

        return NGX_AGAIN;
    }

    // on the other calls, handle the search results

    if (ctx->error_code != LDAP_SUCCESS) {
        ERROR_A(ERR, r->connection->log, 0, "ldap_search_ext() Cnx[%d] request failed (%d: %s)", ctx->c->cnx_idx, ctx->error_code, ldap_err2string(ctx->error_code));
        return NGX_ERROR;
    }

    if (ctx->dn.data == NULL) {
        ERROR_A(CRIT, r->connection->log, 0, "Cnx[%d] Could not find group DN (should not happen!)", ctx->c->cnx_idx);
        return NGX_ERROR;
    } else {
        ERROR_A(INFO, ctx->c->log, 0, "Cnx[%d] Found group DN: \"%V\")", ctx->c->cnx_idx, &ctx->dn);

        ctx->dn.data = NULL;
        ctx->dn.len = 0;
    }

    return NGX_OK;
}

ngx_int_t check_groups(ngx_http_request_t *r, ctx_t *ctx)
{
    ngx_http_complex_value_t *values = ctx->server->require_group->elts;

    for (ngx_uint_t i = 0; i < ctx->server->require_group->nelts; i++) {
        ngx_str_t val;
        if (ngx_http_complex_value(r, &values[i], &val) != NGX_OK) {
            ctx->outcome = OUTCOME_ERROR;
            return NGX_ERROR;
        }

        for (ngx_uint_t j = 0; j < ctx->groups.nelts; j++) {
            ngx_str_t *group = ((ngx_str_t *) ctx->groups.elts) + j;
            DEBUG2(r->connection->log, 0, "comparing group \"%V\" with required \"%V\"", group, &val);
            if (NGX_STR_EQ(&val, group)) {
                if (ctx->server->satisfy_all == 0) {
                    ctx->outcome = OUTCOME_ALLOW;

                    return NGX_OK;
                }
            } else {
                if (ctx->server->satisfy_all == 1) {
                    ctx->outcome = OUTCOME_DENY;

                    return NGX_DECLINED;
                }
            }
        }
    }

    return NGX_OK;
}

// initiate and handle a bind operation using the authentication parameters
ngx_int_t check_bind(ngx_http_request_t *r, ctx_t *ctx)
{
    // on the first call, initiate the bind LDAP operation
    if (ctx->iteration == 0) {
        if (!get_connection(ctx)) {
            return NGX_AGAIN;
        }

        struct berval cred;
        cred.bv_val = (char *) r->headers_in.passwd.data;
        cred.bv_len = r->headers_in.passwd.len;

        ERROR_A(INFO, r->connection->log, 0, "Cnx[%d] binding (user dn: %s) …", ctx->c->cnx_idx, ctx->user_dn.data);
        ngx_int_t rc = ldap_sasl_bind(ctx->c->ld, (const char *) ctx->user_dn.data, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &ctx->c->msgid);
        if (rc != LDAP_SUCCESS) {
            ERROR_A(ERR, r->connection->log, 0, "Cnx[%d] ldap_sasl_bind() failed (%d: %s)", ctx->c->cnx_idx, rc, ldap_err2string(rc));
            ctx->outcome = OUTCOME_ERROR;
            return_connection(ctx->c);

            return NGX_ERROR;
        }

        DEBUG2(r->connection->log, 0, "Cnx[%d] ldap_sasl_bind() -> msgid=%d", ctx->c->cnx_idx, ctx->c->msgid);
        ctx->c->state = STATE_BINDING;
        ctx->iteration++;

        return NGX_AGAIN;
    }

    // on the second call, process the operation result
    if (ctx->error_code != LDAP_SUCCESS) {
        ERROR_A(ERR, r->connection->log, 0, "Cnx[%d] user (dn: %s) bind failed (%d: %s)", ctx->c->cnx_idx, ctx->user_dn.data, ctx->error_code, ldap_err2string(ctx->error_code));
        ctx->outcome = OUTCOME_DENY;
    } else {
        ERROR_A(INFO, r->connection->log, 0, "Cnx[%d] user (dn: %s) bind successfull", ctx->c->cnx_idx, ctx->user_dn.data);
        ctx->outcome = OUTCOME_ALLOW;
    }

    return NGX_OK;
}

ngx_int_t recover_bind(ngx_http_request_t *r, ctx_t *ctx)
{
    // on the first call, initiate the bind LDAP operation
    if (ctx->iteration == 0) {
        if (!get_connection(ctx)) {
            return NGX_AGAIN;
        }

        struct berval cred;
        cred.bv_val = (char *) ctx->server->bind_dn_passwd.data;
        cred.bv_len = ctx->server->bind_dn_passwd.len;

        ERROR_A(INFO, r->connection->log, 0, "cnx[%d] rebinding to binddn …", ctx->c->cnx_idx);
        ngx_int_t rc = ldap_sasl_bind(ctx->c->ld, (const char *) ctx->server->bind_dn.data, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &ctx->c->msgid);
        if (rc != LDAP_SUCCESS) {
            ERROR_A(ERR, r->connection->log, 0, "cnx[%d] ldap_sasl_bind() failed (%d: %s)", ctx->c->cnx_idx, rc, ldap_err2string(rc));
            ctx->outcome = OUTCOME_ERROR;
            return_connection(ctx->c);

            return NGX_ERROR;
        }

        DEBUG2(r->connection->log, 0, "cnx[%d] ldap_sasl_bind() → msgid=%d", ctx->c->cnx_idx, ctx->c->msgid);
        ctx->c->state = STATE_BINDING;
        ctx->iteration++;

        return NGX_AGAIN;
    }

    // on the second call, process the operation result
    if (ctx->error_code != LDAP_SUCCESS) {
        ERROR_A(ERR, r->connection->log, 0, "cnx[%d] rebinding to binddn failed (%d: %s)", ctx->c->cnx_idx, ctx->error_code, ldap_err2string(ctx->error_code));

        return NGX_ERROR;
    }

    ERROR_A(INFO, r->connection->log, 0, "cnx[%d] rebinding to binddn successful", ctx->c->cnx_idx);

    return NGX_OK;
}
