/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-auth-ldap.h
 * LDAP authentication provider types for dav-next
 * © Alexandre Jousset
 */

#ifndef DAV_NEXT_AUTH_LDAP_H
#define DAV_NEXT_AUTH_LDAP_H

#include "dav-next.h"
#include <openldap.h>
#include <openssl/opensslv.h>

typedef enum {
    OUTCOME_ERROR = -1,
    OUTCOME_DENY,
    OUTCOME_ALLOW,
    OUTCOME_CACHED_DENY,
    OUTCOME_CACHED_ALLOW,
    OUTCOME_UNCERTAIN
} outcome_t;

#define MAX_SERVERS_SIZE 7

#define SSL_CERT_VERIFY_OFF   0
#define SSL_CERT_VERIFY_FULL  1
#define SSL_CERT_VERIFY_CHAIN 2

#define DEFAULT_GROUPS_COUNT 5 // the default number of groups

#define RECONNECT_ASAP_MS 1000 // delay (in ms) for LDAP reconnection (when we want ASAP reconnect)

typedef struct {
    LDAPURLDesc *ludpp;
    ngx_str_t url;
    ngx_url_t parsed_url;
} server_url_t;

typedef struct {
    ngx_str_t alias;

    ngx_str_t bind_dn;
    ngx_str_t bind_dn_passwd;

    server_url_t users_url;
    ngx_str_t user_attribute;

    server_url_t groups_url;
    ngx_str_t group_attribute;

    ngx_str_t member_attribute;
    ngx_flag_t member_attribute_dn;

    ngx_flag_t ssl_check_cert;
    ngx_str_t ssl_ca_dir;
    ngx_str_t ssl_ca_file;

    ngx_array_t *require_group;        // array of ngx_http_complex_value_t
    ngx_array_t *require_user;         // array of ngx_http_complex_value_t
    ngx_flag_t require_valid_user;
    // ngx_http_complex_value_t require_valid_user_dn;
    ngx_flag_t satisfy_all;
    ngx_flag_t referral;
    ngx_flag_t clean_on_timeout;

    ngx_uint_t connections;
    ngx_uint_t max_down_retries;
    ngx_uint_t max_down_retries_count;
    ngx_msec_t connect_timeout;
    ngx_msec_t reconnect_timeout;
    ngx_msec_t bind_timeout;
    ngx_msec_t request_timeout;
    ngx_queue_t free_connections;      // queue of free (ready) connections
    ngx_queue_t waiting_requests;      // queue of ctx with not finished requests

    ngx_queue_t pending_reconnections; // queue of pending connections (waiting re-connect)
} server_t;

typedef struct {
    ngx_array_t *servers;        // array of server_t
    ngx_flag_t cache_enabled;
    ngx_msec_t cache_expiration_time;
    size_t cache_size;
    ngx_ssl_t ssl;
    ngx_msec_t resolver_timeout; // resolver_timeout
    ngx_resolver_t *resolver;    // resolver
    ngx_pool_t *cnf_pool;
} main_conf_t;

typedef struct {
    ngx_array_t *servers; // array of server_t*
    ngx_uint_t enabled;
} loc_conf_t;

typedef struct {
    uint32_t small_hash;    // murmur2 hash of username ^ &server
    outcome_t outcome;      // OUTCOME_DENY or OUTCOME_ALLOW
    ngx_msec_t time;        // ngx_current_msec when created
    u_char big_hash[16];    // md5 hash of (username, server, password)
    ngx_array_t groups;     // groups (ngx_str_t *) retrieved during the search
} cache_elt_t;

typedef struct {
    cache_elt_t *buckets;
    ngx_uint_t num_buckets;
    ngx_uint_t elts_per_bucket;
    ngx_msec_t expiration_time;
    ngx_pool_t *pool;
} cache_t;

typedef enum {
    PHASE_START,
    PHASE_SEARCH_USER,
    PHASE_CHECK_USER,
    PHASE_SEARCH_GROUPS,
    PHASE_CHECK_GROUPS,
    PHASE_CHECK_BIND,
    PHASE_REBIND,
    PHASE_NEXT
} request_phase_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_uint_t server_index;
    server_t *server;
    request_phase_t phase;
    unsigned int iteration;
    outcome_t outcome;

    struct connection *c;
    ngx_queue_t queue;      // queue element to be chained in server->waiting_requests queue
    int replied;
    int error_code;
    ngx_str_t error_msg;
    ngx_str_t dn;
    ngx_str_t user_dn;
    ngx_array_t groups;     // groups (ngx_str_t *) retrieved during the search

    cache_elt_t *cache_bucket;
    u_char cache_big_hash[16];
    uint32_t cache_small_hash;
} ctx_t;

typedef enum {
    STATE_DISCONNECTED,
    STATE_INITIAL_BINDING,
    STATE_CONNECTING,
    STATE_READY,
    STATE_BINDING,
    STATE_SEARCHING,
    STATE_COMPARING,
    STATE_DISCONNECTING
} connection_state_t;

typedef struct connection {
    ngx_log_t *log;
    main_conf_t *main_cnf;
    server_t *server;
    ngx_peer_connection_t conn;
    ngx_event_t reconnect_event;

    ngx_pool_t *pool;
    ngx_ssl_t *ssl;

    ngx_queue_t queue;         // queue element to be chained in server->free_connections queue
    ngx_queue_t queue_pending; // queue element to be chained in server->pending_reconnections queue
    ctx_t *rctx;

    LDAP* ld;
    connection_state_t state;
    int msgid;
    ngx_resolver_ctx_t *resolver_ctx;
    ngx_uint_t cnx_idx;        // index of the connection from 0 to server->connections -1
} connection_t;

ngx_int_t auth(ngx_http_request_t *r, void *conf);
ngx_int_t init_cache(ngx_cycle_t *cycle);
ngx_int_t init_connections(ngx_cycle_t *cycle);

#endif // DAV_NEXT_AUTH_LDAP_H
