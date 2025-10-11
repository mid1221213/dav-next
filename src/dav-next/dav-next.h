/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next.h
 * Type definitions and macros for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#ifndef DAV_NEXT_H
#define DAV_NEXT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/statvfs.h>
#include <libxml/parser.h>

// HACK: pointer to function inserted in auth_ldap to fetch result attributes
extern ngx_array_t *auth_ldap_get_attributes(ngx_http_request_t *r) __attribute__((weak));

// HACK: dav_next_module is extern except for dav-next-module.c
#ifndef DAV_NEXT_MODULE_C
extern ngx_module_t  dav_next_module;
#endif



#define  DEBUG0(log, err, str)                          ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, err, "%s:%d: " str, __FUNCTION__, __LINE__)
#define  DEBUG1(log, err, str, arg1)                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, err, "%s:%d: " str, __FUNCTION__, __LINE__, arg1)
#define  DEBUG2(log, err, str, arg1, arg2)              ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, err, "%s:%d: " str, __FUNCTION__, __LINE__, arg1, arg2)
#define  DEBUG3(log, err, str, arg1, arg2, arg3)        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, err, "%s:%d: " str, __FUNCTION__, __LINE__, arg1, arg2, arg3)
#define  DEBUG4(log, err, str, arg1, arg2, arg3, arg4)  ngx_log_debug6(NGX_LOG_DEBUG_HTTP, log, err, "%s:%d: " str, __FUNCTION__, __LINE__, arg1, arg2, arg3, arg4)
#define ERROR_A(lvl, log, err, str, args...)            ngx_log_error(NGX_LOG_##lvl,       log, err, "%s:%d: " str, __FUNCTION__, __LINE__, args)
#define   ERROR(lvl, log, err, str)                     ngx_log_error(NGX_LOG_##lvl,       log, err, "%s:%d: " str, __FUNCTION__, __LINE__)

#define QQ2(val) # val
#define QQ(val) QQ2(val)

// number of ns in 1s
#define _1G 1000000000

#define DAV_NEXT_HEX_ID_LEN                     16 /* = 64 / 8 * 2 */

#define DAV_NEXT_STR_LEN(type, str)             (sizeof(DAV_NEXT_##type##_##str##_STR) - 1)
#define DAV_NEXT_URI_LEN(str)                   DAV_NEXT_STR_LEN(URI, str)
#define DAV_NEXT_CONTENT_LEN(str)               DAV_NEXT_STR_LEN(CONTENT, str)

#define DAV_NEXT_URI_NONE                       0

#define DAV_NEXT_URI_CLOUD_USER                 1
#define DAV_NEXT_URI_CLOUD_USER_STR             "/ocs/v1.php/cloud/user"
#define DAV_NEXT_URI_CLOUD_USER_STR_2           "/ocs/v2.php/cloud/user"
#define DAV_NEXT_URI_CLOUD_USER_LEN             DAV_NEXT_URI_LEN(CLOUD_USER)
// TODO: replace DAV-Next below with setting
#define DAV_NEXT_CONTENT_CLOUD_USER_STR                                        \
    "{\n"                                                                      \
    "  \"ocs\": {\n"                                                           \
    "    \"meta\": {\n"                                                        \
    "      \"status\": \"ok\",\n"                                              \
    "      \"statuscode\": 100,\n"                                             \
    "      \"message\": \"OK\"\n"                                              \
    "    },\n"                                                                 \
    "    \"data\": {\n"                                                        \
    "      \"id\": \"%V\",\n"                                                  \
    "      \"display-name\": \"%V@DAV-Next\"\n"                                \
    "    }\n"                                                                  \
    "  }\n"                                                                    \
    "}\n"
#define DAV_NEXT_CONTENT_CLOUD_USER_LEN                                        \
    (DAV_NEXT_CONTENT_LEN(CLOUD_USER) - 2 * 2)

#define DAV_NEXT_URI_CLOUD_CAPABILITIES         2
#define DAV_NEXT_URI_CLOUD_CAPABILITIES_STR     "/ocs/v1.php/cloud/capabilities"
#define DAV_NEXT_URI_CLOUD_CAPABILITIES_STR_2   "/ocs/v2.php/cloud/capabilities"
#define DAV_NEXT_URI_CLOUD_CAPABILITIES_LEN     DAV_NEXT_URI_LEN(CLOUD_CAPABILITIES)
#define DAV_NEXT_CONTENT_CLOUD_CAPABILITIES_STR                                \
    "{\n"                                                                      \
    "  \"ocs\": {\n"                                                           \
    "    \"meta\": {\n"                                                        \
    "      \"status\": \"ok\",\n"                                              \
    "      \"statuscode\": 100,\n"                                             \
    "      \"message\": \"OK\"\n"                                              \
    "    },\n"                                                                 \
    "    \"data\": {\n"                                                        \
    "      \"version\": {\n"                                                   \
    "        \"major\": 28,\n"                                                 \
    "        \"minor\": 0,\n"                                                  \
    "        \"micro\": 5,\n"                                                  \
    "        \"string\": \"28.0.5\",\n"                                        \
    "        \"edition\": \"dav-next\"\n"                                      \
    "      },\n"                                                               \
    "      \"capabilities\": {\n"                                              \
    "        \"core\": {\n"                                                    \
    "          \"pollinterval\": 60,\n"                                        \
    "          \"webdav-root\": \"remote.php/webdav\"\n"                       \
    "        },\n"                                                             \
    "        \"dav\": {\n"                                                     \
    "          \"chunking\": \"1.0\"\n"                                        \
    "        },\n"                                                             \
    "        \"files\": {\n"                                                   \
    "          \"bigfilechunking\": true,\n"                                   \
    "          \"comments\": false,\n"                                         \
    "          \"undelete\": false,\n"                                         \
    "          \"versioning\": false\n"                                        \
    "        }\n"                                                              \
    "      }\n"                                                                \
    "    }\n"                                                                  \
    "  }\n"                                                                    \
    "}\n"
#define DAV_NEXT_CONTENT_CLOUD_CAPABILITIES_LEN DAV_NEXT_CONTENT_LEN(CLOUD_CAPABILITIES)

#define DAV_NEXT_URI_DELETE_APPPASSWORD         3
#define DAV_NEXT_URI_DELETE_APPPASSWORD_STR_1   "/remote.php/dav/files/"
#define DAV_NEXT_URI_DELETE_APPPASSWORD_LEN_1   (sizeof(DAV_NEXT_URI_DELETE_APPPASSWORD_STR_1) - 1)
#define DAV_NEXT_URI_DELETE_APPPASSWORD_STR_2   "/ocs/v2.php/core/apppassword"
#define DAV_NEXT_URI_DELETE_APPPASSWORD_LEN_2   (sizeof(DAV_NEXT_URI_DELETE_APPPASSWORD_STR_2) - 1)

#define DAV_NEXT_URI_STATUS                     4
#define DAV_NEXT_URI_STATUS_STR                 "/status.php"
#define DAV_NEXT_URI_STATUS_LEN                 DAV_NEXT_URI_LEN(STATUS)
#define DAV_NEXT_CONTENT_STATUS_STR                                            \
    "{\n"                                                                      \
    "  \"edition\": \"\",\n"                                                   \
    "  \"extendedSupport\": false,\n"                                          \
    "  \"installed\": true,\n"                                                 \
    "  \"maintenance\": false,\n"                                              \
    "  \"needsDbUpgrade\": false,\n"                                           \
    "  \"productname\": \"dav-next\",\n"                                       \
    "  \"version\": \"28.0.5.1\",\n"                                           \
    "  \"versionstring\": \"28.0.5\"\n"                                        \
    "}\n"
#define DAV_NEXT_CONTENT_STATUS_LEN             DAV_NEXT_CONTENT_LEN(STATUS)

#define DAV_NEXT_URI_SLASH                      5
#define DAV_NEXT_URI_SLASH_STR                  "/"
#define DAV_NEXT_URI_SLASH_LEN                  DAV_NEXT_URI_LEN(SLASH)

#define DAV_NEXT_URI_DAV_FILES                  6
#define DAV_NEXT_URI_DAV_FILES_STR              "/remote.php/dav/files/"
#define DAV_NEXT_URI_DAV_FILES_LEN              DAV_NEXT_URI_LEN(DAV_FILES)

#define DAV_NEXT_CONTENT_INDEX_STR                                             \
    "This is the WebDAV interface. It can only be "                            \
    "accessed by WebDAV clients such as the Nextcloud "                        \
    "desktop sync client."
#define DAV_NEXT_CONTENT_INDEX_LEN              DAV_NEXT_CONTENT_LEN(INDEX)

#define DAV_NEXT_URI_DAV_UPLOADS                7
#define DAV_NEXT_URI_DAV_UPLOADS_STR            "/remote.php/dav/uploads/"
#define DAV_NEXT_URI_DAV_UPLOADS_LEN            DAV_NEXT_URI_LEN(DAV_UPLOADS)

#define DAV_NEXT_URI_DAV                        8
#define DAV_NEXT_URI_DAV_STR                    "/remote.php/dav/"
#define DAV_NEXT_URI_DAV_LEN                    DAV_NEXT_URI_LEN(DAV)

#define DAV_NEXT_URI_WEBDAV                     9
#define DAV_NEXT_URI_WEBDAV_STR                 "/remote.php/webdav/"
#define DAV_NEXT_URI_WEBDAV_LEN                 DAV_NEXT_URI_LEN(WEBDAV)

#define DAV_NEXT_URI_LOGIN_FLOW                 10
#define DAV_NEXT_URI_LOGIN_FLOW_STR             "/index.php/login/flow"
#define DAV_NEXT_URI_LOGIN_FLOW_LEN             DAV_NEXT_URI_LEN(LOGIN_FLOW)

#define DAV_NEXT_CONTENT_LOGIN_FLOW_STR                                              \
    "<!DOCTYPE html>\n"                                                              \
    "<html lang=\"en\">\n"                                                           \
    "  <head>\n"                                                                     \
    "    <title>Welcome to Luna[e]</title>\n"                                        \
    "    <meta charset=\"utf-8\">\n"                                                 \
    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" \
    "    <style>\n"                                                                  \
    "      input[type='password'],input[type='text'] {\n"                            \
    "        width: 100%;\n"                                                         \
    "        padding: 10px;\n"                                                       \
    "        border-radius: 3px;\n"                                                  \
    "        border: 1px solid #ccc;\n"                                              \
    "        margin-top: 10px;\n"                                                    \
    "        margin-bottom: 20px;\n"                                                 \
    "      }\n"                                                                      \
    "      input[type='password']:focus,input[type='user']:focus {\n"                \
    "        border: 1px solid #5db6db;\n"                                           \
    "        box-shadow: 0 0 10px #b9eaff;\n"                                        \
    "        outline: none !important;\n"                                            \
    "      }\n"                                                                      \
    "      input[type='submit']{\n"                                                  \
    "        background: rgb(39,160,210);\n"                                         \
    "        color: #fff;\n"                                                         \
    "        border: none;\n"                                                        \
    "        padding: 10px 20px;\n"                                                  \
    "        cursor: pointer;\n"                                                     \
    "      }\n"                                                                      \
    "      .main-login-form{\n"                                                      \
    "        max-width: 400px;\n"                                                    \
    "        margin: 0 auto;\n"                                                      \
    "        background: #f5f5f5c7;\n"                                               \
    "        padding: 20px 45px 20px 25px;\n"                                        \
    "        border-radius: 5px;\n"                                                  \
    "        border: 1px solid #ccc;\n"                                              \
    "      }\n"                                                                      \
    "    </style>\n"                                                                 \
    "  </head>\n"                                                                    \
    "  <body>\n"                                                                     \
    "    <div class=\"main-login-form\">\n"                                          \
    "      <form action=\"/index.php/login/flow\" method=\"POST\">\n"                \
    "        <label for=\"username\">Username</label>\n"                             \
    "        <input type=\"text\" name=\"username\" class=\"user\"\n"                \
    "          placeholder=\"Enter your username\" required>\n"                      \
    "        <label for=\"password\">Password</label>\n"                             \
    "        <input type=\"password\" name=\"password\" class=\"password\"\n"        \
    "          placeholder=\"Enter your password\" required>\n"                      \
    "        <input name=\"submit\" type=\"submit\" value=\"Submit\">\n"             \
    "      </form>\n"                                                                \
    "    </div>\n"                                                                   \
    "  </body>\n"                                                                    \
    "</html>\n"
#define DAV_NEXT_CONTENT_LOGIN_FLOW_LEN         DAV_NEXT_CONTENT_LEN(LOGIN_FLOW)

#define DAV_NEXT_URI_CONNECTIVITY_CHECK         11
#define DAV_NEXT_URI_CONNECTIVITY_CHECK_STR     "/index.php/204"
#define DAV_NEXT_URI_CONNECTIVITY_CHECK_LEN     DAV_NEXT_URI_LEN(CONNECTIVITY_CHECK)

#define DAV_NEXT_URI_OTHER                      12
#define DAV_NEXT_URI_OTHER_STR                  "/"
#define DAV_NEXT_URI_OTHER_LEN                  DAV_NEXT_URI_LEN(SLASH)

#define DAV_NEXT_URI_DAV_ALIAS_LEN              (sizeof("/remote.php/dav") - 1)
#define DAV_NEXT_URI_WEBDAV_ALIAS_LEN           (DAV_NEXT_URI_WEBDAV_LEN - 1)

#define DAV_NEXT_INFINITY_DEPTH                 NGX_MAX_INT_T_VALUE

#define DAV_NEXT_PREALLOCATE                    50

#define DAV_NEXT_NODE_PROPFIND                  0x01
#define DAV_NEXT_NODE_PROP                      0x02
#define DAV_NEXT_NODE_PROPNAME                  0x04
#define DAV_NEXT_NODE_ALLPROP                   0x08

#define DAV_NEXT_PROP_DISPLAYNAME               0x0001
#define DAV_NEXT_PROP_GETCONTENTLENGTH          0x0002
#define DAV_NEXT_PROP_GETLASTMODIFIED           0x0004
#define DAV_NEXT_PROP_GETETAG                   0x0008
#define DAV_NEXT_PROP_RESOURCETYPE              0x0010
#define DAV_NEXT_PROP_LOCKDISCOVERY             0x0020
#define DAV_NEXT_PROP_SUPPORTEDLOCK             0x0040
#define DAV_NEXT_PROP_PERMISSIONS               0x0080
#define DAV_NEXT_PROP_FILEID                    0x0100
#define DAV_NEXT_PROP_QUOTA_AVAIL               0x0200
#define DAV_NEXT_PROP_QUOTA_USED                0x0400

#define DAV_NEXT_PROP_ALL                       0x07ff
#define DAV_NEXT_PROP_NAMES                     0x0800

#define LAST_CHAR_OF(str) ((str).data[(str).len - 1])

#define RETURN_RC_IF_NOK(expr)                                          \
    {                                                                   \
        ngx_int_t rc;                                                   \
        if ((rc = (expr)) != NGX_OK) {                                  \
            DEBUG1(r->connection->log, ngx_errno, # expr " != NGX_OK: %d", rc); \
            return rc;                                                  \
        }                                                               \
    }

#define RETURN_500_IF(expr)                                             \
    {                                                                   \
        if ((expr)) {                                                   \
            ERROR(CRIT, r->connection->log, ngx_errno,  # expr " → NGX_HTTP_INTERNAL_SERVER_ERROR"); \
            return NGX_HTTP_INTERNAL_SERVER_ERROR;                      \
        }                                                               \
    }

#define FINALIZE_500_IF(expr)                                           \
    {                                                                   \
        if ((expr)) {                                                   \
            ERROR(CRIT, r->connection->log, ngx_errno,  # expr " → NGX_HTTP_INTERNAL_SERVER_ERROR"); \
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR); \
            return;                                                     \
        }                                                               \
    }

#define ngx_dav_next_file_mtime(sb)                                     \
    ((uint64_t) (((sb)->st_mtim.tv_sec * _1G) + (sb)->st_mtim.tv_nsec))
#define ngx_dav_next_de_mtime(sb)  (ngx_dav_next_file_mtime(sb.info))


// node entry struct
typedef struct {
    ngx_str_t                            uri;
    ngx_str_t                            name;
    time_t                               mtime;
    off_t                                size;
    ngx_file_uniq_t                      id;

    off_t                                fs_used;
    off_t                                fs_avail;

    time_t                               lock_expire;
    ngx_str_t                            lock_root;
    uint32_t                             lock_token;

    unsigned                             read_only:1;
    unsigned                             dir:1;
    unsigned                             is_group:1;
    unsigned                             lock_supported:1;
    unsigned                             lock_infinite:1;
} dav_next_entry_t;

// XML parser context
typedef struct {
    ngx_uint_t                           nodes;
    ngx_uint_t                           props;
} dav_next_xml_ctx_t;

// dav-next context struct
typedef struct {
    ngx_uint_t                           alias;
    ngx_uint_t                           access_needed:1;
    ngx_uint_t                           access_checked:1;
    ngx_int_t                            access_checked_ret;
    ngx_uint_t                           uri_type;
    ngx_uint_t                           orig_uri_type;
    ngx_uint_t                           is_dav_root:1;
    ngx_str_t                           *webdav_rewritten;
    ngx_str_t                           *rewritten;
    ngx_str_t                            in_user;
    ngx_uint_t                           in_user_in_user:1;
    ngx_uint_t                           in_group:1;
    ngx_uint_t                           is_virtual_root:1;
    ngx_array_t                          virtual_dir;
} dav_next_ctx_t;

// location configuration struct
typedef struct {
    ngx_shm_zone_t                      *shm_zone;
    ngx_uint_t                           satisfy;
} dav_next_loc_conf_t;

// lock node struct
typedef struct {
    ngx_queue_t                          queue;
    uint32_t                             token;
    time_t                               expire;
    ngx_uint_t                           infinite; // unsigned  infinite:1;
    size_t                               len;
    u_char                               data[1];
} dav_next_node_t;

// lock shared memory pool struct
typedef struct {
    ngx_queue_t                          queue;
} dav_next_lock_sh_t;

// lock struct
typedef struct {
    time_t                               timeout;
    ngx_slab_pool_t                     *shpool;
    dav_next_lock_sh_t                  *sh;
} dav_next_lock_t;

// LDAP search result attributes
typedef struct {
    ngx_str_t attr_name;
    ngx_str_t attr_value;
} ldap_search_attribute_t;

// chunk entries
typedef ngx_str_t dav_next_chunk_entry_t;

#endif // DAV_NEXT_H
