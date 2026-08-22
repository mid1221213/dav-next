# Configuration directives

The detailed available directives are:

## `dav_next` block

- *Syntax:*  `dav_next <name> { … }`
- *Context:* `server`, `http`
- *Description:* Declare a `dav-next` instance. The `<name>` is a name you
  choose to reference this instance elsewhere. It is also the realm shown during
  the auth. It is a block that itself contains other directives

## `auth`

- *Syntax:*  `auth <type>`
- *Context:* `dav_next`
- *Description:* Declare the authentication method of this `dav-next`
  instance. The `<type>` is one of `basic` or `ldap`

## `root_is_writable`

- *Syntax:* `root_is_writable [on|off]`
- *Context:* `dav_next`
- *Default:* `on`
- *Description:* Return "write allowed" permissions for the virtual root (the
  root path containing the user and group folders). This is a workaround for [a
  bug in NextCloud](https://github.com/nextcloud/desktop/pull/10226). See
  [important note](WARNING.md).

## `lock_mem`

- *Syntax:* `lock_mem <size>`
- *Context:* `dav_next`
- *Default:* `32K` (Linux x86_64)
- *Description:* Define the `<size>` of the shared memory zone for this instance

## `lock_timeout`

- *Syntax:* `lock_timeout <time>`
- *Context:* `dav_next`
- *Default:* `60` (seconds)
- *Description:* Define the duration of the timeout of (WebDAV) locks for this
  instance

## `realm`

- *Syntax:* `realm <realm>`
- *Context:* `dav_next` (when using `auth basic`)
- *Default:* `<name>` in `dav_next <name>`
- *Description:* Define the `<realm>` for this instance Basic auth

## `users_file`

- *Syntax:* `users_file <file>`
- *Context:* `dav_next` (when using `auth basic`)
- *Default:* `htpasswd`
- *Description:* Define the `<file>` of the users / groups for this instance
  Basic auth. The file format is: one "uid:pass:gid1,gid2,..." entry per
  line. Generate the file using `htpasswd -c user`, **remove the `-c` when
  updating (!)**, and add the groups, if any, at the end of each line

## `ldap_server` block

- *Syntax:* `ldap_server <name> { … }`
- *Context:* main
- *Description:* Declare an LDAP server that can be referenced by its `<name>`
  in a `dav_next` block when using LDAP auth

## `auth_ldap_cache_enabled`

- *Syntax:* `auth_ldap_cache_enabled [on|off]`
- *Context:* main
- *Default:* `off`
- *Description:* Define if `dav_next` should use a local cache when doing LDAP
  queries

## `auth_ldap_cache_expiration_time`

- *Syntax:* `auth_ldap_cache_expiration_time <time>`
- *Context:* main
- *Default:* `10` (seconds)
- *Description:* Define the entry timeout when using an LDAP cache

## `auth_ldap_cache_size`

- *Syntax:* `auth_ldap_cache_size <number of entries>`
- *Context:* main
- *Default:* `100`
- *Description:* Define the maximum number of entries to keep in the LDAP cache

## `ldap_resolver`

- *Syntax:* `ldap_resolver <resolver>`
- *Context:* main
- *Description:* The resolver to use as a fallback when the system hostname
  resolution (gethostbyname()) can't resolve the LDAP server hostname hosts

## `ldap_resolver_timeout`

- *Syntax:* `ldap_resolver_timeout <time>`
- *Context:* main
- *Default:* `10` (seconds)
- *Description:* Define the resolver timeout when resolving LDAP hosts

## `servers`

- *Syntax:* `servers <server1>, <server2>…`
- *Context:* `dav_next` (when using `auth ldap`)
- *Description:* Define the server name(s) to use to authenticate users. The
  server names reference the `<name>` in a `ldap_server <name> { … }` block

## `users_url`

- *Syntax:* `users_url <URL>`
- *Context:* `ldap_server`
- *Description:* [LDAP
  URL](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol#URI_scheme)
  of the users (and possibliy groups). The only special meaning in this URL is
  the attribute list. The first (required) attribute is the attribute to look
  for to get the username. If there is another attribute, then it is used as a
  group attribute name. See the examples in the directory `src/dev`

## `groups_url`

- *Syntax:* `groups_url <URL>`
- *Context:* `ldap_server`
- *Description:* [LDAP
  URL](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol#URI_scheme)
  of the groups (when not defined in `users_url`). If this URL is present, then
  the second attribute of the `users_url` is ignored and this URL is then used
  to fetch the groups. In that case, the attribute is the name of the attribute
  to look for the group. When using this directive, the directive
  `member_attribute` must also be present. See the examples in the directory
  `src/dev`

## `binddn`

- *Syntax:* `binddn <DN>`
- *Context:* `ldap_server`
- *Description:* `<DN>` to use when binding for searches

## `binddn_passwd`

- *Syntax:* `binddn_passwd <password>`
- *Context:* `ldap_server`
- *Description:* Password for the `<DN>` to use when binding for searches

## `member_attribute`

- *Syntax:* `member_attribute <attribute>`
- *Context:* `ldap_server`
- *Description:* This field is required when `groups_url` is used. The attribute
  named here is used to list the users belonging to the group. See the examples
  in the directory `src/dev`

## `member_attribute_is_dn`

- *Syntax:* `member_attribute_is_dn [on|off]`
- *Context:* `ldap_server`
- *Default:* `off`
- *Description:* Whether the `member_attribute` is a DN or a just a raw
  value. See the examples in the directory `src/dev`

## `require`

- *Syntax:* `require [valid_user|user <user>|group <group>`
- *Context:* `ldap_server`
- *Description:* Require a valid user, a specified user or group. In case of a
  user or group, the directive can be repeated if more are needed

## `satisfy`

- *Syntax:* `satisfy [any|all]`
- *Context:* `ldap_server`
- *Default:* `any`
- *Description:* Same meaning as in `nginx`'s configuration

## `referral`

- *Syntax:* `referral [on|off]`
- *Context:* `ldap_server`
- *Default:* `off`
- *Description:* Whether to follow LDAP referrals

## `clean_on_timeout`

- *Syntax:* `clean_on_timeout [on|off]`
- *Context:* `ldap_server`
- *Default:* `off`
- *Description:* Tell the module to shutdown an re-connect a LDAP server
connection after a send timeout detected (instead of just marking the connection
as free again)

## `max_down_retries`

- *Syntax:* `max_down_retries <number>`
- *Context:* `ldap_server`
- *Default:* `0`
- *Description:* Retry count for attempting to reconnect to an LDAP server if it
  is considered "DOWN". This may happen if a KEEP-ALIVE connection to an LDAP
  server times out or is terminated by the server end after some amount of time

## `connections`

- *Syntax:* `connections <number>`
- *Context:* `ldap_server`
- *Default:* `1`
- *Description:* The number of connections to the server use concurrently

## `ssl_check_cert`

- *Syntax:* `ssl_check_cert [off|on|full|chain]`
- *Context:* `ldap_server`
- *Default:* `off`
- *Description:* Verify the remote certificate for LDAPs connections. If `off`
  (the default!), any remote certificate will be accepted which exposes you to
  possible man-in-the-middle attacks. Note that the server's certificate will
  need to be signed by a proper CA trusted by your system if this is
  enabled. When `chain` is given, verify cert chain but not hostname / IP in SAN

## `ssl_ca_dir`

- *Syntax:* `ssl_ca_dir <directory>`
- *Context:* `ldap_server`
- *Default:* system certificates directory
- *Description:* CA certificates directory to use when checking the server
  certificate, instead of the system defined directory

## `ssl_ca_file`

- *Syntax:* `ssl_ca_file <file>`
- *Context:* `ldap_server`
- *Description:* CA certificate to use when checking the server certificate

## `connect_timeout`

- *Syntax:* `connect_timeout <time>`
- *Context:* `ldap_server`
- *Default:* `10` (seconds)
- *Description:* Timeout for LDAP connections

## `reconnect_timeout`

- *Syntax:* `reconnect_timeout <time>`
- *Context:* `ldap_server`
- *Default:* `10` (seconds)
- *Description:* The delay before an LDAP reconnection attempts

## `bind_timeout`

- *Syntax:* `bind_timeout <time>`
- *Context:* `ldap_server`
- *Default:* `5` (seconds)
- *Description:* Timeout for LDAP bind attempts

## `request_timeout`

- *Syntax:* `request_timeout <time>`
- *Context:* `ldap_server`
- *Default:* `10` (seconds)
- *Description:* Timeout for LDAP search requests
