# `dav-next`

Module for [nginx](http://nginx.org) providing an easy to use WebDAV server
compatible with the NextCloud Desktop sync client, the NextCloud Android client,
Gnome Online Account WebDAV feature and other WebDAV implementations.

**WARNING: This is not prod, nor even beta quality software! Call me WIP**

## About

The nginx `ngx_http_dav_module` implements partial WebDAV specification. More
WebDAV support in nginx requires `ngx_http_dav_ext_module`.

However, the NextCloud Desktop sync client extends the WebDAV specification
with some special headers and some specific workflows.

In order to use the sync client without the burden of installing and
maintaining a full-fledged NextCloud server, when the need is only to sync
files on a server, enters `dav-next`.

The modules `ngx_http_dav_module` and `ngx_http_dav_ext_module` are **not**
needed to use `dav-next`.

This module is part of a broader project, and for now it only supports being
built for a **Linux system**!

## Trying…, try it!

If you just want to quickly test an example build / config, read
[TRY-ME.md](TRY-ME.md). Read it if possible before git-cloning the project
because there is a submodule available in case you would like to authenticate
users with an LDAP server. It is required for 2 of the 3 test setups. The only
other auth method is the good old htpasswd, and it is available with the third
test setup.

You should read [USING.md](USING.md) too that explains the main differences in
using the NextCloud Desktop and Android clients with `dav-next` compared to the
official NextCloud server.

## Build

Building nginx with the module should be, as for any module, something like the
following, from the nginx source tree:

```sh
# static module
./configure --add-module=/path/to/nginx-dav-next-module
make

# OR

# dynamic module
./configure --add-dynamic-module=/path/to/nginx-dav-next-module
make
```

## Requirements

Nothing needed except than the nginx' requirements.

### Build

- nginx source (tested with >= 1.28.0) -- due to the way nginx modules are
  built, the complete nginx source must be available

### Run

- nginx binary (tested with >= 1.28.0)

### Test

**The tests have not been rewritten / adapted yet!**

## Known limitations

### Only use an ext4 formated partition as backend storage (advice)

Because, for now, only this filesystem has been tested.

The actual limits are, FYI or if you dare to test something else (tell me!):

#### `mtime` precision

This module will not work correctly on a filesystem with a `mtime` resolution of
1 (or worse) second. The reason is that to generate the header `ETag` and
reflect multiple changes in a file without having to compute a hash, the chosen
solution is to increment the `mtime` (actually the corresponding subdivision of
a second) when the change occurs in the same second. This is a cheap, but
effective way to get the `Etag` feature compatible with the Nextcloud clients.

#### Unique (and available at all) inodes

The module uses another hackish way to stay DB-less: it uses the inode number as
the unique file ID. This means that there must be inodes on the filesystem, and
that they must be unique. This means that **cross-filesystems storage are not
supported**.

### Only one dav-next instance per nginx configuration

This limitation is temporary and will be removed next.

## Configuration

### `dav_next_server_zone`

- *Syntax:*  `dav_next_server_zone zone=NAME:SIZE [timeout=TIMEOUT]`
- *Context:* `http`
- *Description:* Declare a shared zone for the multiple nginx process to share
  data about this `dav-next` instance. The `zone` parameter is mandatory and the
  default `timeout` parameter (`TIMEOUT` in nginx time format) is set to 60
  seconds. `NAME` is an arbitrary name you wish to use, `SIZE` is the size of
  the shared memory (in nginx size format, if you don't know what to set, try
  `10M`)

### `dav_next_server`

- *Syntax:* `dav_next_server zone=NAME`
- *Context:* `server`
- *Description:* Use the zone with this `NAME` on this server

### Example configuration

```
http {
    dav_next_server_zone zone=foo:10M;

    …

    server {
        …

        dav_next_server zone=foo;
        root /data/www;
    }
}
```

## Useful references

### Compatible clients

- NextCloud Desktop: https://github.com/nextcloud/desktop
- NextCloud Android:
  - Play: https://play.google.com/store/apps/details?id=com.nextcloud.client
  - F-Droid: https://f-droid.org/packages/com.nextcloud.client/
- WebDAV specification: https://tools.ietf.org/html/rfc4918

Please note that `dav-next` is not 100 % WebDAV compliant. It does not prevent
it from being used by some widespread clients like Gnome Online Accounts (for
better results using GOA, choose the option "WebDAV", **not "NextCloud"**!), …

### Copyright & Licenses

Some parts of this code has been copied, and modified, from the source code of
`nginx`, and the modules `ngx_http_dav_module` and `ngx_http_dav_ext_module`.
The copyright and the license of the corresponding code prior to modifications
are not changed and are available at the following URLs:

- nginx: http://nginx.org
- ngx_http_dav_module: http://nginx.org/en/docs/http/ngx_http_dav_module.html
- ngx_http_dav_ext_module: https://github.com/arut/nginx-dav-ext-module

All code from the above 3 projects that has been modified, and all the remaining
code of this project is licensed under the GNU AGPLv3. See the file COPYING.

The file COPYRIGHT contains the copyright notices, where each copyright line
apply to the corresponding code only.
