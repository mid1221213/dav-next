# `dav-next`

Module for [nginx](http://nginx.org) providing an easy to use WebDAV server
compatible with the NextCloud and OwnCloud Desktop sync clients, the NextCloud
Android client and other WebDAV implementations.

**WARNING: This is not stable or for production, this is beta software**

Some items of the [TODO](docs/TODO.md) need to be implemented before releasing a
beta version.

## About

The nginx `ngx_http_dav_module` implements partial WebDAV specification. More
WebDAV support in nginx requires `ngx_http_dav_ext_module`.

However, the NextCloud Desktop and OwnCloud sync clients extend the WebDAV
specification with some special headers and some specific workflows.

In order to use these sync clients without the burden of installing and
maintaining a full-fledged NextCloud or OwnCloud server, when the need is only
to sync files on a server, enters `dav-next`.

Note that the modules `ngx_http_dav_module` and `ngx_http_dav_ext_module` are
**not needed** to use `dav-next`.

This module is part of a broader project, and for now (and possibly for a long
time) it only supports being built for a **Linux system**!

There are currently two authentication methods available for `dav-next`:
`auth-basic` and `auth-ldap` and they are provided as nginx modules, too. The
former is a kind of hijack on the nginx module of the same name to adapt it for
groups and `dav-next`, and the latter is, as its name suggests, an LDAP
authentication module (that can only be used with `dav-next`).

## Trying…, try it!

**But beforehands, please see this [important note](docs/WARNING.md).**

Now, if you just want to quickly test an example build / config, or you want to
contribute, see [TRY-ME](docs/TRY-ME.md).

You should read [USING](docs/USING.md) too, it explains the main differences in
using the NextCloud Desktop, Android and OwnCloud clients with `dav-next`
compared to the official NextCloud / OwnCloud servers.

## Build

Building nginx with the module should be, as for any module, something like the
following, from the nginx source tree:

```sh
# static modules
./configure --with-debug --with-compat --with-http_ssl_module --with-http_dav_module --add-module=/path/to/nginx-dav-next-source-dir
make modules
```
**or**

```sh
# dynamic modules
./configure --with-debug --with-compat --with-http_ssl_module --with-http_dav_module --add-dynamic-module=/path/to/nginx-dav-next-source-dir
make modules
```

Note that the `--with-xxx` (except `--with-debug`) are
mandatory. `--with-http_dav_module` is used only for a `#define` and may (will)
be removed later.

### Requirements

Besides the same as own nginx' requirements, the OpenLDAP dev package is
needed. The nginx's Lua module along with cjson are required for development
when logging full HTTP requests and responses.

Due to the way nginx modules are built, the complete `nginx` source must be
available (tested with `nginx` ≥ 1.30.4).

## Configuration

### Example configurations

See the `src/dev/` subdir and the [TRY-ME](docs/TRY-ME.md) documentation.

### Configuration directives

The simplest configration for `dav-next` is the following, here in a location
block:

```
location / {
	dav_next dav-test {
		auth basic;
	}
}
```

The available directives are detailed in [CONFIGURATION](docs/CONFIGURATION.md).

## Test

**The tests are currently being written / adapted.**

## Known limitations

The limits are, FYI or if you dare to test something else (tell me!):

### [advice] Only use an ext4 formated partition as backend storage

Because, for now, only this filesystem has been tested.

#### `mtime` precision

This module will not work correctly on a filesystem with a `mtime` resolution of
1 (or worse) second. The reason is that to generate the header `ETag` and
reflect multiple changes in a file without having to compute a hash, the chosen
solution is to increment the `mtime` (actually the corresponding subdivision of
a second) when the change occurs at the same exact time. This is a cheap, but
effective way to get the `Etag` feature compatible with the Nextcloud or
OwnCloud clients.

#### Unique (and available at all) inodes

The module uses another hackish way to stay DB-less: it uses the inode number as
the unique file ID. This means that there must be inodes on the filesystem, and
that they must be unique. This means that **cross-filesystems storage are not
supported**.

## Useful references

### Compatible clients

- OwnCloud Desktop: [https://github.com/owncloud/client](https://github.com/owncloud/client)
- NextCloud Desktop: [https://github.com/nextcloud/desktop](https://github.com/nextcloud/desktop)
- NextCloud Android:
  - Play: [https://play.google.com/store/apps/details?id=com.nextcloud.client](https://play.google.com/store/apps/details?id=com.nextcloud.client)
  - F-Droid: [https://f-droid.org/packages/com.nextcloud.client/](https://f-droid.org/packages/com.nextcloud.client/)
- Other WebDAV clients, specification: [https://tools.ietf.org/html/rfc4918](https://tools.ietf.org/html/rfc4918)

Please note that `dav-next` is not 100 % WebDAV compliant, but that does not
prevent it from being used by some widespread clients like Nautilus (the file
manager of Gnome) or Dolphin (the file manager of KDE / Plasma). It used to work
with Gnome Online Accounts but unfortunately it is not the case anymore, for
now…

### Copyright & Licenses

Some parts of this code has been copied, and modified, from the source code of
`nginx`, and the modules `ngx_http_dav_module`, `ngx_http_dav_ext_module` and
`nginx-auth-ldap`. The copyright and the license of the corresponding code prior
to modifications are not changed and are available at the following URLs:

- nginx: [https://nginx.org](https://nginx.org)
- ngx_http_dav_module: [https://nginx.org/en/docs/http/ngx_http_dav_module.html](https://nginx.org/en/docs/http/ngx_http_dav_module.html)
- ngx_http_dav_ext_module: [https://github.com/arut/nginx-dav-ext-module](https://github.com/arut/nginx-dav-ext-module)
- nginx-auth-ldap: [https://github.com/Ericbla/nginx-auth-ldap](https://github.com/Ericbla/nginx-auth-ldap)

All code borrowed from the above 4 projects that has been modified, and all the
remaining code of this project is licensed under the GNU AGPLv3. See the file
[COPYING](COPYING).

The file [COPYRIGHT](COPYRIGHT) contains the copyright notices, where each
copyright line apply to the corresponding code only.
