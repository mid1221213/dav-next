# TODO

- quota? → how?
- WebSocket for file modification push-notifications
- FS size left checking when PUT / COPY?
- shares
- e2e testing
- e2ee?
- mutex-protections? → check if needed
- multi-dav-next in mono-nginx
- avatars?
  - `/remote.php/dav/avatars/fake/32.png`
  - `/remote.php/dav/avatars/fake/128.png`

# DONE

- "finish" README.md == now publishable
- potential conflict between LOCK / UNLOCK between NC client (/remote.php/dav/files/$user/…) and direct WebDAV (/remote.php/webdav/…) → to check == nope, no conflict
- make it possible to use with https://github.com/Ericbla/nginx-auth-ldap.git (group auth) = use my slightly patched version: https://codeberg.org/lunae/auth-ldap
- avoid multi-thread problems
- auto-create [user] dirs (as long as NC desktop crashes?)
- make sure auth'ed user matches the user directory in `/remote.php/dav/files/` and `/remote.php/dav/uploads/`
- "satisfy any" should not be mandatory → hack to avoid this: save satisfy mode in ACCESS_PHASE and restore it in PRECONTENT_PHASE, force it to "any" in case of bypass (= no need for auth) == err, no, useless requirement, "satisfy" can be what the user wants it to be
- "etag off" should not be mandatory → force it to 0 in ACCESS_PHASE
- fix 500 in DELETE `/remote.php/dav/files/[user]/ocs/v2.php/core/apppassword`
- chunked upload algo, NG
  - MKCOL on `/remote.php/dav/uploads/[user]/[xferID]`
    - OC-Total-Length to check FS free space / "NC" quotas / "my" limit per file?
    - status must be 201 (created)
  - WHILE chunk-to-send DO (possibly in //, except for the last chunk)
    - PUT to `/remote.php/dav/uploads/[user]/[xferID]/0000000000000001` (etc…)
  - MOVE (with black magic!) `/remote.php/dav/uploads/[user]/[xferID]/.file` → `/remote.php/dav/files/[user]/[destination]`
    - status must be 201 (created) or 204 (no content = overwritten)
    - OC-FileID
    - ETag

# MISC

## limits

- cf README.md

## bugs?

- NC desktop
  - `src/libsync/account.cpp:786`
    - DELETE `/remote.php/dav/files/[user]/ocs/v2.php/core/apppassword` (wrong path + no auth?!)
  - `src/gui/owncloudsetupwizard.cpp:537` ↓ not sure
    - `createRemoteFolder();` should be followed by a `return;` to avoid double call to `finalizeSetup(bool);`? ATM if remote [user] folder does not exist, MKCOL then crash at `src/gui/owncloudsetupwizard.cpp:???`

## account add sequences

### Basic Auth process

- GET `/status.php` → 200
```json
  {
    "edition": "",
    "extendedSupport": false,
    "installed": true,
    "maintenance": false,
    "needsDbUpgrade": false,
    "productname": "dav-next",
    "version": "24.0.7.1",
    "versionstring": "24.0.7"
  }
```
- GET `/` → 401
- PROPFIND `/remote.php/dav/files//` → 401
- GET `/ocs/v2.php/cloud/capabilities?format=json` → 200
```json
  {
    "core": {
      "pollinterval": 60,
      "webdav-root": ""
    },
    "dav": {
    },
    "files": {
      "bigfilechunking": false,
      "comments": false,
      "undelete": false,
      "versioning": false
    }
  }
```
- AUTH-GET `/ocs/v1.php/cloud/user?format=json` → 200
```json
  {
    "ocs": {
      "meta": {
        "status": "ok",
        "statuscode": 100,
        "message": null
      },
      "data": {
        "id": "fake",
        "display-name": "fake@DAV-Next"
      }
    }
  }
```
- AUTH-PROPFIND `/remote.php/dav/files/fake/` → 404 or 200 (no getetag)
- AUTH-GET `/remote.php/dav/avatars/fake/32.png` → 404?
- AUTH-PROPFIND `/remote.php/dav/files/fake/` → 200

### OAuth process

(mandatory for Android client 😢, thus eventually **implemented**) -- see "Basic Auth" for file contents

- GET `/status.php` → 200
- GET `/` → 200
- PROPFIND `/remote.php/dav/files//` → 401
- GET `/ocs/v2.php/cloud/capabilities?format=json` → 200
- POST `/index.php/login/v2` → 200
- AUTH-GET `/ocs/v1.php/cloud/user?format=json`
- AUTH-PROPFIND `/remote.php/dav/files/fake/` → 404 or 200 (no getetag)
- AUTH-GET `/remote.php/dav/avatars/fake/32.png` → 404?
- AUTH-PROPFIND `/remote.php/dav/files/fake/` → 200

## WebDAV access

It is possible to access the resources without Nextcloud Desktop client, in a pure WebDAV manner using a URL like `https://example.com/remote.php/webdav/`, or even using Nautilus with a URL like `davs://example.com/`!

For Window$ 10 users, [these tweaks](https://www.maketecheasier.com/map-webdav-drive-windows10/) are required to allow to mount a WebDAV drive. NOTE: M$ is reportedly deprecating the WebDAV client…?
