# MISC

## Limits

- see `USING.md`

## Bugs?

- NC desktop
  - `src/libsync/account.cpp:786`
    - DELETE `/remote.php/dav/files/[user]/ocs/v2.php/core/apppassword` (wrong path + no auth?!)
  - `src/gui/owncloudsetupwizard.cpp:537` ↓ not sure -- **UPDATE: fixed in NC**
    - `createRemoteFolder();` should be followed by a `return;` to avoid double call to `finalizeSetup(bool);`? ATM if remote [user] folder does not exist, MKCOL then crash at `src/gui/owncloudsetupwizard.cpp:???`

## Account add sequences

**NOT UPDATED**

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

(mandatory for Android client 😢) -- see "Basic Auth" for file contents

- GET `/status.php` → 200
- GET `/` → 200
- PROPFIND `/remote.php/dav/files//` → 401
- GET `/ocs/v2.php/cloud/capabilities?format=json` → 200
- POST `/index.php/login/v2` → 200
- AUTH-GET `/ocs/v1.php/cloud/user?format=json`
- AUTH-PROPFIND `/remote.php/dav/files/fake/` → 404 or 200 (no getetag)
- AUTH-GET `/remote.php/dav/avatars/fake/32.png` → 404?
- AUTH-PROPFIND `/remote.php/dav/files/fake/` → 200
