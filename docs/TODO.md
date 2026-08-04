# TODO

- reported directory size is 0 byte, not the actual size of the directory
  content including the sizes of its subdirectories
- quota management
- versionning
- trashbin
- public share feature
- quota? → how?
- WebSocket for file modification push-notifications (NC)
- FS size left checking when PUT / COPY?
- e2e testing
- e2ee?
- mutex-protections? → check if needed
- multi-dav-next in mono-nginx
- avatars?
  - `/remote.php/dav/avatars/fake/32.png`
  - `/remote.php/dav/avatars/fake/128.png`

# DONE, FTR

- `ngx_uint_t protos = NGX_SSL_SSLv2…` (!) → check which protos to keep → NGX_SSL_DEFAULT_PROTOCOLS
- test `client_max_body_size xxxM`
  - minimal size
  - adjust bluk upload chunk size
- APKBUILD for Alpine APK packaging
- "finish" README.md == now publishable
- potential conflict between LOCK / UNLOCK between NC client
  (/remote.php/dav/files/$user/…) and direct WebDAV (/remote.php/webdav/…) → to
  check == nope, no conflict
- make it possible to use with https://github.com/Ericbla/nginx-auth-ldap.git
  (group auth) = use my slightly patched version:
  https://codeberg.org/lunae/auth-ldap
- avoid multi-thread problems
- auto-create [user] dirs (as long as NC Desktop crashes?)
- make sure auth'ed user matches the user directory in `/remote.php/dav/files/`
  and `/remote.php/dav/uploads/`
- "satisfy any" should not be mandatory
- "etag off" should not be mandatory → force it to 0 in ACCESS_PHASE
- fix 500 in DELETE `/remote.php/dav/files/[user]/ocs/v2.php/core/apppassword`
- chunked upload algo, NG
  - MKCOL on `/remote.php/dav/uploads/[user]/[xferID]`
    - OC-Total-Length to check FS free space / "NC" quotas / "my" limit per file?
    - status must be 201 (created)
  - WHILE chunk-to-send DO (possibly in //, except for the last chunk)
    - PUT to `/remote.php/dav/uploads/[user]/[xferID]/0000000000000001` (etc…)
  - MOVE (with black magic!) `/remote.php/dav/uploads/[user]/[xferID]/.file` →
    `/remote.php/dav/files/[user]/[destination]`
    - status must be 201 (created) or 204 (no content = overwritten)
    - OC-FileID
    - ETag
