# Using dav-next with OwnCloud / NextCloud clients

This document explains the main differences in using the OwnCloud Desktop,
NextCloud Desktop and Android clients with `dav-next` compared to the actual
OwnCloud / NextCloud servers.

Remember that `dav-next` is **not** a full OwnCloud or NextCloud server
replacement, far from it!  It only provides a file synchronization server that
is compatible with, among other, the OwnCloud and NextCloud clients.

## Limitations when using any client

- each reported directory size is still, for now, 0 byte, not the actual size of
  the directory content including the sizes of its subdirectories. That *may*
  lead to bugs in clients
- there is no quota management (yet)
- there is no versionning (yet)
- there is no trashbin (yet)
- there is no internal or public share feature (yet?)

## OwnCloud / NextCloud Desktop clients' differences

You are supposed to know how to use the OwnCloud or NextCloud Desktop
clients. If you don't, then please refer to the client documentation to learn
how to use it.

Say you are the user `ali` and you are included in the groups `family` and
`friends`, you will be able to select among those 3 subdirectories from the
directory selection dialog in the add account / directory sync setup. The user
directory, `ali`, is personal, while the others, corresponding to the groups
`family` and `friends`, are shared by their respective members.

See also this [important note](WARNING.md).

## NextCloud Android client's differences

**Important note:** The login flow currently used in the NextCloud Android
client uses a WebFlow. But now, the previously implemented flow, which was a
quick hack that simply returned the user password as token, does not work
anymore. The flow in the NextCloud Android client is now "v2", thus this hack
needs to be adapted or better, be implemented the right way.

You are supposed to know how to use the NextCloud Android client. If you don't,
then please refer to the client documentation to learn how to use it.

The Android client does not actually sync the files (by default), it allows you
to upload and download them. If you try to upload something to the root sync
directory, the server (i.e. `dav-next`) will correctly return an error, and the
upload will fail. There is no real need for a workaround.

# WebDAV access

It is possible to access the resources without the OwnCloud nor Nextcloud
Desktop client, in a pure WebDAV manner using a URL like
`https://example.com/remote.php/webdav/`, or even using Nautilus / Dolphin with
a URL like `davs://example.com/`!

For Window$ 10 users, I don't care, but [these
tweaks](https://www.maketecheasier.com/map-webdav-drive-windows10/) may help
to allow to mount a WebDAV drive. NOTE: M$ is reportedly deprecating the WebDAV
client…?

For Window$ 11+ users, I don't care neither. If it is possible at all and you
wish to document the required steps, feel free to make an MR, but without any
guarantee to be merged…
