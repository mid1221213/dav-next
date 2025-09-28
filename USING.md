# Using dav-next with NextCloud clients

This doc explains the main differences in using the NextCloud Desktop and
Android clients with `dav-next` compared to the official NextCloud server.

These differences, especially those marked below in important notes, makes this
server unusable in the real world. Anyway, for now **it's a WIP**.

Remember that `dav-next` is **not** a full NextCloud replacement, far from it!
It only provides a file synchronization server that is compatible with, among
other, the NextCloud clients.

## Common differences

- each reported directory size is only the size of the directory without
  including the sizes of its subdirectories. That *may* lead to bugs in clients.
- no quota (yet)
- no reshare (yet?)

## NextCloud Desktop Client

You are supposed to know how to use the NextCloud Desktop Client. If you don't,
then please refer to the client documentation to learn how to use it.

Say you are the user `mid` and you are included in the groups `family` and
`friends`, you will be able to select among those 3 subdirectories from the
directory selection dialog in the add account / directory sync setup. The user
directory, `mid`, is personal, while the others, corresponding to the groups
`family` and `friends`, are shared by their respective users.

**Important note:** The parent directory of these user and group directories is
**read-only**!  Unfortunately, for now, the NextCloud Desktop Client does not
change the permissions of read-only directories, so nothing prevents you to
write to the local version of the root sync directory, making the sync fail
until you remove what you've put at this place, or worse, until the NextCloud
Desktop Client decides to remove that by itself (it can, without any warning!).

There are workarounds to this issue, e.g. you can `chmod a-w [DIR]` (just once),
or sync a subdirectory instead of the root sync directory (this way you may
need a sync directory for each group and one for your user directory).

## NextCloud Android Client

You are supposed to know how to use the NextCloud Android Client. If you don't,
then please refer to the client documentation to learn how to use it.

The Android client does not actually sync the files (by default), it allows to
upload and download them. If you try to upload something to the root sync
directory, the server (i.e. `dav-next`) will correctly return an error, and the
upload will fail. There is no need for a workaround.

**Important note:** The login flow used nowadays in the Android Android Client
uses OAuth. For now, and this is not recommended, the implemented flow simply
returns the user password as token. This will change.
