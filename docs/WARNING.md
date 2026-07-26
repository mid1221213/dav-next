# Important note

The sync'ed root directory, which is the parent directory of the user and groups
sync'ed directories is virtual and **read-only**!

Actually, it should be set as-is with a `chmod` command. Unfortunately, for now,
the OwnCloud and NextCloud Desktop clients do not change the permissions of
read-only directories (although they are correctly flagged by `dav-next`), thus
nothing prevents you to write to the local version of the root sync directory or
even delete the groups or your user directory.

That will lead to trouble. E.g. using the OwnCloud Desktop client, that makes
the sync fail for the item you have put in until you remove it.

Worse, the NextCloud Desktop client will simply **delete** everything in that
root directory by itself, **without any warning nor notification!**, that is not
already existing server-side. Moreover, if you remove locally a group, or your
user, directory, the behavior is wrong for both of the Desktop clients, too.

Fortunately, there are workarounds to this issue, the recommended one being
doing a `chmod -w <ROOTDIR>` (just once, when it has been created by the Desktop
client), or sync'ing from a subdirectory instead of directly from the root sync
directory (this way you would need a sync'ed directory for each group you belong
to and one for your user directory).
