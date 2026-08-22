# Important note

The sync'ed root directory, which is the parent directory of the user and groups
sync'ed directories is virtual and **should⁽¹⁾ be server-side read-only**!

Actually, it should be set as such with a `chmod` command. Unfortunately, for
now, the OwnCloud and NextCloud Desktop clients do not change the permissions of
read-only directories (although they are correctly flagged by `dav-next`), thus
nothing prevents you to write to the local version of the root sync directory or
even delete the groups or your user directory.

That will lead to trouble. E.g. when using the OwnCloud Desktop client, that
makes the sync fail for the item you have put in until you remove it.

Worse, the NextCloud Desktop client will simply **delete** everything in that
root directory by itself, **without any warning nor notification!**, that is not
already existing server-side. See what [this MR in
NextCloud](https://github.com/nextcloud/desktop/pull/10226) fixes.

Moreover, if you remove locally a group's, or your user's, directory, the
behavior is wrong for both of the Desktop clients, too. Don't do that.

For now, the only usable workaround to this issue, if there is a need, is to
sync from a subdirectory instead of directly from the root sync directory (this
way you would need a sync'ed directory for each group you belong to and one for
your user directory). Doing a `chmod -w <ROOTDIR>` **may** be OK, but because
the NextCloud and OwnCloud Desktop clients need to store their sync DBs / logs
there, once they are created it's apparently OK, but they (may?) need to be
rotated.

⁽¹⁾ currently, unless you use the directive `root_is_writable off` in
`dav-next`, it defaults to `on` to prevent accidental deletion of files /
directories by NextCloud and make all sync from the root directory fail.
