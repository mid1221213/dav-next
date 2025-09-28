# dav-next example setup

This doc will help you to test an example setup of this project. The project
provides a (quickly made) script that allows to start a docker instance,
pulling an Alpine image, and do whatever is required to build the module
in 3 different possible test setups.

## Prerequisites

- Linux
- bash
- docker (can be rootless)

## Trying…, try it!

### `git clone` with or without the submodule

First, if you already have git-cloned this repo, if you didn't include the init
of the submodule you can do it afterwards with: `git submodule update --init`
from the project root directory.

To clone with the submodule, issue a `git clone --recurse-submodules https://codeberg.org/lunae/dav-next.git`,
this will clone the repo with the LDAP auth submodule. This module is optional
but allows using, along with the LDAP auth, a "groups" feature.

### Quick try HowTo…

The instructions given below can be repeated, as long as the script doesn't
error **and** stop, you can consider it did the job. You can safely ignore the
error messages if the scripts doesn't stop, it usually means one action has
already been done in a previous invocation. It's just an example setup!

#### Quickly try dav-next with the LDAP example auth server

Launch, from the root directory: `./src/dav-next-example.sh refull ldap`

This will, if all goes well, leave you in a shell in a container named
`dav-next-ldap-example`. Just look at the line just above the prompt, beginning
with an arrow "→", you just have to copy and paste its commands and hit Return.

Now launch NextCloud Desktop Client and enter `http://localhost:8888` in the
NextCloud "Add account" wizard, select "Next", then enter the Username `ben` and
the password `pOuetpOuet`, and you should be presented with the next screen
where you can select what directories will be sync'ed.

**Enjoy!**

### Longer example HowTos

These are longer instructions of the same example HowTos.

#### Try dav-next with the LDAP example auth server

Launch, from the root directory: `./src/dav-next-example.sh refull ldap`

This will, if all goes well, leave you in a shell in a container named
`dav-next-ldap-example`. Just look at the line just above the prompt, beginning
with an arrow "→", you just have to copy and paste its commands and hit Return.

This will kill any running nginx process from a previous invocation and start a
new one, and then show you the flow of logs of the nginx server.

This script will be changed next to smoothly allow to test `dav-next` without
seeing all the rough details here. It is left as-is for the moment to allow
easier debug.

Once the steps above are done, you can try to connect using the official
NextCloud Desktop Client auth with any user login present in the `example.com`
LDAP server, see the file
[src/examples/example-with-ldap/dc=example.com.ldif](src/examples/example-with-ldap/dc=example.com.ldif)
for details. The passwords for anything in the `examples` directory are all the
same: `pOuetpOuet`.

So for instance you can try to enter `http://localhost:8888` in the NextCloud
"Add account" wizard, select "Next", then enter the username `ben` and the
password `pOuetpOuet`, and you should be presented with the next screen where
you can select what directories will be sync'ed.

As the LDAP is populated with some groups, you should see the ones the user
`ben` is affiliated too, and a subdirectory `ben` too. The former directories
are shared by the group members while the user directory is not shared.

**/!\\ WARNING /!\\:** The parent directory of these user and group directories is
**read-only**! Unfortunately, for now, the NextCloud Desktop Client does not
change the permissions of directories, so nothing prevents you to write to the
local version of the sync'ed parent directory. There are workarounds to this
issue, e.g. you can `chmod a-w [DIR]` (just once), or sync a subdirectory of the
server directory instead of root (this way you would need a sync directory for
each group and one for your user directory).

#### Try dav-next with an external LDAP auth server

The script `./src/dav-next-example.sh` can be launched after setting (and
exporting) some environment variables. For this to work, the LDAP server should
provide a DB with the same structure as the example LDAP server.

The available variables are the following:

- LDAP_URL: URL of the ldap server, with only the scheme and the host / port
- LDAP_DOMAIN: the domain component to use instead of `example.com`
- LDAP_NOBODY_SECRET: the password of the user `nobody`

With these variables set, try the `dav-next` by doing the same steps as in the
previous section. Note that this testing mode will **not** provide an LDAP
example server.

#### Try dav-next with local htaccess users

This a more basic setup that does not query an LDAP server for authenticating
but use a local htaccess file instead.

The command to launch is `./src/dav-next-example.sh refull`. The created
container will be named `dav-next-example` and will use a minimally htaccess
file that contains two users, `mid` and `fake`, using the same password:
`pOuetpOuet`. In this LDAP-less mode, no groups are available.

### The `./src/dav-next-example.sh` invocation

This script, used in the sections above, create and launches a container that
will be used to build the module(s) and to host the nginx process to test.

It takes 2 (positional) parameters: the "action" and the "ldap" option.

The action can be one of:
- "reconf": force rerun the `configure` script
- "reinst": force the reinstallation of the setup
- "refull": both of the above at the same time

If not set, the script will do only the necessary steps.

The "ldap" option shoud either be present (i.e. the value "ldap" is specified as
the second parameter), or left unset. If you wish to set the "ldap" option
without using one of the "action" values, use something like
`./src/dav-next-example.sh "" ldap`

As stated above, the script leaves you in a bash running in the container. To
quit, simply write `exit` of type the keys `Ctrl + d`, as you would exit any
shell.
