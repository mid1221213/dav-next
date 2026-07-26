# dav-next example / dev setup

This document will help you to test an example setup of this project. The
project provides a script (in `…/src/dev/dav-next-dev.sh`) that allows to start
a docker instance, pull an Alpine image, and do whatever is required to build
the module in 3 different possible test setups.

The script is actually the one used to build / test code in this project. If you
plan to contribute in any way, just use it!

Launch it with any (unrecognized) argument (like `-h`) to see usage. With no
argument at all it will start a default Docker container and build an example
setup using default values.

## Prerequisites

- Linux (any distro)
- git
- Docker (can be rootless)

… and… that's it! Everything will be built inside a Docker container using an
Alpine base image.

## Trying…, try it!

Go to a suitable parent directory (`~/src` or `~/projects`) and use the usual
`git` command to clone the repository:

- `cd ~/src`
- `git clone https://codeberg.org/lunae/dav-next.git`
- `cd dav-next`

**Important note:** Of course, never, ever, launch a script without inspecting
carefully **beforehands** what it does, and indeed if it does what it is
supposed to do.

Thus inspect, then launch from the source root directory:
`./src/dev/dav-next-dev.sh`

This will, if all goes well and after starting the Alpine container (named
`dav-next-dev-basic`), installing the required packages (in the container),
running `./configure` and make'ing the `nginx` modules, leave you in a bash
shell in the container. Just look at the 2 lines just above the prompt, they
should display these messages:

```
…
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

At this point, you are in a normal bash shell. Aliases are predefined that you
can use. You can display them by typing the builtin command `alias`. The only
one that is needed for now is `n`. So, type `n` then Return. This will start
`nginx-debug` in foreground with a correctly setup example configuration.

Now launch, on the same host or on another machine in the local network, an
OwnCloud or NextCloud Desktop client, and enter `http://localhost:8888` (or
`http://xxx.local:8888` if the hostname is `xxx` and you're in a local network)
in the "Add account" wizard, select "Next", acknowledge that `http` is insecure
(here we don't care), then enter the Username `mid` and the password
`pOuetpOuet`, and you should be presented with the next screen where you can
select what directories will be sync'ed.

**Enjoy!**
