#! /usr/bin/env bash

# dav-next-example.sh
#
# AVER is the Alpine image version to use
# NVER is the (source) nginx version to use
# PORT is the port to reach the dav-next server (on localhost by default, or wherever your docker context points to)
#
# The following variables configure the LDAP auth, if any
# If "LDAP_URL" and "LDAP_DOMAIN" are set to their default values, the script will install and configure an OpenLDAP example server
# If the URL or the domain is set to a different value than default, the script will suppose you want to use an existing server and will only use this information to setup dav-next to use it
#
# LDAP_URL is the LDAP URL for authentication, defaults to "ldap://localhost"
# LDAP_DOMAIN is the domain component (dc) to use, defaults to "example.com"
# LDAP_NOBODY_SECRET is the password of the user that will help doing LDAP searches with minimal permissions, defaults to "pOuetpOuet"
#
# To see some example invocations of the script, see TRY-ME.md

set -euo pipefail

# check and display mandatory variables
AVER=${AVER:-3.22}
NVER=${NVER:-1.28.0}
PORT=${PORT:-8888}
LDAP_URL=${LDAP_URL:-ldap://localhost}
LDAP_DOMAIN=${LDAP_DOMAIN:-example.com}
LDAP_NOBODY_SECRET=${LDAP_NOBODY_SECRET:-pOuetpOuet}

# check and display positional variables
BUILD_ARG=${1:-}
echo BUILD_ARG=$BUILD_ARG
LDAP=${2:-}
echo LDAP=$LDAP

echo AVER=$AVER
echo NVER=$NVER
echo PORT=$PORT
echo LDAP=$LDAP

export ENV_STR="VER=$NVER\nLDAP=$LDAP"

if [[ -n $LDAP ]]; then
    echo LDAP_URL=$LDAP_URL
    echo LDAP_DOMAIN=$LDAP_DOMAIN
    echo LDAP_NOBODY_SECRET=$LDAP_NOBODY_SECRET

    ENV_STR="$ENV_STR\nLDAP_URL=$LDAP_URL\nLDAP_DOMAIN=$LDAP_DOMAIN\nLDAP_NOBODY_SECRET=$LDAP_NOBODY_SECRET"
else
    LDAP_URL=
    LDAP_DOMAIN=
    LDAP_NOBODY_SECRET=
fi

echo

cd $(dirname $0)

NAME=dav-next${LDAP:+'-ldap'}-example

docker create --name $NAME -h $NAME -it --cap-add=SYS_PTRACE -p $PORT:80 -v `pwd`:/mnt alpine:$AVER || true

docker start $NAME || true

docker exec -i --env-file=<(echo -e "$ENV_STR") $NAME sh -c "apk add bash && bash /mnt/examples/alpine-dav-next-example.sh '$BUILD_ARG'"

if [[ -n $LDAP && $LDAP_URL == "ldap://localhost" && $LDAP_DOMAIN == "example.com" ]]; then
    [[ -s "auth-ldap/auth-ldap.c" ]] || { echo -e "\n\n\nMISSING SUBMODULE, ABORTING!\nhint: type \`git submodule update --init\`\n\n\n" && exit 1; }
    docker exec -i --env-file=<(echo -e "$ENV_STR") $NAME sh -c "bash /mnt/examples/example-with-ldap/alpine-setup-ldap-example.sh"
fi

docker exec -it $NAME sh -c "cd && exec bash"
