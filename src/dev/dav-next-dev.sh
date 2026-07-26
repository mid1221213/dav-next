#! /usr/bin/env bash

# dav-next-example.sh
#
# AVER is the Alpine image version to use
# NVER is the (source) nginx version to use
# PORT is the port to reach the dav-next server (on localhost by default, or wherever your docker context points to)
#
# To see some example invocations of the script, see TRY-ME.md

set -euo pipefail

# set mandatory variables
: ${AVER:=3.24.1}
: ${NVER:=1.30.4}
: ${RESET:=noreset}
: ${BUILD:=nobuild}
: ${LDAP:=noldap}
: ${LDAP2:=}
: ${FULL:=nofull}
: ${PORT:=}

function usage {
    cat <<EOF
$(basename "$0"): you must provide up to 3 parameters in any order: [no]reset [no]ldap|ldap2 [no]full
An ommitted parameter is set as the "no" version of it

[no]reset:	reset (or not) the container
[no]build:	build (or not) the modules (implied by "reset")
[no]ldap|ldap2:	setup LDAP (or basic) version, ldap2 for an alternate LDAP config
[no]full:	setup full (or normal) logs
EOF
}

# check parameters

for param in "$@"; do
    case "$param" in
        reset|noreset)
            RESET=$param
            ;;
        build|nobuild)
            BUILD=$param
            ;;
        noldap)
            LDAP=$param
            : ${PORT:=8888}
            ;;
        ldap)
            LDAP=$param
            : ${PORT:=8889}
            ;;
        ldap2)
            LDAP=ldap
            LDAP2=-lunae
            : ${PORT:=8890}
            ;;
        full|nofull)
            FULL=$param
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [[ $LDAP == ldap ]]; then
    NAME=dav-next-dev-ldap$LDAP2
    pkg_ldap="openldap openldap-back-mdb ${LDAP2:+openldap-clients openldap-overlay-dynlist}"
    dav_next_module_type=ldap
else
    NAME=dav-next-dev-basic
    pkg_ldap=""
    dav_next_module_type=basic
    : ${PORT:=8888}
fi

export LDAPSET=${LDAP/noldap/}
export FULLSET=${FULL/nofull/}
export FULLPORTSPEC=${FULLSET:+-p 1$PORT:8080}
export FULLPORTINCLUDE=${FULLSET:+include full.conf;}

pkg_aux="$pkg_ldap ${FULLSET:+nginx-mod-http-lua lua5.1-cjson}"

# display (some) mandatory variables
echo AVER=$AVER
echo NVER=$NVER
echo PORT=$PORT
echo FULLPORTSPEC=${FULLPORTSPEC:--N/A-}

echo $RESET $BUILD $LDAP$LDAP2 $FULL

cd $(dirname $0)

CONT_ID="$(docker container ls --quiet --filter name=$NAME)"

if [[ $RESET == reset && -n $CONT_ID ]]; then
    docker rm -f $NAME
    CONT_ID=""
fi

if [[ -z $CONT_ID ]]; then

    docker create --name $NAME -h $NAME -it --cap-add=SYS_PTRACE -p $PORT:80 $FULLPORTSPEC -v $(pwd)/..:/mnt alpine:$AVER

    docker start $NAME

    docker exec -t $NAME sh -c "apk add bash vim alpine-sdk gettext-envsubst gdb nginx nginx-debug nginx-mod-dev openldap-dev $pkg_aux"

    docker exec -i $NAME bash -euo pipefail <<EOF

cd /mnt/dev

export FULLPORTINCLUDE="$FULLPORTINCLUDE"
export LDAP2=$LDAP2
envsubst <default${LDAPSET:+-ldap}.conf >/etc/nginx/http.d/default.conf
cp -af full.conf /etc/nginx/

if [[ $LDAP == ldap ]]; then
    if [[ -n "$LDAP2" ]]; then
        sed -i -e 's/nis.schema/nis.schema\ninclude \/etc\/openldap\/schema\/dyngroup.schema\ninclude \/mnt\/dev\/example-lunae.schema/' -e 's/^database config/database config\nrootpw secret/' /etc/openldap/slapd.conf
    fi

    slapd
    slaptest -v

    if [[ -n "$LDAP2" ]]; then
        ldapmodify -v -H ldap://localhost/ -x -D cn=config -w secret -f example-lunae-conf.ldif
    fi

    slapadd -v -l example$LDAP2.ldif
else
    cp -a htpasswd /etc/nginx/
fi

cp -af .gdbinit .inputrc .bashrc ~/
sed -i -e 's/^worker_processes auto/worker_processes 1/' /etc/nginx/nginx.conf

ln -sf /var/log/nginx/access.log /var/log/nginx/error.log /var/log/nginx/proxy_full.log ~/
mkdir -p /var/lib/nginx/html/files /var/lib/nginx/html/uploads
chown -R nginx:nginx /var/lib/nginx/html/

EOF

fi

if [[ -z $CONT_ID || $BUILD == build ]]; then

    docker exec -i $NAME bash -euo pipefail <<EOF

cd /usr/src/nginx-$NVER

./configure --with-debug --with-compat --with-http_ssl_module --with-http_dav_module --add-dynamic-module="/mnt"
make -j modules

install -D -m755 objs/dav_next_module.so /usr/lib/nginx/modules/ngx_http_dav_next_module.so
install -D -m755 objs/dav_next_auth_${dav_next_module_type}_module.so /usr/lib/nginx/modules/ngx_http_dav_next_auth_${dav_next_module_type}_module.so
echo "load_module \"modules/ngx_http_dav_next_module.so\";" | install -D -m644 /dev/stdin "/etc/nginx/modules/10_http_dav_next.conf"
echo "load_module \"modules/ngx_http_dav_next_auth_${dav_next_module_type}_module.so\";" | install -D -m644 /dev/stdin "/etc/nginx/modules/11_http_dav_next_auth_${dav_next_module_type}.conf"

cd /mnt

nginx -t || true

EOF

fi

docker exec -it $NAME sh -c "cd && exec bash"
