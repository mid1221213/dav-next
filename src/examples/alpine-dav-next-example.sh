#!/usr/bin/env bash

set -euo pipefail

: $VER
NGINX_VER=nginx-$VER
NGINX_URL=https://nginx.org/download/$NGINX_VER.tar.gz

cd

reconf=
reinst=
case $1 in
    refull|reconf)
        reconf=reconf
        reinst=reinst
        ;;
    reinst)
        reinst=reinst
        ;;
esac

[[ $1 != refull ]] || rm -rf $NGINX_VER $NGINX_VER.tar.gz

LDAP=$LDAP # declare variable (as void if !exists)

apk add alpine-sdk brotli-dev gd-dev geoip-dev hiredis-dev jansson-dev libmaxminddb-dev libxml2-dev libxslt-dev linux-headers openssl-dev pcre-dev perl-dev pkgconf zeromq-dev zlib-dev zstd-dev !zstd-static luajit-dev gdb nginx-mod-http-lua nginx-debug

[[ -z $LDAP ]] || apk add libldap openldap openldap-back-mdb openldap-overlay-dynlist openldap-dev

[[ -f $NGINX_VER.tar.gz ]] || wget $NGINX_URL
[[ -f $NGINX_VER ]] || tar xzf $NGINX_VER.tar.gz

cd $NGINX_VER
# patch -p1 < /mnt/nginx-reveal-modules-signatures.patch # only used when recompiling nginx

export CFLAGS="-DNGX_HTTP_HEADERS"

if [[ ! -f Makefile || -n $reconf ]]; then
    export LDAP
    /mnt/configure-nginx.sh /mnt
fi

make -q modules >& /dev/null || reinst=Y
make -j modules

if [[ -n $reinst ]]; then
    cp -af objs/dav_next_module.so $HOME/dav-next-module.so
    [[ -z $LDAP ]] || cp -af objs/auth_ldap_module.so $HOME/auth-ldap-module.so

    mkdir -p /var/lib/nginx-mid/tmp /var/lib/nginx-mid/root /var/lib/nginx-mid/root/files /var/lib/nginx-mid/root/uploads
    chown -R nginx:nginx /var/lib/nginx-mid/tmp /var/lib/nginx-mid/root

    cat >~/.gdbinit <<EOF
set follow-fork-mode child
EOF

    cat >~/.inputrc <<EOF
set blink-matching-paren on
set colored-completion-prefix on
set colored-stats on
set visible-stats on
set enable-bracketed-paste off
EOF

    echo -n >/etc/nginx/nginx.conf

    [[ -z $LDAP ]] || cat >>/etc/nginx/nginx.conf <<EOF
load_module $HOME/auth-ldap-module.so;
EOF

    cat >>/etc/nginx/nginx.conf <<EOF
load_module $HOME/dav-next-module.so;
EOF

    cat >>/etc/nginx/nginx.conf <<'EOF'
load_module /usr/lib/nginx/modules/ndk_http_module.so;

user nginx;
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;
EOF

    [[ -z $LDAP ]] || cat >>/etc/nginx/nginx.conf <<EOF

    ldap_server dav-next {
        url "$LDAP_URL/ou=users,dc=$LDAP_DOMAIN?uid?one?(objectClass=*)";
        search_attributes gid;
        binddn "uid=nobody,dc=$LDAP_DOMAIN";
        binddn_passwd "$LDAP_NOBODY_SECRET";
    }

EOF

    [[ -z $LDAP ]] || echo '    auth_ldap_resolver ' $(grep -Eom1 '\d+\.\d+\.\d+\.\d+' /etc/resolv.conf) ';' >>/etc/nginx/nginx.conf

    cat >>/etc/nginx/nginx.conf <<'EOF'
    sendfile on;
    keepalive_timeout 65;
    dav_next_server_zone zone=foo:10M;
    client_max_body_size 0;

    server {
        error_log logs/error.log debug;

        set $body "";
        set $headers "";

        listen 80;
        server_name localhost;

        root /var/lib/nginx-mid/root/;

        dav_next_server zone=foo;

EOF

    if [[ -n $LDAP ]]; then
	cat >>/etc/nginx/nginx.conf <<'EOF'
        auth_ldap "dav-next";
        auth_ldap_servers dav-next;
EOF
    else
	cat >>/etc/nginx/nginx.conf <<'EOF'
        auth_basic "dav-next";
        auth_basic_user_file htpasswd;
EOF

	# fake:pOuetpOuet
	# mid:pOuetpOuet
	cat >/etc/nginx/htpasswd <<'EOF'
fake:$apr1$Lf22ugz8$F3KLosVWZTPAT8S72CpQU0
mid:$apr1$Lf22ugz8$F3KLosVWZTPAT8S72CpQU0
EOF
    fi

    cat >>/etc/nginx/nginx.conf <<'EOF'
        satisfy any;

        access_log /dev/stdout;
        error_log /dev/sterr;
    }
}
EOF

fi

nginx-debug -V
nginx-debug -t

echo -e "\n → killall nginx-debug; sleep 1; nginx-debug && cd /var/lib/nginx/logs/ && tail -f *.log"

echo -e "\n  \\o/\n"
