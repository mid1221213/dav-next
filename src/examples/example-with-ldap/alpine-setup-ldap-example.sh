#!/bin/bash

set -euo pipefail

killall slapd || true

cp -af /mnt/examples/example-with-ldap/*.{conf,schema} /etc/openldap/

mkdir -p /opt/openldap-data

slapadd -b dc=example.com -v -l /mnt/examples/example-with-ldap/dc=example.com.ldif || true

slaptest -v

ulimit -n 1048576 || true

slapd

echo -e "\n → killall nginx-debug; sleep 1; nginx-debug && cd /var/lib/nginx/logs/ && tail -f *.log"

echo -e "\n  \\o/\n"
