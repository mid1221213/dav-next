#! /usr/bin/bash

set -euo pipefail

LOG=${1:-proxy_full.log}
[[ ! -f $LOG ]] && echo "[$LOG] not found" && exit 1

NL=$(wc -l <$LOG)

awk -e '
BEGIN { print "[" }
FNR != '$NL' { print $0 "," }
FNR == '$NL' { print $0 }
END { print "]" }
' $LOG | tee $LOG.json | jq >$LOG.pretty.json

function warn {
    echo -e "$*" >&2
}

function die {
    echo -e "$*" >&2
    exit 1
}

function cry {
    local text
    text=$1; shift
    die "${BASH_SOURCE[1]}:${FUNCNAME[1]:-main}:${BASH_LINENO[0]}: $text\n$@"
}

function header {
    local header
    header="$1"
    shift
    jq -r 'to_entries | .[] | select(.key | ascii_downcase == "'$header'") | .value | select(. != null)' <<<"$@" | sed -e 's/;.*//'
}

function jiquote {
    jq --indent 4 <<<"$1" | sed -e "s/'/'\\\''/g"
}

function xijiquote {
    jiquote "$(tr \"\\n\" ' ' <<<\"$1\" | xq -j)"
}

function xiquote {
    xq --indent 4 <<<"$1" | tr \' \"
}

function jpatch {
    sed -r "s|$1|$1|gi" <<<"$2"
}

SEEN=
function seen {
    local line="$1"

    local sum
    sum=$(md5sum <<<"$line" | cut -c-32)

    echo -e "$SEEN" | grep -qE "^$sum$"
    local ret=$?

    echo "$sum\n"

    return $ret
}

function write-testline {
    local method uri ret ret_ok ret_nok req_headers req_type req_auth req_depth req_dest req_body resp_headers resp_type resp_body
    method=$1
    uri="$2"
    ret=$3
    ret_ok=
    ret_nok=
    [[ $ret -ge 400 ]] && ret_nok=$ret || ret_ok=$ret
    req_headers="$4"
    req_type=$(header content-type "$req_headers")
    req_auth=$(header authorization "$req_headers")
    req_auth=${req_auth:+AUTH}
    req_depth=$(header depth "$req_headers")
    req_dest=$(header destination "$req_headers")
    req_body="$5"
    resp_headers="$6"
    resp_type=$(header content-type "$resp_headers")
    resp_body="$7"

    case $ret in
        400|500)
            cry "something failed ($ret)!" "$@"
            ;;
        401)
            [[ -n $(header www-authenticate "$resp_headers") ]] || cry "401 without asking auth" "$@"
            ;;
    esac

    [[ $req_type != text/xml ]] || req_body=$(xiquote "$req_body")

    case $resp_type in
        text/html)
            [[ -n $ret_nok ]] || cry "HTML returned without fail ($ret)?" "$@"
            [[ $ret_nok -le 400 || $ret_nok -ge 500 ]] || resp_body=.*
            ;;
        application/json)
            resp_body=$(jiquote "$resp_body")
            ;;
        application/xml|text/xml)
            [[ -n $ret_ok ]] || cry "XML returned with fail ($ret)?" "$@"
            case $ret in
                200)
                    ;;
                207)
                    local mstatus
                    xq -x //D:status <x.xml | cut -d' ' -f2 | sort -u | while read mstatus; do
                        [[ $mstatus -lt 400 ]] || cry "XML MULTI returned with fail ($mstatus)?" "$@"
                    done
                    ;;
                *)
                    cry "XML returned with unexpected status ($ret)?" "$@"
                    ;;
            esac
            resp_body=$(xijiquote "$resp_body")
            ;;
        *)
            ;;
    esac

    for pattern in \
        '"getlastmodified": ".* GMT"' \
        '"id": "[0-9a-f]{24}"' \
        '"getetag": "[0-9a-f]{16}"' \
        '"permissions": "[GMSWCKDNV]*"'\
        '"quota-available-bytes": "[0-9]+"' \
        '"quota-used-bytes": "[0-9]+"' \
        ; do

        resp_body=$(jpatch "$pattern" "$resp_body")
    done

    local out="_try $method '$ret_ok' '$ret_nok' '$uri' '$req_type' '$req_auth' '$req_depth' '$req_dest' '$req_body' '$resp_type' '$resp_body'"
    SEEN+=$(seen "$out") || echo "$out"
}

while read -r line; do
    req=$(jq -r .request <<<$line)
    read method uri < <(cut -d" " -f1,2 <<<$req)

    status=$(jq -r .status <<<$line)

    req_headers=$(jq -r .req_headers <<<$line)
    req_body=$(jq -r .req_body <<<$line)

    resp_headers=$(jq -r .resp_headers <<<$line)
    resp_body=$(jq -r .resp_body <<<$line)

    write-testline $method $uri $status "$req_headers" "$req_body" "$resp_headers" "$resp_body"
done <$LOG
