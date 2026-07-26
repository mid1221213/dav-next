#!/usr/bin/bash
#

set -euo pipefail

FLAG=$1
FILE="$2"
CLOUD=$3
[[ $FLAG == "-f" ]] && shift 2 || CLOUD=$1
USER=$2
PASS=$3
S=${4:-}

[[ -z $CLOUD || -z $USER || -z $PASS ]] && echo "Missing CLOUD, USER and PASS (and optionally a final 's' for 'https')" && exit 1

# cool catch() function borrowed from `https://stackoverflow.com/a/59592881/2588750` on 2024-04-30
# usage: `catch STDOUT_VARIABLE STDERR_VARIABLE COMMAND [ARG1[ ARG2[ ...[ ARGN]]]]`
catch() {
    {
        IFS=$'\n' read -r -d '' "${1}";
        IFS=$'\n' read -r -d '' "${2}";
        (IFS=$'\n' read -r -d '' _ERRNO_; return ${_ERRNO_});
    } < <((printf '\0%s\0%d\0' "$(((({ shift 2; "${@}"; echo "${?}" 1>&3-; } | tr -d '\0' 1>&4-) 4>&2- 2>&1- | tr -d '\0' 1>&4-) 3>&1- | exit "$(cat)") 4>&1-)" "${?}" 1>&2) 2>&1)
}

# cool json_match() function produced by Mistral on 2026-07-16
# compares 2 quoted JSON strings and tell if first (`json`) matches the second (`pattern`)
json_match() {
    local json="$1"
    local pattern="$2"

    [[ $(jq -n --argjson actual "$json" --argjson expected "$pattern" '
    def match($p; $a):
        if $p | type == "object" then
            if $a | type != "object" then false
            else [
                (
                    $p | to_entries[] |
                    .key as $pkey |
                    .value as $pval |
                    [
                        $a | to_entries[] |
                        select(.key | test($pkey)) |
                        .value as $aval |
                        match($pval; $aval)
                    ] | any
                ) ] | all
            end
        elif $p | type == "array" then
            if $a | type != "array" then false
            elif ($p | length) != ($a | length) then false
            else
                foreach range(0; $p | length) as $i (
                    true;
                    . and match($p[$i]; $a[$i])
                )
            end
        elif $p | type == "string" then
            $a | tostring | test($p)
        else
            $p == $a
        end;

    match($expected; $actual)
    ') == true ]]
}

LOCAL=$0
REMOTE=`basename $0`
CURL_ARGS="-sfw%{stderr}%{response_code}"

check-results() {
    OUT="$1"
    ERR="$2"
    RET_OK="$3"
    RET_NOK="$4"
    FAIL="$5"

    echo -n "→ $ERR: "

    if [[ -z $FAIL ]]; then
        echo -n "OK"

        if [[ -n $RET_OK ]]; then
            if [[ $ERR == $RET_OK ]]; then
                echo
                return 0
            fi

            echo ", but was expecting $RET_OK, then NOK!"
            exit 1
        fi

        echo " but wasn't expected? then NOK!"
        exit 1
    fi

    echo -n "NOK"

    if [[ -n $RET_NOK ]]; then
        if [[ $ERR == $RET_NOK ]]; then
            echo ", but that was expected, so OK"
            return 0
        fi
        echo " (and didn't get expected $RET_NOK)"
        exit 1
    fi

    echo "!"
    exit 1;
}

check-output() {
    OUT="$1"
    RESP_TYPE="$2"
    RESP_BODY="$3"

    case $RESP_TYPE in
        application/json)
            json_match "$OUT" "$RESP_BODY" || { echo -e "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n$OUT !~ $RESP_BODY" && exit 1; }
            ;;
        application/xml)
            OUTJ="$(tr \"\\n\" ' ' <<<\"$OUT\" | xq -j)"
            json_match "$OUTJ" "$RESP_BODY" || { echo -e "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n$OUTJ !~ $RESP_BODY" && exit 1; }
            ;;
        *)
            ;;
    esac
}

_try() {
    METH="$1"
    RET_OK="$2"
    RET_NOK="$3"
    URL="http$S://$CLOUD$4"
    REQ_TYPE="$5"
    AUTH="$6"
    [[ -z "$AUTH" ]] || URL="http$S://$USER:$PASS@$CLOUD$4"
    REQ_DEPTH="$7"
    REQ_DEST="$8"
    REQ_BODY="$9"
    RESP_TYPE="$10"
    RESP_BODY="$11"

    echo -n "$METH $URL "

    FAIL=
    case $METH in
        PUT)
            catch OUT ERR curl $CURL_ARGS -T "$LOCAL" -H "Expect:" "$URL" || FAIL=y
            ;;
        HEAD)
            catch OUT ERR curl $CURL_ARGS -I "$URL" || FAIL=y
            ;;
        COPY|MOVE)
            catch OUT ERR curl $CURL_ARGS -X "$METH" -H "Destination: $DEST" "$URL" || FAIL=y
            ;;
        PROPFIND)
            catch OUT ERR curl $CURL_ARGS -X $METH -H "Content-Type: $REQ_TYPE" -H "Depth: $REQ_DEPTH" -d "$REQ_BODY" "$URL" || FAIL=y
            ;;
        *)
            catch OUT ERR curl $CURL_ARGS -X $METH "$URL" || FAIL=y
            ;;
    esac

    check-results "$OUT" "$ERR" "$RET_OK" "$RET_NOK" "$FAIL"
    check-output "$OUT" "$RESP_TYPE" "$RESP_BODY"
}

try() {
    METH="$1"
    RET_OK="$2"
    RET_NOK="$3"
    URL="$4"
    DEST="${5:-}"
    echo -n "$METH $URL "
    [[ -n $DEST ]] && echo -n "to $DEST "

    FAIL=
    case $METH in
        PUT)
            catch OUT ERR curl $CURL_ARGS -T "$LOCAL" -H "Expect:" "$URL" || FAIL=y
            ;;
        HEAD)
            catch OUT ERR curl $CURL_ARGS -I "$URL" || FAIL=y
            ;;
        COPY|MOVE)
            catch OUT ERR curl $CURL_ARGS -X "$METH" -H "Destination: $DEST" "$URL" || FAIL=y
            ;;
        *)
            catch OUT ERR curl $CURL_ARGS -X "$METH" "$URL" || FAIL=y
            ;;
    esac

    check-results "$OUT" "$ERR" "$RET_OK" "$RET_NOK" "$FAIL"
}

[[ $FLAG == "-f" ]] && source "$FILE"

DAVROOT="/$USER"
WEBDAV="/remote.php/webdav/$USER"
NC_FILES="/remote.php/dav/files/$USER/$USER"

for DAV in "$DAVROOT" "$WEBDAV" "$NC_FILES"; do
    LUNAE="http$S://$USER:$PASS@$CLOUD$DAV"
    NOCREDS="http$S://$CLOUD$DAV"

    echo -e "\nTESTING \"$DAV\""

    try DELETE 204 404 "$LUNAE/test/"

    try PROPFIND 207 "" "$LUNAE/"
    try DELETE "" 403 "$LUNAE"

    try MKCOL 201 "" "$LUNAE/test/"
    try PROPFIND 207 "" "$LUNAE/test/"
    try PUT 201 "" "$LUNAE/test/$REMOTE"
    try HEAD 200 "" "$LUNAE/test/$REMOTE"
    try PROPFIND 207 "" "$LUNAE/test/$REMOTE"
    try COPY 201 "" "$LUNAE/test/$REMOTE" "$NOCREDS/test/$REMOTE.copy"
    try MOVE 201 "" "$LUNAE/test/$REMOTE" "$NOCREDS/test/$REMOTE.move"
    try DELETE "" 404 "$LUNAE/test/$REMOTE"
    try DELETE 204 "" "$LUNAE/test/$REMOTE.move"
    try DELETE 204 "" "$LUNAE/test/$REMOTE.copy"
    try DELETE 204 "" "$LUNAE/test/"

    echo ALL "$DAV" TESTS PASSED.
done

echo
echo "TESTING parallel uploads"

NC_UPLOADS="http$S://$USER:$PASS@$CLOUD/remote.php/dav/uploads/$USER"
NC_FILES="http$S://$USER:$PASS@$CLOUD/remote.php/dav/files/$USER/$USER"
NOCREDS="http$S://$CLOUD/remote.php/dav/files/$USER/$USER"
try DELETE 204 404 "$NC_UPLOADS/uptest/"
try DELETE 204 404 "$NC_FILES/uptest-ok"
try MKCOL 201 "" "$NC_UPLOADS/uptest/"
echo -n "PUT $NC_UPLOADS/uptest/[0000001-0000100]: "
curl -ZT "$LOCAL" $NC_UPLOADS/uptest/[0000001-0000099] >& /dev/null || { echo "KO"; exit 1; }
curl -T "$LOCAL" $NC_UPLOADS/uptest/0000100 >& /dev/null && echo "OK" || { echo "KO"; exit 1; }
try MOVE 201 "" "$NC_UPLOADS/uptest/.file" "$NOCREDS/uptest-ok"
try PROPFIND 207 "" "$NC_FILES/uptest-ok"
try DELETE 204 "" "$NC_FILES/uptest-ok"

echo "parallel uploads OK"

echo
echo ALL TESTS PASSED.
