#!/bin/bash

API_SERVER=localhost:8080
COOKIE_JAR=$(mktemp /tmp/cookies.XXXXXX)

cleanup() {
    rm -rf $COOKIE_JAR
}

_curl_rest_raw() {
    curl \
        -v \
        --no-progress-meter \
        -X POST \
        --header 'Content-Type: application/json' \
        "$@"
}


_curl_rest_validate_response() {
    local json=$(_curl_rest_raw "$@") || {
        local status=$?
        echo 1>&2 "curl $* failed: ${status}"
        exit ${status}
    }
    if ! echo "$json" | jq . > /dev/null
    then
        echo 1>&2 "Malformed output from API $*: json=$json"
        return 1
    else
        echo $json
    fi
}

_curl_rest_cookies() {
    _curl_rest_validate_response \
        --cookie "${COOKIE_JAR}" \
        --cookie-jar "${COOKIE_JAR}" \
        "$@"
}

_curl_rest_post() {
    _curl_rest_cookies \
        -X POST \
        --header 'Content-Type: application/json' \
        "$@"
}

_curl_post() {
    local api_path=$1
    local data=${2:-}
    _curl_rest_post --data "$data" http://$API_SERVER/$api_path
}

_curl_rest_cookies() {
    _curl_rest_validate_response \
        --cookie "${COOKIE_JAR}" \
        --cookie-jar "${COOKIE_JAR}" \
        "$@"
}

_curl_rest_get() {
    _curl_rest_cookies \
        -X GET \
        "$@"
}

_curl_get() {
    local api_path=$1
    _curl_rest_get http://$API_SERVER/$api_path
}


_curl_post api/signup "{ \"username\": \"Radcliffe\", \"password\": \"password1234\", \"email\": \"radcliffe@gmail.com\"}"
# _curl_post api/verify "{ \"email\": \"radcliffe@gmail.com\", \"code\": \"037039\"}"
# _curl_post api/login "{ \"email\": \"radcliffe@gmail.com\", \"password\": \"password1234\"}"
# _curl_post api/logout ""
# _curl_get api/verify?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb2RlIjoiODg1NTExIiwiZXhwIjoxNzE4MTI2MzMzLCJpYXQiOjE3MTgwMzk5MzMsInVzZXJuYW1lIjoiU3RldmUifQ.xYJz4KvhmEsHhHNtCHmbzupMniUPfwhm6VaiEq9rbOo

