#!/bin/sh
set -e

CONNECT="${CONNECT_ADDR:?CONNECT_ADDR is required}"
PROXY_ID="${PROXY_ID:-}"
BOOTSTRAP_SECRET="${TURN_BOOTSTRAP_SECRET:-}"
BOOTSTRAP_PUBLIC_KEY="${TURN_BOOTSTRAP_PUBLIC_KEY:-}"

TCP_FLAG=""
if [ "${TCP_MODE}" = "true" ]; then
    TCP_FLAG="-tcp"
fi

set -- ./vk-turn-proxy -listen 0.0.0.0:56000 -connect "$CONNECT"
if [ -n "$TCP_FLAG" ]; then
    set -- "$@" "$TCP_FLAG"
fi
if [ -n "$PROXY_ID" ]; then
    set -- "$@" -proxy-id "$PROXY_ID"
fi
if [ -n "$BOOTSTRAP_SECRET" ]; then
    set -- "$@" -bootstrap-secret "$BOOTSTRAP_SECRET"
fi
if [ -n "$BOOTSTRAP_PUBLIC_KEY" ]; then
    set -- "$@" -bootstrap-public-key "$BOOTSTRAP_PUBLIC_KEY"
fi

exec "$@"
