#!/bin/sh
set -eu
cert=$1
upstream=$2
socat "OPENSSL-LISTEN:443,bind=0.0.0.0,reuseaddr,fork,cert=/certs/$cert.pem,key=/certs/$cert.key,verify=0" "TCP:$upstream" &
server=$!
trap 'kill $server 2>/dev/null || true; exit 0' TERM INT
while :; do
  sleep 1 &
  wait $!
done
