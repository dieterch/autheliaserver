#!/usr/bin/env bash

# Usage: ./generate_userhash.sh PASSWORD

if [ -z "$1" ]; then
  echo "Usage: $0 PASSWORD"
  exit 1
fi

PASSWORD="$1"

docker run --rm authelia/authelia:latest \
  authelia crypto hash generate argon2 --password "$PASSWORD"
