#!/bin/bash

echo "=== Authelia User Generator ==="
echo

# --- Username ---
read -p "Username: " USERNAME
if [ -z "$USERNAME" ]; then
  echo "Username darf nicht leer sein."
  exit 1
fi

# --- Display Name ---
read -p "Display Name: " DISPLAYNAME
[ -z "$DISPLAYNAME" ] && DISPLAYNAME="$USERNAME"

# --- Email ---
read -p "E-Mail: " EMAIL
if [[ ! "$EMAIL" =~ @ ]]; then
  echo "E-Mail sieht ungültig aus."
  exit 1
fi

# --- Password ---
read -s -p "Password: " PASSWORD
echo
read -s -p "Password (repeat): " PASSWORD2
echo

if [ "$PASSWORD" != "$PASSWORD2" ]; then
  echo "Passwörter stimmen nicht überein."
  exit 1
fi

echo
echo "→ hashing password with Authelia…"
echo

RAW_HASH=$(docker run --rm -i authelia/authelia:latest \
  authelia crypto hash generate \
  --password "$PASSWORD" 2>/dev/null)

if [ -z "$RAW_HASH" ]; then
  echo "Fehler: Hash konnte nicht erzeugt werden."
  exit 1
fi

# --- Extract clean hash ---
# Removes “Digest: ” prefix if present
HASH=$(echo "$RAW_HASH" | sed -E 's/^Digest:[[:space:]]*//')

echo "=== Fertiges users.yml Snippet ==="
echo
cat <<EOF
  $USERNAME:
    displayname: "$DISPLAYNAME"
    password: "$HASH"
    email: "$EMAIL"
    groups:
      - users
EOF

echo
echo "Kopiere diesen Block in deine Authelia users.yml."
