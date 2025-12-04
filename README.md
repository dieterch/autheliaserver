## Authelia Docker Authentification setup for traefik 3.6.2

- config/configuration.yam an domain anpassen
- config/users.yml anlegen

```yaml
users:
  admin:
    password: hash
    displayname: "Admin"
    email: "name@example.com"
    groups:
      - admins
...
````

use create_authelia_user.sh
and / or generate_userhash.sh

- .env kopieren/anlegen mit

```
AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET=64 bit secret
AUTHELIA_SESSION_SECRET=32 bit secret
AUTHELIA_STORAGE_ENCRYPTION_KEY=32 bit secret
AUTHELIA_NOTIFIER_SMTP_USERNAME=name@example.com
AUTHELIA_NOTIFIER_SMTP_PASSWORD=Google APP password für smtp
````

use generate_secrets.sh

start with:
```
docker compose up -d
docker logs -f authelia
```

in traefik/dynamic.yml:
```yaml
http:
  middlewares:

    ###############################################
    # Authelia ForwardAuth
    ###############################################
    authelia:
      forwardAuth:
        address: http://authelia:9091/api/verify?rd=https://authelia.home.smallfamilybusiness.net/
        trustForwardHeader: true
        authResponseHeaders:
          - Remote-User
          - Remote-Groups
          - Remote-Name
          - Remote-Email
```

in compose.yml:
```yaml
    labels:
...
      # Alternative ForwardAuth middleware pointing to Authelia
      - "traefik.http.routers._routername_.middlewares=authelia@file"
...
```
Documentation
https://www.authelia.com/


useradmin:
addon to allow easy usermanagement & invitations

add the folloing Environment variables to your .env file

# Base url (used for invite links)
BASE_URL=...

# SMTP (optional) - set these on your server if you want invite mails
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=hugo.master@example.com
SMTP_PASS=xxxxxx
SMTP_FROM="Authelia <hugo.master@example.com"

# Optional: override config dir in container (defaults to /config)
# CONFIG_DIR=/config

change the Authelia configuration access policy, e.g:

    - domain: authelia.home.smallfamilybusiness.net
      resources:
        - "^/admin/invite.*"
      policy: bypass

    - domain: authelia.home.smallfamilybusiness.net
      resources:
        - "^/admin/api/invite.*"
      policy: bypass

    - domain: authelia.home.smallfamilybusiness.net
      resources:
        - "^/admin.*"
      policy: deny
      subject:
        - "group:users"