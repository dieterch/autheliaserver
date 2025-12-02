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