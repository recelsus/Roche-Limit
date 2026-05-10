# Roche-Limit

## Description

A dedicated authorisation server for reverse proxy auth subrequests, including nginx `auth_request`.

Roche-Limit keeps access decisions outside the application backend. A reverse proxy calls Roche-Limit first, and the backend is reached only when the returned decision allows it.

## Features

- IP allow / deny rules
- IP and API key access levels
- Cookie session authorisation for browser flows
- Service-specific access level overrides
- Request hardening for auth, login, logout, and session auth endpoints
- In-memory containment, emergency denylist, audit logs, and Prometheus metrics
- SQLite storage and CLI management

## Endpoints

- `/auth`
  IP / API key authorisation for proxy subrequests.
- `/session/auth`
  Cookie session authorisation for proxy subrequests.
- `/login`
  Login page and credential submit.
- `/logout`
  Session logout.
- `/metrics`
  Prometheus text metrics.

Keep Roche-Limit behind a reverse proxy. Do not expose auth endpoints or `/metrics` directly to the public internet.

## Minimal Configuration

Set a strong API key pepper before starting the server:

```env
ROCHE_LIMIT_API_KEY_PEPPER=change-me-long-random-secret
```

For public deployments, also set peer restrictions:

```env
ROCHE_LIMIT_DEPLOYMENT_MODE=public
ROCHE_LIMIT_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_ALLOWED_PEERS=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_METRICS_MODE=internal
```

See [`docs/configuration.md`](./docs/configuration.md) for deployment modes, endpoint limits, session cookies, containment, metrics, and headers.

## CLI

Use `roche_limit_cli` to manage IP rules, API keys, users, sessions, and audit cleanup.

```text
roche_limit_cli ip list
roche_limit_cli key gen --service primary --level 60
roche_limit_cli user list
roche_limit_cli audit cleanup --retention-days 90 --max-rows 10000
```

High-impact commands such as key rotation, key disable/remove, session revoke, password changes, and user remove require `--force`. Use `--dry-run` first to preview the target.

See [`docs/cli.md`](./docs/cli.md) for all commands.

## Docker

Minimal `docker-compose.yml` example:

```yaml
services:
  roche-limit:
    image: ghcr.io/recelsus/roche-limit:latest
    container_name: roche-limit
    restart: unless-stopped
    environment:
      ROCHE_LIMIT_API_KEY_PEPPER: "change-me-long-random-secret"
    networks:
      - nginx
    volumes:
      - ./data:/var/lib/roche-limit

networks:
  nginx:
    external: true
```

Example `docker run` command:

```bash
docker run -d \
  --name roche-limit \
  --restart unless-stopped \
  --network nginx \
  -e ROCHE_LIMIT_API_KEY_PEPPER='change-me-long-random-secret' \
  -v "$(pwd)/data:/var/lib/roche-limit" \
  ghcr.io/recelsus/roche-limit:latest
```

## Reverse Proxy

Start with the nginx examples in [`docs/nginx-sample.md`](./docs/nginx-sample.md).

For the proxy-neutral response contract, status mapping, and headers, see [`docs/reverse-proxy-contract.md`](./docs/reverse-proxy-contract.md).

## Documentation

- [`docs/configuration.md`](./docs/configuration.md)
  Runtime configuration, auth contract, session cookie settings, containment, and metrics.
- [`docs/cli.md`](./docs/cli.md)
  CLI commands and high-impact operation handling.
- [`docs/nginx-sample.md`](./docs/nginx-sample.md)
  nginx `auth_request` examples.
- [`docs/reverse-proxy-contract.md`](./docs/reverse-proxy-contract.md)
  Reverse proxy contract notes.
- [`docs/migration.md`](./docs/migration.md)
  Database migration policy.

## Database

New databases are created from [`schema/init.sql`](./schema/init.sql). Existing databases are upgraded through migrations in [`schema/migrations`](./schema/migrations).

## Licence

Roche-Limit is licensed under the MIT License. See [`LICENSE`](./LICENSE).

Third-party dependency notices are listed in [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).
