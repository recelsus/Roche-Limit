# Roche-Limit

## Description

A dedicated authorisation server designed around nginx `auth_request`.

- IP address allow / deny rules
- IP-based access level control
- API key based access level control
- API key usage stats, rotation, and expiry disable
- Service-specific access level control
- CLI-based inspection and updates

## Features

- `Drogon`-based C++20 server
- `SQLite` storage for IP rules and API keys
- Access decisions and access levels returned through `/auth`
- CLI management operations

## HTTP Endpoints

- `/`
  Basic reachability check
- `/auth`
  IP / API key authorisation. `GET` only.
- `/login`
  Login page and login submit. `GET` renders the page, `POST` submits credentials.
- `/logout`
  Logout endpoint. `POST` only.
- `/session/auth`
  Cookie session authorisation. `GET` only.
- `/metrics`
  Prometheus text metrics. `GET` only.

These endpoints are intended to be used behind nginx.
Keep `/metrics` on an internal network or protect it at nginx.

`/login` now applies per-IP + username rate limiting and temporary lockout.  
`/login` and `/logout` both verify CSRF tokens. `GET /login` issues the token, and `/logout` expects the CSRF cookie plus either `X-CSRF-Token` or `csrf_token`.

## Observability

Auth-related responses include `X-Request-Id` so nginx logs and Roche-Limit logs can be correlated.

Audit logs now carry a hash chain. `metadata_json` is stored in a standardised JSON shape, and CLI management operations plus cleanup are audited as well.

`/metrics` exposes Prometheus-style counters:

- `roche_limit_auth_requests_total`
  Counted by `endpoint`, `result`, and `reason`
- `roche_limit_request_ids_issued_total`
  Number of request ids issued by the running process

## Rules

Access levels assume `0` for blocked and `1-99` for allowed levels.  
Recommended values are `0`, `10`, `30`, `60`, and `90`.  
Unknown IPs default to `10`.

- Shared `IP deny` rules reject first
- Shared `IP allow` rules grant `60`
- Unregistered IP addresses receive `10` by default
- Service-specific overrides are applied when present
- API keys may raise the access level
- The final access level is returned to nginx

## Configuration

- `ROCHE_LIMIT_API_KEY_PEPPER`
  Required at startup and used for API key creation and verification. Set a long random value.
- `ROCHE_LIMIT_UNKNOWN_IP_LEVEL`
  Default access level for unknown IPs. Defaults to `10`.
- `ROCHE_LIMIT_AUDIT_AUTH_ALLOW`
  When set to `1`, `/auth` and `/session/auth` allow events are also written to the audit log. By default only deny, error, login, and logout style events are recorded.
- `ROCHE_LIMIT_AUDIT_RETENTION_DAYS`
  Intended audit retention window. When unset, retention depends on the cleanup policy you run.
- `ROCHE_LIMIT_AUDIT_MAX_ROWS`
  Intended audit row cap. The small-deployment baseline is `10000`.

## Required Headers

`/auth` mainly expects the following headers.

- `X-Target-Service`
  Required
- `X-Required-Level`
  Required
- `Authorization: Bearer <token>`
  Optional
- `X-API-Key`
  Optional
- `X-Real-IP`
  Optional
- `X-Forwarded-For`
  Optional

`X-Target-Service` and `X-Required-Level` are required.  
For API keys, `Bearer` is checked first, then `X-API-Key`.
If `X-Required-Level` cannot be parsed, `/auth` returns `403`.

For API keys, `service` acts as the scope.  
Resolution is `service match -> *`.

API keys also track:

- `last_used_at`
- `last_used_ip`
- `last_failed_at`
- `failed_attempts`

Expiring API keys are auto-disabled during lookup/list operations.  
The CLI provides `key rotate` to issue a replacement key and disable the old one.

`X-Real-IP` and `X-Forwarded-For` are trusted only when the direct peer matches `ROCHE_LIMIT_TRUSTED_PROXIES`. If it is not set, forwarded headers are ignored and the peer IP is used.
`/auth` and `/session/auth` are allowed only from peers matching `ROCHE_LIMIT_ALLOWED_PEERS`. When it is unset, Roche-Limit reuses `ROCHE_LIMIT_TRUSTED_PROXIES`. Only when both are unset are auth endpoints open to any peer.

Example:

```env
ROCHE_LIMIT_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_ALLOWED_PEERS=127.0.0.1,::1,172.18.0.0/16
```

Cookie sessions use `roche_limit_session` with `Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800` by default.

Session cookie settings can be overridden with environment variables:

- `ROCHE_LIMIT_SESSION_COOKIE_NAME`
  Default: `roche_limit_session`
- `ROCHE_LIMIT_SESSION_COOKIE_PATH`
  Default: `/`
- `ROCHE_LIMIT_SESSION_COOKIE_DOMAIN`
  Default: unset
- `ROCHE_LIMIT_SESSION_COOKIE_SAMESITE`
  Default: `Lax`; supported values: `Lax`, `Strict`, `None`
- `ROCHE_LIMIT_SESSION_COOKIE_SECURE`
  Default: `1`
- `ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY`
  Default: `1`
- `ROCHE_LIMIT_SESSION_COOKIE_MAX_AGE`
  Default: `604800`
- `ROCHE_LIMIT_SESSION_TOKEN_PEPPER`
  When unset, Roche-Limit reuses `ROCHE_LIMIT_API_KEY_PEPPER`
- `ROCHE_LIMIT_SESSION_IDLE_TIMEOUT_SECONDS`
  Default: `3600`
- `ROCHE_LIMIT_SESSION_ABSOLUTE_TIMEOUT_SECONDS`
  Default: `604800`
- `ROCHE_LIMIT_SESSION_ROTATION_INTERVAL_SECONDS`
  Default: `86400`

Session cookie settings are validated at startup:

- Cookie name, domain, and path must not contain control characters
- `SameSite=None` forces `Secure`
- `__Host-` cookies require `Secure`, `Path=/`, and no `Domain`
- `__Secure-` cookies require `Secure`

Sessions track idle timeout and absolute timeout separately.  
When the rotation interval is exceeded, the session is denied with `session_rotation_required` and the user must sign in again.

## Response Headers

Auth endpoints may return the following headers:

- `X-Request-Id`
  Per-request correlation id
- `X-Auth-Level`
  Granted numeric access level
- `X-Auth-Reason`
  Machine-readable auth reason
- `X-Auth-Service`
  Target service evaluated by Roche-Limit
- `X-Auth-IP-Rule-Id`
  Matched IP rule id, when an IP rule matched
- `X-Auth-Key-Id`
  Matched API key id, when an API key matched
- `X-Auth-User-Id`
  Matched user id for session auth
- `X-Auth-Session-Id`
  Matched session id for session auth

## CLI

See [`docs/cli.md`](./docs/cli.md) for details.

## DB Migration

New databases are created from [`schema/init.sql`](./schema/init.sql). See [`docs/migration.md`](./docs/migration.md) for the existing database upgrade policy.

## Licence

Roche-Limit is licensed under the MIT License. See [`LICENSE`](./LICENSE).

Third-party dependency notices are listed in [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

## Nginx Config Sample

Minimal example:

```nginx
upstream roche_limit_auth {
    server roche-limit:8080;
}

upstream app_primary {
    server app-primary:8080;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    location / {
        auth_request /__roche_limit_auth;
        proxy_pass http://app_primary;
    }

    location = /__roche_limit_auth {
        internal;
        proxy_pass http://roche_limit_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Target-Service primary;
        proxy_set_header X-Required-Level 30;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-API-Key $http_x_api_key;
    }
}
```

Example requiring access level `90` or higher:

```nginx
location /admin/ {
    auth_request /__roche_limit_auth_90;
    proxy_pass http://app_primary;
}

location = /__roche_limit_auth_90 {
    internal;
    proxy_pass http://roche_limit_auth/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_set_header X-Target-Service primary;
    proxy_set_header X-Required-Level 90;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-API-Key $http_x_api_key;
}
```

In this example:

- requests pass only when `granted level >= 90`
- levels below `90` are rejected by `/auth`
- nginx only needs the `auth_request` result

See [`docs/nginx-sample.md`](./docs/nginx-sample.md) for more detailed examples.

That document also includes:

- per-location required level examples
- a mixed setup where `/` uses IP/API-key auth and `/web/` uses login/session auth
- a `/web/api/` pattern where `karing-web` proxies to `karing` internally
- a subpath example such as `regufa.com/karing/`
