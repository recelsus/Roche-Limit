# Roche-Limit Configuration

Runtime configuration and auth contract notes.

## Deployment Mode

- `ROCHE_LIMIT_DEPLOYMENT_MODE`
  - `internal`
  - `public`
  - `hardened`
  - default: `internal`

`public` and `hardened` reject weak secrets and unsafe defaults at startup.

`public` requires at least one of:

- `ROCHE_LIMIT_ALLOWED_PEERS`
- `ROCHE_LIMIT_TRUSTED_PROXIES`

`hardened` requires both:

- `ROCHE_LIMIT_ALLOWED_PEERS`
- `ROCHE_LIMIT_TRUSTED_PROXIES`

## Required Secret

- `ROCHE_LIMIT_API_KEY_PEPPER`
  Required for API key creation and verification.
- `ROCHE_LIMIT_SESSION_TOKEN_PEPPER`
  Used for session token hashing. Defaults to `ROCHE_LIMIT_API_KEY_PEPPER` when unset.

Use long random values in public and hardened deployments.

## Access Level Defaults

- `ROCHE_LIMIT_UNKNOWN_IP_LEVEL`
  - default: `10` in `internal`
  - default: `0` in `public` / `hardened`
  - `public`: explicit value must be `<= 10`
  - `hardened`: explicit value must be `0`
- `ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL`
  - default: `10` in `internal`
  - default: `0` in `public` / `hardened`
  - `public`: explicit value must be `<= 10`
  - `hardened`: explicit value must be `0`
- `ROCHE_LIMIT_DEFAULT_API_KEY_LEVEL`
  Default level for `key add` / `key gen` when `--level` is omitted. Default: `10`.

Access levels use:

- `0`
  blocked
- `1..99`
  allowed levels
- recommended values
  `10`, `30`, `60`, `90`

## Proxy Trust

- `ROCHE_LIMIT_TRUSTED_PROXIES`
  Peers whose `X-Real-IP` / `X-Forwarded-For` headers are trusted.
- `ROCHE_LIMIT_ALLOWED_PEERS`
  Peers allowed to call `/auth` and `/session/auth`.

When `ROCHE_LIMIT_ALLOWED_PEERS` is unset, Roche-Limit reuses `ROCHE_LIMIT_TRUSTED_PROXIES`.
When both are unset, auth endpoints are open to any peer. This is intended only for internal/dev use.

Example:

```env
ROCHE_LIMIT_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_ALLOWED_PEERS=127.0.0.1,::1,172.18.0.0/16
```

## Auth Request Headers

`/auth` and `/session/auth` expect:

- `X-Target-Service`
  required
- `X-Required-Level`
  required, integer `0..99`
- `Authorization: Bearer <token>`
  optional API key
- `X-API-Key`
  optional API key
- `X-Real-IP`
  optional client IP header from trusted proxy
- `X-Forwarded-For`
  optional client IP chain from trusted proxy

Validation:

- `X-Target-Service`
  - 1-128 characters
  - letters, digits, `_`, `-`, `.`, `:`, `/`
  - rejects `..`
  - rejects leading or trailing `/`
- single-value auth headers reject comma-joined values
- conflicting `X-Real-IP` and `X-Forwarded-For` client IPs are rejected
- `public` / `hardened` reject malformed `X-Forwarded-For` chains
- `hardened` rejects using both `Authorization` and `X-API-Key`

## Auth Response Headers

Auth endpoints return:

- `X-Request-Id`
  Request correlation id.
- `X-Auth-Level`
  Granted numeric access level. Deny/error paths use `0`.
- `X-Auth-Reason`
  Machine-readable reason.
- `X-Auth-Service`
  Evaluated service. Missing service uses `*`.

Optional:

- `X-Auth-IP-Rule-Id`
- `X-Auth-Key-Id`
- `X-Auth-User-Id`
- `X-Auth-Session-Id`
- `Retry-After`

See [`reverse-proxy-contract.md`](./reverse-proxy-contract.md) for status and proxy mapping notes.

## Endpoint Hardening

- `ROCHE_LIMIT_AUTH_RATE_LIMIT_ENABLED`
  Default: `1`.
- `ROCHE_LIMIT_AUTH_RATE_LIMIT_WINDOW_SECONDS`
  Default: `60`.
- `ROCHE_LIMIT_AUTH_RATE_LIMIT_PER_WINDOW`
  `/auth` requests per window. Default: `600`.
- `ROCHE_LIMIT_SESSION_AUTH_RATE_LIMIT_PER_WINDOW`
  `/session/auth` requests per window. Default: `600`.
- `ROCHE_LIMIT_LOGIN_RATE_LIMIT_PER_WINDOW`
  `/login` request-hardening limit. Default: `120`.
- `ROCHE_LIMIT_LOGOUT_RATE_LIMIT_PER_WINDOW`
  `/logout` request-hardening limit. Default: `120`.
- `ROCHE_LIMIT_AUTH_MAX_HEADER_BYTES`
  Default: `8192`.
- `ROCHE_LIMIT_AUTH_MAX_QUERY_BYTES`
  Default: `1024`.
- `ROCHE_LIMIT_AUTH_MAX_BODY_BYTES`
  Default: `0`.
- `ROCHE_LIMIT_LOGIN_MAX_BODY_BYTES`
  Default: `16384`.
- `ROCHE_LIMIT_LOGOUT_MAX_BODY_BYTES`
  Default: `4096`.

## Sessions

Cookie defaults:

- name: `roche_limit_session`
- path: `/`
- `HttpOnly`
- `Secure`
- `SameSite=Lax`
- `Max-Age=604800`

Environment variables:

- `ROCHE_LIMIT_SESSION_COOKIE_NAME`
- `ROCHE_LIMIT_SESSION_COOKIE_PATH`
- `ROCHE_LIMIT_SESSION_COOKIE_DOMAIN`
- `ROCHE_LIMIT_SESSION_COOKIE_SAMESITE`
- `ROCHE_LIMIT_SESSION_COOKIE_SECURE`
- `ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY`
- `ROCHE_LIMIT_SESSION_COOKIE_MAX_AGE`
- `ROCHE_LIMIT_SESSION_IDLE_TIMEOUT_SECONDS`
  Default: `3600`.
- `ROCHE_LIMIT_SESSION_ABSOLUTE_TIMEOUT_SECONDS`
  Default: `604800`.
- `ROCHE_LIMIT_SESSION_ROTATION_INTERVAL_SECONDS`
  Default: `86400`.

Startup validation:

- cookie name, domain, and path must not contain control characters
- `SameSite=None` requires `Secure`
- `__Host-` requires `Secure`, `Path=/`, and no `Domain`
- `__Secure-` requires `Secure`
- `public` / `hardened` require secure cookie defaults

## Containment

- `ROCHE_LIMIT_CONTAINMENT_ENABLED`
  Default: `1`.
- `ROCHE_LIMIT_CONTAINMENT_WINDOW_SECONDS`
  Default: `60`.
- `ROCHE_LIMIT_CONTAINMENT_DENY_THRESHOLD`
  Deny/error count that triggers quarantine. Default: `20`.
- `ROCHE_LIMIT_CONTAINMENT_QUARANTINE_SECONDS`
  Default: `300`.
- `ROCHE_LIMIT_CONTAINMENT_LOCKDOWN_DENY_THRESHOLD`
  Process-wide deny/error count that triggers lockdown. Default: `0`, disabled.
- `ROCHE_LIMIT_CONTAINMENT_LOCKDOWN_SECONDS`
  Default: `300`.

Manual denylist:

- `ROCHE_LIMIT_CONTAINMENT_DENYLIST_IPS`
- `ROCHE_LIMIT_CONTAINMENT_DENYLIST_API_KEY_IDS`
- `ROCHE_LIMIT_CONTAINMENT_DENYLIST_SESSION_IDS`
- `ROCHE_LIMIT_CONTAINMENT_DENYLIST_USER_IDS`

Containment subjects:

- `ip`
- `api_key`
- `session`
- `user`

Signal kinds:

- `header_abuse`
- `credential_abuse`
- `session_anomaly`
- `authorization_denied`
- `internal_error`

## Metrics

- `ROCHE_LIMIT_METRICS_MODE`
  - `enabled`
  - `internal`
  - `disabled`
  - default: `enabled`
- `ROCHE_LIMIT_METRICS_ALLOW_PUBLIC`
  Required only when `public` uses `ROCHE_LIMIT_METRICS_MODE=enabled`.

`hardened` cannot use `ROCHE_LIMIT_METRICS_MODE=enabled`.

Prometheus metrics include:

- `roche_limit_auth_requests_total`
- `roche_limit_request_ids_issued_total`
- containment active counts by subject
- containment signals by subject and signal kind

## Audit

- `ROCHE_LIMIT_AUDIT_AUTH_ALLOW`
  When `1`, `/auth` and `/session/auth` allow events are audited.
- `ROCHE_LIMIT_AUDIT_RETENTION_DAYS`
  Cleanup retention hint.
- `ROCHE_LIMIT_AUDIT_MAX_ROWS`
  Cleanup row cap hint. Small-deployment default: `10000`.

Audit logs include CLI management operations and cleanup. CLI metadata redacts plain API keys and passwords.
