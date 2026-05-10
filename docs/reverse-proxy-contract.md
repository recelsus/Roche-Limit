# Reverse Proxy Contract

Roche-Limit を nginx 以外の reverse proxy からも扱うための contract notes。

## Scope

- 対象 endpoint
  - `/auth`
  - `/session/auth`
- 想定 caller
  - reverse proxy の auth subrequest / external auth / forward auth 相当
  - nginx `auth_request`
  - Apache auth helper 構成
  - Caddy `forward_auth`
- 非対象
  - `/login`
  - `/logout`
  - `/metrics`

## Request Contract

- method
  - `GET`
  - `HEAD` は拒否
  - その他 method は `405`
- body
  - auth subrequest は body なし
  - 既定 `ROCHE_LIMIT_AUTH_MAX_BODY_BYTES=0`
- required headers
  - `X-Target-Service`
  - `X-Required-Level`
- optional credential headers
  - `Authorization: Bearer <token>`
  - `X-API-Key`
- optional client IP headers
  - `X-Real-IP`
  - `X-Forwarded-For`
  - trusted proxy 経由時のみ信用
- duplicate / joined header policy
  - single-value auth header に comma joined 値がある場合は拒否
  - `hardened` は `Authorization` と `X-API-Key` 併用を拒否

## Response Status Contract

- `200`
  - allow
  - proxy 側は upstream へ通す
- `403`
  - deny
  - proxy 側は upstream へ通さない
- `405`
  - invalid method
  - proxy misconfiguration として扱う
- `429`
  - rate limited / quarantined
  - `Retry-After` を proxy/client に反映可能
- `500`
  - Roche-Limit internal error
  - fail-closed 推奨
- `503`
  - lockdown
  - `Retry-After` を proxy/client に反映可能

## Response Header Contract

- always expected on auth responses
  - `X-Request-Id`
  - `X-Auth-Level`
  - `X-Auth-Reason`
  - `X-Auth-Service`
- `/auth` optional headers
  - `X-Auth-IP-Rule-Id`
  - `X-Auth-Key-Id`
- `/session/auth` optional headers
  - `X-Auth-User-Id`
  - `X-Auth-Session-Id`
- retry headers
  - `Retry-After`
  - present for rate limit / quarantine / lockdown style responses

## Decision Fields

- `X-Auth-Level`
  - numeric string
  - deny/error path uses `0`
  - allow path uses granted level
- `X-Auth-Reason`
  - machine-readable reason
  - log / metrics / proxy response mapping key
- `X-Auth-Service`
  - evaluated service name
  - `*` when service is missing or unavailable
- `X-Request-Id`
  - Roche-Limit log
  - proxy access log
  - audit row

## Reason Groups

- allow
  - `ip_allow`
  - `ip_service_override`
  - `unknown_ip`
  - `api_key_elevated`
  - `session_allow`
- access deny
  - `ip_deny`
  - `insufficient_level`
  - `invalid_credentials`
  - `missing_session`
  - `invalid_session`
  - `expired_session`
  - `session_rotation_required`
- request / proxy issue
  - `missing_service`
  - `invalid_service`
  - `missing_required_level`
  - `invalid_required_level`
  - `invalid_header`
  - `invalid_client_ip`
  - `conflicting_forwarded_headers`
  - `forbidden_peer`
- containment / emergency
  - `rate_limited`
  - `quarantined`
  - `lockdown`
  - `emergency_denylist`
- internal
  - `internal_error`

## Proxy Mapping Notes

- common behavior
  - `2xx` allow
  - `403` deny
  - `429` deny with retry hint
  - `5xx` fail-closed
- headers to copy to upstream when allowed
  - `X-Request-Id`
  - `X-Auth-Level`
  - `X-Auth-Reason`
  - `X-Auth-Service`
  - `X-Auth-Key-Id`
  - `X-Auth-User-Id`
  - `X-Auth-Session-Id`
- headers not to trust from external clients
  - all `X-Auth-*`
  - `X-Target-Service`
  - `X-Required-Level`
  - forwarded client IP headers unless set by trusted proxy

## nginx

- current sample remains canonical
- `auth_request`
- `auth_request_set` only when upstream needs auth metadata
- subrequest location should be `internal`
- clear body for `/auth` and `/session/auth`

## Apache

- target shape
  - auth subrequest / helper to Roche-Limit
  - map `200` to allow
  - map non-`200` to deny
- items to verify later
  - module choice
  - header copy behavior
  - fail-closed behavior on Roche-Limit timeout
  - `Retry-After` propagation

## Caddy

- target shape
  - `forward_auth`
  - copy selected `X-Auth-*` headers
  - deny on non-`2xx`
- items to verify later
  - exact Caddyfile snippet
  - response header propagation
  - timeout / error handling

## Operational Notes

- Roche-Limit endpoints should not be public entrypoints
- proxy must strip user-supplied `X-Auth-*`
- `ROCHE_LIMIT_ALLOWED_PEERS` should restrict auth endpoint callers
- `ROCHE_LIMIT_TRUSTED_PROXIES` should match only real proxy peers
- public / hardened mode should use fail-closed defaults
