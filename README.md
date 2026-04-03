# Roche-Limit

## Description

A dedicated authorisation server designed around nginx `auth_request`.

- IP address allow / deny rules
- IP-based access level control
- API key based access level control
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
  IP / API key authorisation
- `/login`
  Login page and login submit
- `/logout`
  Logout endpoint
- `/session/auth`
  Cookie session authorisation

These endpoints are intended to be used behind nginx.

## Rules

Access levels assume `0` for blocked and `1-99` for allowed levels.  
Recommended values are `0`, `10`, `30`, `60`, and `90`.  
The default level is `30`.

- Shared `IP deny` rules reject first
- Shared `IP allow` rules grant the default access level
- Unregistered IP addresses receive the default access level
- Service-specific overrides are applied when present
- API keys may raise the access level
- The final access level is returned to nginx

## Required Headers

`/auth` mainly expects the following headers.

- `X-Target-Service`
  Required
- `Authorization: Bearer <token>`
  Optional
- `X-API-Key`
  Optional
- `X-Real-IP`
  Optional
- `X-Forwarded-For`
  Optional

`X-Target-Service` is required.  
For API keys, `Bearer` is checked first, then `X-API-Key`.
If needed, nginx may also pass `X-Required-Level`, and `/auth` will enforce the required level directly.

## CLI

See [`docs/roche-limit-cli.md`](./docs/roche-limit-cli.md) for details.

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
- a subpath example such as `regufa.com/karing/`
