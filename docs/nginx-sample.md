# Nginx Sample

`Roche-Limit` を nginx の `auth_request` と組み合わせて使うためのサンプルです。  
ここでは `roche-limit` は内部 network 上に存在し、外部公開しない前提です。

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
        auth_request_set $auth_level $upstream_http_x_auth_level;
        auth_request_set $auth_reason $upstream_http_x_auth_reason;

        proxy_set_header X-Auth-Level $auth_level;
        proxy_set_header X-Auth-Reason $auth_reason;
        proxy_pass http://app_primary;
    }

    location = /__roche_limit_auth {
        internal;
        proxy_pass http://roche_limit_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Target-Service primary;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-API-Key $http_x_api_key;
    }
}
```

- `X-Target-Service` は必須
- API キーは `Authorization: Bearer ...` を優先し、なければ `X-API-Key` を利用
- `X-Real-IP` と `X-Forwarded-For` は両方渡しておく
- `auth_request_set` で `X-Auth-Level` と `X-Auth-Reason` を受け取り、backend へ引き継げる

#### Multiple service example

```nginx
upstream roche_limit_auth {
    server roche-limit:8080;
}

upstream app_primary {
    server app-primary:8080;
}

upstream app_secondary {
    server app-secondary:8080;
}

server {
    listen 443 ssl http2;
    server_name primary.example.com;

    location / {
        auth_request /__roche_limit_auth_primary;
        auth_request_set $auth_level $upstream_http_x_auth_level;
        proxy_set_header X-Auth-Level $auth_level;
        proxy_pass http://app_primary;
    }

    location = /__roche_limit_auth_primary {
        internal;
        proxy_pass http://roche_limit_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Target-Service primary;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-API-Key $http_x_api_key;
    }
}

server {
    listen 443 ssl http2;
    server_name secondary.example.com;

    location / {
        auth_request /__roche_limit_auth_secondary;
        auth_request_set $auth_level $upstream_http_x_auth_level;
        proxy_set_header X-Auth-Level $auth_level;
        proxy_pass http://app_secondary;
    }

    location = /__roche_limit_auth_secondary {
        internal;
        proxy_pass http://roche_limit_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Target-Service secondary;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-API-Key $http_x_api_key;
    }
}
```

#### Branching based on access level

`Roche-Limit` は `X-Auth-Level` を返すため、必要なら nginx 側で分岐できます。  
ただし複雑にしすぎず、基本は backend 側へそのまま渡す運用を推奨します。

簡単な例:

```nginx
location /admin/ {
    auth_request /__roche_limit_auth;
    auth_request_set $auth_level $upstream_http_x_auth_level;

    if ($auth_level != 90) {
        return 403;
    }

    proxy_pass http://app_primary;
}
```

本番では `if` を多用するより、`map` や location 分割で整理する方が安全です。

