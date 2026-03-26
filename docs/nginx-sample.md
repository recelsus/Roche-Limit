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

- `X-Target-Service` は必須
- `X-Required-Level` を渡すと `/auth` 側で必要レベル判定を行う
- API キーは `Authorization: Bearer ...` を優先し、なければ `X-API-Key` を利用
- `X-Real-IP` と `X-Forwarded-For` は両方渡しておく
- `auth_request_set` は backend へ補助情報を引き継ぎたい場合のみ利用する

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
        proxy_pass http://app_primary;
    }

    location = /__roche_limit_auth_primary {
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

server {
    listen 443 ssl http2;
    server_name secondary.example.com;

    location / {
        auth_request /__roche_limit_auth_secondary;
        proxy_pass http://app_secondary;
    }

    location = /__roche_limit_auth_secondary {
        internal;
        proxy_pass http://roche_limit_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Target-Service secondary;
        proxy_set_header X-Required-Level 60;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-API-Key $http_x_api_key;
    }
}
```

#### Requiring a level per location

`Roche-Limit` は `X-Required-Level` を受け取れるため、location ごとに必要レベルを nginx 側で定義できます。  
分岐ルール自体は nginx に置いたまま、判定は `/auth` に任せる形です。

例:

```nginx
location /admin/ {
    auth_request /__roche_limit_auth_90;
    proxy_pass http://app_primary;
}

location /member/ {
    auth_request /__roche_limit_auth_60;
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

location = /__roche_limit_auth_60 {
    internal;
    proxy_pass http://roche_limit_auth/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_set_header X-Target-Service primary;
    proxy_set_header X-Required-Level 60;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-API-Key $http_x_api_key;
}
```

この形なら nginx は `auth_request` の可否だけを見ればよく、`auth_request_set` の値を `if` で評価する必要はありません。
