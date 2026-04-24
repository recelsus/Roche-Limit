# Nginx Sample

`Roche-Limit` を nginx の `auth_request` と組み合わせて使うためのサンプルです。  
ここでは `roche-limit` は内部 network 上に存在し、外部公開しない前提です。

`/auth` と `/session/auth` は nginx `auth_request` 用の endpoint なので `GET` のみ受け付けます。

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
- `X-Required-Level` も必須
- API キーは `Authorization: Bearer ...` を優先し、なければ `X-API-Key` を利用
- `X-Real-IP` と `X-Forwarded-For` は両方渡しておく
- `auth_request_set` は backend へ補助情報を引き継ぎたい場合のみ利用する

`roche-limit` 側では `ROCHE_LIMIT_TRUSTED_PROXIES` に一致する接続元から来た場合のみ `X-Real-IP` / `X-Forwarded-For` を信用します。Docker の nginx reverse proxy 例では次のように設定できます。

```env
ROCHE_LIMIT_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_ALLOWED_PEERS=127.0.0.1,::1,172.18.0.0/16
```

`ROCHE_LIMIT_ALLOWED_PEERS` は `/auth` `/session/auth` 自体へ到達できる peer を制限します。未設定時は `ROCHE_LIMIT_TRUSTED_PROXIES` が流用されます。
本番でより厳密にする場合は、nginx の固定 IP または nginx と `roche-limit` の専用 Docker network の CIDR に絞ってください。

`roche-limit` は `/metrics` で Prometheus text 形式の counter を返します。外部公開せず、Prometheus など監視系コンテナからだけ到達できる network に置くか、nginx 側で別途保護してください。

サブパス配下に login を置く場合でも、通常は cookie `Path=/` のままで問題ありません。複数の Roche-Limit インスタンスを同一ドメインで使い分ける場合は、`ROCHE_LIMIT_SESSION_COOKIE_NAME` や `ROCHE_LIMIT_SESSION_COOKIE_PATH` を分けて衝突を避けてください。

主なレスポンスヘッダ:

- `X-Request-Id`
  nginx と Roche-Limit のログ照合用
- `X-Auth-Level`
  backend に渡すアクセスレベル
- `X-Auth-Reason`
  判定理由
- `X-Auth-Service`
  判定対象 service

## 複数 service の例

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

## location ごとに required level を変える例

`Roche-Limit` は `X-Required-Level` を必須で受け取るため、location ごとに必要レベルを nginx 側で定義します。  
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

## `/` は IP / APIキー、`/web/` は login/session を使う例

この例では:

- `/`
  既存の `/auth` を利用
- `/web/`
  `/session/auth` を利用
- `/web/login`
  `roche-limit` の login 画面
- `/web/logout`
  `roche-limit` の logout
- `app-web` が backend API を使う場合は `/web/api/` などの別経路を frontend 側で用意すると扱いやすい

```nginx
upstream roche_limit_auth {
    server roche-limit:8080;
}

upstream app_primary {
    server app-primary:8080;
}

upstream app_web {
    server app-web:8080;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    location = /web {
        return 301 /web/;
    }

    location = /web/login {
        proxy_pass http://roche_limit_auth/login;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /web/logout {
        proxy_pass http://roche_limit_auth/logout;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Cookie $http_cookie;
    }

    location /web/ {
        auth_request /__roche_limit_session_auth;
        error_page 403 = @web_login_redirect;
        proxy_pass http://app_web;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Auth-Level $upstream_http_x_auth_level;
    }

    location / {
        auth_request /__roche_limit_auth;
        proxy_pass http://app_primary;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Auth-Level $upstream_http_x_auth_level;
    }

    location = /__roche_limit_auth {
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

    location = /__roche_limit_session_auth {
        internal;
        proxy_pass http://roche_limit_auth/session/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Target-Service web;
        proxy_set_header X-Required-Level 60;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Cookie $http_cookie;
    }

    location @web_login_redirect {
        return 302 /web/login;
    }
}
```

この形では:

- `app-primary` 側は IP / APIキー中心
- `app-web` 側は Cookie session 中心
- `roche-limit` は両方の endpoint を提供するだけ

`app-web` が browser から `karing` API を使う場合は、frontend から root `/` を直接叩かず、
`/web/api/` のような path を `app-web` 側 nginx で backend に proxy する構成が安全です。

## サブパス `regufa.com/karing/` の例

サブドメインではなくサブパスで公開する場合は、nginx で prefix を剥がして backend に渡す構成が扱いやすいです。

```nginx
upstream roche_limit_auth {
    server roche-limit:8080;
}

upstream karing_app {
    server karing:8080;
}

server {
    listen 443 ssl http2;
    server_name regufa.com;

    location = /karing {
        return 301 /karing/;
    }

    location = /karing/login {
        proxy_pass http://roche_limit_auth/login;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /karing/ {
        auth_request /__roche_limit_auth_karing;
        rewrite ^/karing/(.*)$ /$1 break;
        proxy_pass http://karing_app;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Auth-Level $upstream_http_x_auth_level;
    }

    location = /__roche_limit_auth_karing {
        internal;
        proxy_pass http://roche_limit_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header X-Target-Service karing;
        proxy_set_header X-Required-Level 90;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-API-Key $http_x_api_key;
    }
}
```

この例では:

- 公開 URL は `/karing/...`
- backend には `/...` として渡す
- login も `/karing/login` として切り出す
