# Roche-Limit

## Description

nginxの`auth_request`を前提の認証専用サーバー。  

- IPアドレスのallow/deny
- IPアドレスのアクセスレベル制御
- APIキーによるアクセスレベル制御
- サービス単位のアクセスレベル制御
- CLIによる設定確認と更新

## Feature

- `Drogon` ベースの C++20 サーバー
- `SQLite` でのIPアドレス, API-Key管理
- `/auth` へのリクエストのみでアクセス可否やアクセスレベルを制御
- CLI管理操作

## HTTP Endpoints

- `/`
  疎通確認用
- `/auth`
  認証判定用

`/` `/auth` どちらもnginx からの内部リクエストを前提としているためSSL/TLS非実装

## Rules

アクセスレベルは0(ブロック)と1-99を想定, 推奨は(0, 10, 30, 60, 90) デフォルトは30

- 共通 `IP deny` は最優先で拒否
- 共通 `IP allow` はデフォルトのアクセスレベルを付与
- 未登録のIP はデフォルトのアクセスレベルを付与
- サービス別overrideがあればそれを適用
- APIキーがあればアクセスレベルを再評価
- 最終的なアクセスレベルをnginxへ返す

## 必要なヘッダ

現在の `/auth` は主に次のヘッダを受け取ります。

- `X-Target-Service`
  必須
- `Authorization: Bearer <token>`
  任意
- `X-API-Key`
  任意
- `X-Real-IP`
  任意
- `X-Forwarded-For`
  任意

`X-Target-Service` は必須です。  
API キーは `Bearer` を優先し、次に `X-API-Key` を参照します。
必要であれば `X-Required-Level` を nginx から渡し、`/auth` 側で必要レベル判定を行えます。

## CLI

詳細は [`docs/roche-limit-cli.md`](./docs/roche-limit-cli.md) を参照。

## Nginx Config Sample

最小構成の例:

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

アクセスレベル `90` 以上を要求したい場合の例:

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

この例では:

- `granted level >= 90` のときのみ通過
- `90` 未満は `/auth` が `403` を返す
- nginx は `auth_request` の結果だけを見ればよい

詳細なサンプルは [`docs/nginx-sample.md`](./docs/nginx-sample.md) を参照。
