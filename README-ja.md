# Roche-Limit

## Description

nginxの`auth_request`を前提の認証専用サーバー。  

- IPアドレスのallow/deny
- IPアドレスのアクセスレベル制御
- APIキーによるアクセスレベル制御
- APIキーの利用統計 / rotation / expiry disable
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
  IP / APIキー用の認証判定。`GET` のみ。
- `/login`
  ログイン画面 / ログイン処理。`GET` は画面表示、`POST` は credential 送信。
- `/logout`
  ログアウト処理。`POST` のみ。
- `/session/auth`
  Cookie session 用の認証判定。`GET` のみ。
- `/metrics`
  Prometheus text 形式のメトリクス。`GET` のみ。

これらは nginx からの内部利用を前提とした構成です。
`/metrics` は内部 network に留めるか、nginx 側で保護してください。

`/login` には IP + username 単位の rate limit / 一時 lockout があります。  
`/login` / `/logout` は CSRF token を検証します。`/login` は GET 時に token を発行し、`/logout` は login 成功後に払い出された CSRF cookie と `X-CSRF-Token` または `csrf_token` を利用します。

## Observability

認証系のレスポンスには `X-Request-Id` を付与します。nginx のログと Roche-Limit 側のログを突き合わせるための値です。

監査ログは hash chain を持ちます。`metadata_json` は標準化された JSON 形式で保存され、CLI 管理操作や cleanup も監査対象です。

`/metrics` は Prometheus 形式の counter を返します。

- `roche_limit_auth_requests_total`
  `endpoint`, `result`, `reason` ごとの認証関連リクエスト数
- `roche_limit_request_ids_issued_total`
  プロセスが発行した request id の数

## Rules

アクセスレベルは0(ブロック)と1-99を想定, 推奨は(0, 10, 30, 60, 90)  
未登録IPは10, 共通allowは10を基準とします

- 共通 `IP deny` は最優先で拒否
- 共通 `IP allow` は `10` を付与
- 未登録のIP は既定で `10` を付与
- サービス別overrideがあればそれを適用
- APIキーがあればアクセスレベルを再評価
- 最終的なアクセスレベルをnginxへ返す

## Configuration

- `ROCHE_LIMIT_API_KEY_PEPPER`
  起動時に必須。APIキー作成・検証にも使うため、長いランダム値を設定してください。
- `ROCHE_LIMIT_UNKNOWN_IP_LEVEL`
  未登録IPの既定アクセスレベル。未設定時は `10`。
- `ROCHE_LIMIT_SHARED_IP_ALLOW_LEVEL`
  共通 `IP allow` の既定アクセスレベル。未設定時は `10`。
- `ROCHE_LIMIT_DEFAULT_API_KEY_LEVEL`
  `key add` / `key gen` で `--level` を省略したときの既定アクセスレベル。未設定時は `10`。
- `ROCHE_LIMIT_AUDIT_AUTH_ALLOW`
  `1` のときのみ `/auth` / `/session/auth` の allow event も監査ログへ記録。未設定時は deny / error / login / logout 系のみを記録。
- `ROCHE_LIMIT_AUDIT_RETENTION_DAYS`
  監査ログ保持日数の想定値。未設定時は運用側の cleanup 実行方針に従います。
- `ROCHE_LIMIT_AUDIT_MAX_ROWS`
  監査ログの最大行数の想定値。小規模運用の基準は `10000`。

## 必要なヘッダ

現在の `/auth` は主に次のヘッダを受け取ります。

- `X-Target-Service`
  必須
- `X-Required-Level`
  必須
- `Authorization: Bearer <token>`
  任意
- `X-API-Key`
  任意
- `X-Real-IP`
  任意
- `X-Forwarded-For`
  任意

`X-Target-Service` と `X-Required-Level` は必須です。  
API キーは `Bearer` を優先し、次に `X-API-Key` を参照します。
`X-Required-Level` の parse に失敗した場合は `403` を返します。

APIキーの `service` は scope として扱います。  
一致順は `service一致 -> *` です。

APIキーは次を保持します。

- `last_used_at`
- `last_used_ip`
- `last_failed_at`
- `failed_attempts`

期限付き API キーは lookup / list 時に自動で disable されます。  
CLI では `key rotate` で旧 key を disable しつつ新 key を再発行できます。

`X-Real-IP` / `X-Forwarded-For` は `ROCHE_LIMIT_TRUSTED_PROXIES` に一致する接続元から来た場合のみ信用します。未設定時は forwarded 系ヘッダを無視し、直接の peer IP を使用します。
`/auth` と `/session/auth` は `ROCHE_LIMIT_ALLOWED_PEERS` に一致する接続元のみ許可します。未設定時は `ROCHE_LIMIT_TRUSTED_PROXIES` を流用し、両方未設定のときだけ peer 制限なしで動作します。

例:

```env
ROCHE_LIMIT_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_ALLOWED_PEERS=127.0.0.1,::1,172.18.0.0/16
```

Cookie session は `roche_limit_session` を使用し、既定で `Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800` を付与します。

Session cookie は環境変数で変更できます。

- `ROCHE_LIMIT_SESSION_COOKIE_NAME`
  既定値: `roche_limit_session`
- `ROCHE_LIMIT_SESSION_COOKIE_PATH`
  既定値: `/`
- `ROCHE_LIMIT_SESSION_COOKIE_DOMAIN`
  既定値: 未設定
- `ROCHE_LIMIT_SESSION_COOKIE_SAMESITE`
  既定値: `Lax`; 利用値: `Lax`, `Strict`, `None`
- `ROCHE_LIMIT_SESSION_COOKIE_SECURE`
  既定値: `1`
- `ROCHE_LIMIT_SESSION_COOKIE_HTTP_ONLY`
  既定値: `1`
- `ROCHE_LIMIT_SESSION_COOKIE_MAX_AGE`
  既定値: `604800`
- `ROCHE_LIMIT_SESSION_TOKEN_PEPPER`
  未設定時は `ROCHE_LIMIT_API_KEY_PEPPER` を流用
- `ROCHE_LIMIT_SESSION_IDLE_TIMEOUT_SECONDS`
  既定値: `3600`
- `ROCHE_LIMIT_SESSION_ABSOLUTE_TIMEOUT_SECONDS`
  既定値: `604800`
- `ROCHE_LIMIT_SESSION_ROTATION_INTERVAL_SECONDS`
  既定値: `86400`

Cookie 設定には起動時検証があります。

- Cookie 名 / Domain / Path に制御文字は使えません
- `SameSite=None` の場合は `Secure` を強制します
- `__Host-` prefix は `Secure`, `Path=/`, `Domain` 未設定が必須です
- `__Secure-` prefix は `Secure` が必須です

session は idle timeout / absolute timeout を別で持ちます。  
rotation interval を超えた session は `session_rotation_required` で deny され、再 login を要求します。

## Response Headers

認証 endpoint は次のヘッダを返します。

- `X-Request-Id`
  リクエスト単位の照合用 ID
- `X-Auth-Level`
  付与された数値アクセスレベル
- `X-Auth-Reason`
  機械可読な認証 reason
- `X-Auth-Service`
  Roche-Limit が判定した対象 service
- `X-Auth-IP-Rule-Id`
  IP ルールに一致した場合の rule id
- `X-Auth-Key-Id`
  API キーに一致した場合の key id
- `X-Auth-User-Id`
  session auth で一致した user id
- `X-Auth-Session-Id`
  session auth で一致した session id

## CLI

詳細は [`docs/cli.md`](./docs/cli.md) を参照。

## Docker

最小の `docker-compose.yml` 例:

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

`docker run` の例:

```bash
docker run -d \
  --name roche-limit \
  --restart unless-stopped \
  --network nginx \
  -e ROCHE_LIMIT_API_KEY_PEPPER='change-me-long-random-secret' \
  -v "$(pwd)/data:/var/lib/roche-limit" \
  ghcr.io/recelsus/roche-limit:latest
```

## DB Migration

新規 DB は [`schema/init.sql`](./schema/init.sql) から作成します。既存 DB の更新方針は [`docs/migration.md`](./docs/migration.md) を参照してください。

## Licence

Roche-Limit は MIT License です。詳細は [`LICENSE`](./LICENSE) を参照してください。

第三者ライブラリの notice は [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) に記載しています。

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

`docs/nginx-sample.md` には次も含めています。

- location ごとに required level を切り替える例
- `/` は IP / APIキー、`/web/` は login/session を使う併用例
- `karing-web` が `/web/api/` 経由で `karing` を叩く構成例
- `example.com/karing/` のようなサブパス配下で使う例
