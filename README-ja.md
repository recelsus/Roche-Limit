# Roche-Limit

## Description

nginx `auth_request` を含む reverse proxy auth subrequest 前提の認証専用サーバーです。

Roche-Limit は access decision を application backend の外側に置きます。reverse proxy が先に Roche-Limit を呼び、許可された場合だけ backend へ通します。

## Feature

- IP allow / deny rule
- IP / API key access level
- browser flow 向け cookie session auth
- service 単位の access level override
- `/auth`, `/login`, `/logout`, `/session/auth` の request hardening
- in-memory containment、emergency denylist、audit log、Prometheus metrics
- SQLite storage と CLI 管理

## Endpoints

- `/auth`
  proxy subrequest 用の IP / API key authorization。
- `/session/auth`
  proxy subrequest 用の cookie session authorization。
- `/login`
  login page と credential submit。
- `/logout`
  session logout。
- `/metrics`
  Prometheus text metrics。

Roche-Limit は reverse proxy の背後に置いてください。auth endpoint や `/metrics` を public internet へ直接公開しないでください。

## Minimal Configuration

起動前に強い API key pepper を設定します。

```env
ROCHE_LIMIT_API_KEY_PEPPER=change-me-long-random-secret
```

public deployment では peer restriction も設定します。

```env
ROCHE_LIMIT_DEPLOYMENT_MODE=public
ROCHE_LIMIT_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_ALLOWED_PEERS=127.0.0.1,::1,172.18.0.0/16
ROCHE_LIMIT_METRICS_MODE=internal
```

deployment mode、endpoint limit、session cookie、containment、metrics、headers は [`docs/configuration.md`](./docs/configuration.md) を参照してください。

## CLI

`roche_limit_cli` で IP rule、API key、user、session、audit cleanup を管理します。

```text
roche_limit_cli ip list
roche_limit_cli key gen --service primary --level 60
roche_limit_cli user list
roche_limit_cli audit cleanup --retention-days 90 --max-rows 10000
```

key rotation、key disable/remove、session revoke、password change、user remove などの高影響操作は `--force` が必要です。先に `--dry-run` で対象を確認してください。

全 command は [`docs/cli.md`](./docs/cli.md) を参照してください。

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

## Reverse Proxy

nginx の例は [`docs/nginx-sample.md`](./docs/nginx-sample.md) から始めてください。

proxy 共通の response contract、status mapping、headers は [`docs/reverse-proxy-contract.md`](./docs/reverse-proxy-contract.md) を参照してください。

## Documentation

- [`docs/configuration.md`](./docs/configuration.md)
  runtime configuration、auth contract、session cookie、containment、metrics。
- [`docs/cli.md`](./docs/cli.md)
  CLI command と高影響操作の扱い。
- [`docs/nginx-sample.md`](./docs/nginx-sample.md)
  nginx `auth_request` の例。
- [`docs/reverse-proxy-contract.md`](./docs/reverse-proxy-contract.md)
  reverse proxy contract notes。
- [`docs/migration.md`](./docs/migration.md)
  database migration policy。

## Database

新規 DB は [`schema/init.sql`](./schema/init.sql) から作成します。既存 DB は [`schema/migrations`](./schema/migrations) の migration で更新します。

## Licence

Roche-Limit は MIT License です。詳細は [`LICENSE`](./LICENSE) を参照してください。

第三者ライブラリの notice は [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) に記載しています。
