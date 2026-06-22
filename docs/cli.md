# roche-limit CLI

## Help

Top-level help shows command domains instead of every available action.

```text
roche_limit_cli -h
roche_limit_cli --help
roche_limit_cli help
```

Domain help groups actions by purpose and impact.

```text
roche_limit_cli ip -h
roche_limit_cli key -h
roche_limit_cli user -h
roche_limit_cli audit -h
```

Action help shows the exact usage and safety requirements.

```text
roche_limit_cli key rotate -h
roche_limit_cli user revoke-all-user-sessions --help
roche_limit_cli help key disable-all
```

Help is processed before opening the database.

Entering only a command domain, such as `roche_limit_cli ip`, falls back to
that domain's help. Unknown domains/actions and actions missing their required
target also display the nearest available help and exit with a non-zero status.

## Usage

### IP

```text
roche_limit_cli ip list
roche_limit_cli ip add <ip-or-cidr> --allow|--deny [--note TEXT]
roche_limit_cli ip set <rule-id> [--value <ip-or-cidr>] [--allow|--deny] [--note TEXT]
roche_limit_cli ip set <rule-id> [--service <name|*>] [--level <0-90>] [--note TEXT]
roche_limit_cli ip set <ip-or-cidr> [--service <name|*>] --level <0-90> [--note TEXT]
roche_limit_cli ip remove <rule-id>
```

- `ip add` は `single` / `cidr` と IPv4 / IPv6 を自動判別
- `ip set <rule-id>` は共通 `ip_rules` の更新
- `ip set <rule-id> --service ... --level ...` は、その `ip_rule_id` に紐づく `ip_service_levels` の更新
- `ip set <ip-or-cidr> --service ...` は `ip_service_levels` の upsert
- `ip set <ip-or-cidr> --level ...` のみで、全サービス向け override を設定できる
- サービス別設定は、対応する共通 `allow` ルールがない場合は失敗する
- `ip remove` は紐づく `ip_service_levels` もまとめて削除する
- `ip list` は共通 IP ルールに加え、`ip_service_levels` も表示する

### API Key

```text
roche_limit_cli key list
roche_limit_cli key add <plain-api-key> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key gen [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key rotate <api-key-id> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT] [--dry-run|--force]
roche_limit_cli key set <api-key-id> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key disable <api-key-id> [--dry-run|--force]
roche_limit_cli key disable-all [--dry-run|--force]
roche_limit_cli key remove <api-key-id> [--dry-run|--force]
```

- `key add` と `key gen` の `--level` 省略時は `10`
- `ROCHE_LIMIT_DEFAULT_API_KEY_LEVEL` で `--level` 省略時の既定値を上書きできる
- `--service` は key の scope として扱われます。省略時は全サービス共通です
- `--service *` でも全サービス共通を指定できます
- `key gen` と `key rotate` は生成した平文キーを1回だけ表示します
- `key rotate` は旧 key を disable したうえで、新しい key を同じ設定で再発行します
- `key rotate`, `key disable`, `key disable-all`, `key remove` は破壊的操作として扱い、実行には `--force` が必要です
- `--dry-run` は対象 key を表示し、変更せずに監査ログへ dry-run event を残します
- APIキー作成・検証には `ROCHE_LIMIT_API_KEY_PEPPER` が必須
- DBには平文キーを保存せず、Argon2id verifier, peppered lookup hash, prefix のみを保存する
- `key list` は平文キーや verifier を表示せず、prefix と利用統計のみを表示します
- `key list` では `last_used`, `last_ip`, `fails`, `last_failed`, `expires` を確認できます
- 期限切れ key は lookup/list 時に自動で disable されます
- `key_prefix` は DB 上で一意です

### Client Certificate

```text
roche_limit_cli cert list
roche_limit_cli cert add <fingerprint> [--service <name|*>] [--level <0-99>] [--serial TEXT] [--subject TEXT] [--issuer TEXT] [--not-before <timestamp>] [--not-after <timestamp>] [--note TEXT]
roche_limit_cli cert set <cert-id> [--service <name|*>] --level <0-99> [--note TEXT]
roche_limit_cli cert disable <cert-id> [--dry-run|--force]
roche_limit_cli cert enable <cert-id> [--dry-run|--force]
roche_limit_cli cert remove <cert-id> [--dry-run|--force]
```

- `cert add` は SHA-256 fingerprint を正規化して保存します
- `cert add` は証明書本体と初期 service level を作成します。`--level` 省略時は既定 `10`
- `cert set` は `client_cert_service_levels` を upsert します
- `--service` 省略時または `--service *` は全サービス共通 fallback です
- `cert disable`, `cert enable`, `cert remove` は高影響操作として扱い、実行には `--force` が必要です
- `--dry-run` は対象証明書を表示し、変更せずに監査ログへ dry-run event を残します

### Audit

```text
roche_limit_cli audit list [--limit <1-500>] [--event-type <type>] [--result <result>] [--service <name>] [--request-id <id>] [--actor-type <type>] [--reason <reason>] [--client-ip <ip>]
roche_limit_cli audit show <event-id>
roche_limit_cli audit cleanup [--retention-days <days>] [--max-rows <count>]
```

- `audit list` は新しい event から既定50件を表示します
- `audit list` の filter は完全一致です。複数指定時はすべてに一致する event を表示します
- `audit show` は metadata と hash chain を含む保存項目を表示します
- `audit list` と `audit show` は監査ログへ新しい event を追加しません
- `audit cleanup` は retention と row cap に基づいて監査ログを整理します
- 削除件数は `audit_cleanup` event の metadata に記録されます
- CLI の管理操作は監査ログに記録されます
- plain API key / password は CLI 監査 metadata では redact されます

### User

```text
roche_limit_cli user list
roche_limit_cli user add <username> [--password <plain>] [--note TEXT]
roche_limit_cli user set-password <user-id> [--password <plain>] [--dry-run|--force]
roche_limit_cli user set <user-id> [--note TEXT] [--disable|--enable] [--dry-run|--force]
roche_limit_cli user set <user-id> [--service <name|*>] [--level <0-99>] [--note TEXT] [--dry-run|--force]
roche_limit_cli user session-list [--user-id <id>]
roche_limit_cli user revoke-session <session-id> [--dry-run|--force]
roche_limit_cli user revoke-all-sessions <user-id> [--dry-run|--force]
roche_limit_cli user revoke-all-user-sessions [--dry-run|--force]
roche_limit_cli user disable <user-id> [--dry-run|--force]
roche_limit_cli user remove <user-id> [--dry-run|--force]
```

- `user add` はユーザー本体と password credential を作成する
- `user set-password` は credential のみ更新する
- `user set --service ... --level ...` は `user_service_levels` の upsert
- password 変更、enable/disable、service level 変更時はその user の全 session を revoke する
- session revoke、password 変更、disable/remove、service level 変更、enable/disable は高影響操作として扱い、実行には `--force` が必要です
- `--dry-run` は対象 user/session と active session 数を表示し、変更せずに監査ログへ dry-run event を残します
- `user session-list` は session 一覧を表示する
- `user revoke-session` は 1 session を revoke する
- `user revoke-all-sessions` は user 配下の全 session を revoke する
- `user revoke-all-user-sessions` は全 user session を revoke する緊急操作です
- user の service 解決は `service一致 -> * -> 0`
- `user remove` は user 配下の credential / service level / session も含めて削除される
- session は absolute timeout / idle timeout を別で持ち、rotation interval 超過時は再 login を要求する

### List

- `list` はヘッダ付きの表形式で表示する

### Experimental

次の ID 詰め直しコマンドは監査ログや外部メモとの整合性を崩しやすいため、通常は非表示かつ無効です。使う場合のみ `ROCHE_LIMIT_ENABLE_EXPERIMENTAL_CLI=1` を設定してください。

```text
roche_limit_cli ip compact-ids
roche_limit_cli key compact-ids
roche_limit_cli user compact-ids
```

- `ip compact-ids` は `ip_rules.id` と `ip_service_levels.id` を1から詰め直し、参照先も追従する
- `key compact-ids` は `api_keys.id` を1から詰め直す
- `user compact-ids` は `users.id` を1から詰め直し、関連する `user_id` 参照と `user_service_levels.id`, `user_sessions.id` も追従させる
