# roche-limit CLI

## 1. Usage

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
roche_limit_cli key rotate <api-key-id> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key set <api-key-id> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key disable <api-key-id>
roche_limit_cli key remove <api-key-id>
```

- `key add` と `key gen` の `--level` 省略時は `30`
- `--service` は key の scope として扱われます。省略時は全サービス共通です
- `--service *` でも全サービス共通を指定できます
- `key gen` と `key rotate` は生成した平文キーを1回だけ表示します
- `key rotate` は旧 key を disable したうえで、新しい key を同じ設定で再発行します
- APIキー作成・検証には `ROCHE_LIMIT_API_KEY_PEPPER` が必須
- DBには平文キーを保存せず、Argon2id verifier, peppered lookup hash, prefix のみを保存する
- `key list` は平文キーや verifier を表示せず、prefix と利用統計のみを表示します
- `key list` では `last_used`, `last_ip`, `fails`, `last_failed`, `expires` を確認できます
- 期限切れ key は lookup/list 時に自動で disable されます
- `key_prefix` は DB 上で一意です

### Audit

```text
roche_limit_cli audit cleanup [--retention-days <days>] [--max-rows <count>]
```

- `audit cleanup` は retention と row cap に基づいて監査ログを整理します
- 削除件数は `audit_cleanup` event の metadata に記録されます
- CLI の管理操作は監査ログに記録されます
- plain API key / password は CLI 監査 metadata では redact されます

### User

```text
roche_limit_cli user list
roche_limit_cli user add <username> [--password <plain>] [--note TEXT]
roche_limit_cli user set-password <user-id> [--password <plain>]
roche_limit_cli user set <user-id> [--note TEXT] [--disable|--enable]
roche_limit_cli user set <user-id> [--service <name|*>] [--level <0-99>] [--note TEXT]
roche_limit_cli user session-list [--user-id <id>]
roche_limit_cli user revoke-session <session-id>
roche_limit_cli user revoke-all-sessions <user-id>
roche_limit_cli user disable <user-id>
roche_limit_cli user remove <user-id>
```

- `user add` はユーザー本体と password credential を作成する
- `user set-password` は credential のみ更新する
- `user set --service ... --level ...` は `user_service_levels` の upsert
- password 変更、enable/disable、service level 変更時はその user の全 session を revoke する
- `user session-list` は session 一覧を表示する
- `user revoke-session` は 1 session を revoke する
- `user revoke-all-sessions` は user 配下の全 session を revoke する
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
