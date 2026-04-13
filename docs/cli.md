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
roche_limit_cli ip compact-ids
```

- `ip add` は `single` / `cidr` と IPv4 / IPv6 を自動判別
- `ip set <rule-id>` は共通 `ip_rules` の更新
- `ip set <rule-id> --service ... --level ...` は、その `ip_rule_id` に紐づく `ip_service_levels` の更新
- `ip set <ip-or-cidr> --service ...` は `ip_service_levels` の upsert
- `ip set <ip-or-cidr> --level ...` のみで、全サービス向け override を設定できる
- サービス別設定は、対応する共通 `allow` ルールがない場合は失敗する
- `ip remove` は紐づく `ip_service_levels` もまとめて削除する
- `ip compact-ids` は `ip_rules.id` と `ip_service_levels.id` を1から詰め直し、参照先も追従する
- `ip list` は共通 IP ルールに加え、`ip_service_levels` も表示する

### API Key

```text
roche_limit_cli key list
roche_limit_cli key add <plain-api-key> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key gen [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key set <api-key-id> [--service <name|*>] [--level <0-90>] [--expires-at <timestamp>] [--note TEXT]
roche_limit_cli key clear-plain <api-key-id>
roche_limit_cli key disable <api-key-id>
roche_limit_cli key remove <api-key-id>
roche_limit_cli key compact-ids
```

- `key add` と `key gen` の `--level` 省略時は `30`
- `--service` 省略時は全サービス共通
- `--service *` でも全サービス共通を指定できる
- `key gen` は生成した平文キーを表示し、DB にも保存する
- `key clear-plain` により、堅牢に扱いたい API キーだけ後から平文を削除できる
- `key compact-ids` は `api_keys.id` を1から詰め直す

### User

```text
roche_limit_cli user list
roche_limit_cli user add <username> [--password <plain>] [--note TEXT]
roche_limit_cli user set-password <user-id> [--password <plain>]
roche_limit_cli user set <user-id> [--note TEXT] [--disable|--enable]
roche_limit_cli user set <user-id> [--service <name|*>] [--level <0-99>] [--note TEXT]
roche_limit_cli user disable <user-id>
roche_limit_cli user remove <user-id>
roche_limit_cli user compact-ids
```

- `user add` はユーザー本体と password credential を作成する
- `user set-password` は credential のみ更新する
- `user set --service ... --level ...` は `user_service_levels` の upsert
- user の service 解決は `service一致 -> * -> 0`
- `user remove` は user 配下の credential / service level / session も含めて削除される
- `user compact-ids` は `users.id` を1から詰め直し、関連する `user_id` 参照と `user_service_levels.id`, `user_sessions.id` も追従させる

### List

- `list` はヘッダ付きの表形式で表示する
