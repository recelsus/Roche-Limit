# roche-limit CLI

## 1. Usage

### IP

```text
roche_limit_cli ip list
roche_limit_cli ip add <ip-or-cidr> --allow|--deny [--note TEXT]
roche_limit_cli ip set <rule-id> [--value <ip-or-cidr>] [--allow|--deny] [--note TEXT]
roche_limit_cli ip set <ip-or-cidr> [--service <name|*>] --level <0-90> [--note TEXT]
roche_limit_cli ip remove <rule-id>
```

- `ip add` は `single` / `cidr` と IPv4 / IPv6 を自動判別
- `ip set <rule-id>` は共通 `ip_rules` の更新
- `ip set <ip-or-cidr> --service ...` は `ip_service_levels` の upsert
- `ip set <ip-or-cidr> --level ...` のみで、全サービス向け override を設定できる
- サービス別設定は、対応する共通 `allow` ルールがない場合は失敗する
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
```

- `key add` と `key gen` の `--level` 省略時は `30`
- `--service` 省略時は全サービス共通
- `--service *` でも全サービス共通を指定できる
- `key gen` は生成した平文キーを表示し、DB にも保存する
- `key clear-plain` により、堅牢に扱いたい API キーだけ後から平文を削除できる

### List

- `list` はヘッダ付きの表形式で表示する

