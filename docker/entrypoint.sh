#!/usr/bin/env sh
set -eu

mkdir -p /var/lib/roche-limit
chown -R roche-limit:roche-limit /var/lib/roche-limit /app

exec gosu roche-limit "$@"
