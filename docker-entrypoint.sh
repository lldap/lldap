#!/usr/bin/env bash
set -euo pipefail

for SECRET in LLDAP_JWT_SECRET LLDAP_LDAP_USER_PASS; do
    FILE_VAR="${SECRET}_FILE"
    SECRET_FILE="${!FILE_VAR:-}"
    if [[ -n "$SECRET_FILE" ]]; then
        if [[ -f "$SECRET_FILE" ]]; then
            declare "$SECRET=$(cat $SECRET_FILE)"
            export "$SECRET"
            echo "[entrypoint] Set $SECRET from $SECRET_FILE"
        else
            echo "[entrypoint] Could not read contents of $SECRET_FILE (specified in $FILE_VAR)" >&2
        fi
    fi
done

exec /app/lldap "$@"
