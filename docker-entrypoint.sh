#!/usr/bin/env bash
set -euo pipefail

for SECRET in LLDAP_JWT_SECRET LLDAP_LDAP_USER_PASS LLDAP_SMTP_OPTIONS__PASSWORD; do
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

CONFIG_FILE=/data/lldap_config.toml

if [[ ( ! -w "/data" ) ]] || [[ ( ! -d "/data" ) ]]; then
  echo "[entrypoint] The /data folder doesn't exist or cannot be written to. Make sure to mount
  a volume or folder to /data to persist data across restarts, and that the current user can
  write to it."
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Copying the default config to $CONFIG_FILE"
  echo "[entrypoint] Edit this file to configure LLDAP."
  cp /app/lldap_config.docker_template.toml $CONFIG_FILE
fi

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Config file is not readable. Check the permissions"
  exit 1;
fi

echo "> Setup permissions.."
find /app \! -user "$UID" -exec chown "$UID:$GID" '{}' +
find /data \! -user "$UID" -exec chown "$UID:$GID" '{}' +


echo "> Starting lldap.."
echo ""
exec gosu "$UID:$GID" /app/lldap "$@"

exec "$@"
