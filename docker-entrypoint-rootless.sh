#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/data/lldap_config.toml

if [ ! -f "$CONFIG_FILE" ]; then
  echo "[entrypoint] Copying the default config to $CONFIG_FILE"
  echo "[entrypoint] Edit this $CONFIG_FILE to configure LLDAP."
  if cp /app/lldap_config.docker_template.toml $CONFIG_FILE; then
     echo "Configuration copied successfully."
  else
     echo "Fail to copy configuration, check permission on /data or manually create one by copying from LLDAP repository"
     exit 1
  fi
fi

echo "> Starting lldap.."
echo ""
exec /app/lldap "$@"
exec "$@"
