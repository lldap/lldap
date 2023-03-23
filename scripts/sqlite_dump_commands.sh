#! /bin/bash

tables=("users" "groups" "memberships" "jwt_refresh_storage" "jwt_storage" "password_reset_tokens")
echo ".header on"

for table in ${tables[@]}; do
    echo ".mode insert $table"
    echo "select * from $table;"
done