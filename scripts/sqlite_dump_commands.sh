#! /bin/bash

tables=("users" "groups" "memberships" "jwt_refresh_storage" "jwt_storage" "password_reset_tokens" "group_attribute_schema" "group_attributes" "user_attribute_schema" "user_attributes")
echo ".header on"

for table in ${tables[@]}; do
    echo ".mode insert $table"
    echo "select * from $table;"
done
