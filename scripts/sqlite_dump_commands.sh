#! /bin/bash

tables=("users" "groups" "memberships" "jwt_refresh_storage" "jwt_storage" "password_reset_tokens" "group_attribute_schema" "group_attributes")
echo ".header on"

for table in ${tables[@]}; do
    echo ".mode insert $table"
    echo "select * from $table;"
done

echo ".mode insert user_attribute_schema"
echo "select * from user_attribute_schema where user_attribute_schema_name not in ('first_name', 'last_name', 'avatar');"

echo ".mode insert user_attributes"
echo "select * from user_attributes;"
