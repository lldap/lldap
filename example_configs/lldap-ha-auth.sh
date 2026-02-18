#!/bin/bash

# Usernames should be validated using a regular expression to be of
# a known format. Special characters will be escaped anyway, but it is
# generally not recommended to allow more than necessary.
# This pattern is set by default. In your config file, you can either
# overwrite it with a different one or use "unset USERNAME_PATTERN" to
# disable validation completely.
USERNAME_PATTERN='^[a-z|A-Z|0-9|_|-|.]+$'

# When the timeout (in seconds) is exceeded (e.g. due to slow networking),
# authentication fails.
TIMEOUT=3

# Log messages to stderr.
log() {
	echo "$1" >&2
}

# Get server address
if [ -z "$1" ]; then
	log "Usage: lldap-auth.sh <LLDAP server address> <Optional group to filter>"
	exit 2
fi
SERVER_URL="${1%/}"

# Check username and password are present and not malformed.
if [ -z "$username" ] || [ -z "$password" ]; then
	log "Need username and password environment variables."
	exit 2
elif [ ! -z "$USERNAME_PATTERN" ]; then
	username_match=$(echo "$username" | sed -r "s/$USERNAME_PATTERN/x/")
	if [ "$username_match" != "x" ]; then
		log "Username '$username' has an invalid format."
		exit 2
	fi
fi

RESPONSE=$(curl -f -s -X POST -m "$TIMEOUT" -H "Content-type: application/json" -d '{"username":"'"$username"'","password":"'"$password"'"}' "$SERVER_URL/auth/simple/login")
if [[ $? -ne 0 ]]; then
    log "Auth failed"
    exit 1
fi
TOKEN=$(jq -e -r .token <<< $RESPONSE)
if [[ $? -ne 0 ]]; then
    log "Failed to parse token"
    exit 1
fi

RESPONSE=$(curl -f -s -m "$TIMEOUT" -H "Content-type: application/json" -H "Authorization: Bearer ${TOKEN}" -d '{"variables":{"id":"'"$username"'"},"query":"query($id:String!){user(userId:$id){displayName groups{displayName}}}"}' "$SERVER_URL/api/graphql")
if [[ $? -ne 0 ]]; then
    log "Failed to get user"
    exit 1
fi

USER_JSON=$(jq -e .data.user <<< $RESPONSE)
if [[ $? -ne 0 ]]; then
    log "Failed to parse user json"
    exit 1
fi

if [[ ! -z "$2" ]] && ! jq -e '.groups|map(.displayName)|index("'"$2"'")' <<< $USER_JSON > /dev/null 2>&1; then
	log "User is not in group '$2'"
	exit 1
fi

DISPLAY_NAME=$(jq -r '.displayName // .id' <<< $USER_JSON)

IS_ADMIN=false
if [[ ! -z "$3" ]] && jq -e '.groups|map(.displayName)|index("'"$3"'")' <<< "$USER_JSON" > /dev/null 2>&1; then
    IS_ADMIN=true
fi

IS_LOCAL=false
if [[ ! -z "$4" ]] && jq -e '.groups|map(.displayName)|index("'"$4"'")' <<< "$USER_JSON" > /dev/null 2>&1; then
	IS_LOCAL=true
fi

[[ ! -z "$DISPLAY_NAME" ]] && echo "name = $DISPLAY_NAME"

if [[ "$IS_ADMIN" = true ]]; then
	echo "group = system-admin"
else
    echo "group = system-users"
fi

if [[ "$IS_LOCAL" = true ]]; then
	echo "local_only = true"
else
    echo "local_only = false"
fi
