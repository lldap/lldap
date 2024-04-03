#!/usr/bin/env bash

set -e
set -o pipefail

LLDAP_URL="${LLDAP_URL}"
LLDAP_ADMIN_USERNAME="${LLDAP_ADMIN_USERNAME}"
LLDAP_ADMIN_PASSWORD="${LLDAP_ADMIN_PASSWORD}"
USER_CONFIGS_DIR="${USER_CONFIGS_DIR:-/user-configs}"
GROUP_CONFIGS_DIR="${GROUP_CONFIGS_DIR:-/group-configs}"
LLDAP_SET_PASSWORD_PATH="${LLDAP_SET_PASSWORD_PATH:-/app/lldap_set_password}"
DO_CLEANUP="${DO_CLEANUP:-false}"

check_install_dependencies() {
  local commands=('curl' 'jq' 'jo')
  local commands_not_found='false'

  if ! hash "${commands[@]}" 2>/dev/null; then
    if hash 'apk' 2>/dev/null && [[ $EUID -eq 0 ]]; then
      apk add "${commands[@]}"
    elif hash 'apt' 2>/dev/null && [[ $EUID -eq 0 ]]; then
      apt update -yqq
      apt install -yqq "${commands[@]}"
    else
      local command=''
      for command in "${commands[@]}"; do
        if ! hash "$command" 2>/dev/null; then
          printf 'Command not found "%s"\n' "$command"
        fi
      done
      commands_not_found='true'
    fi
  fi

  if [[ "$commands_not_found" == 'true' ]]; then
    return 1
  fi
}

check_required_env_vars() {
  local env_var_not_specified='false'
  local dual_env_vars_list=(
    'LLDAP_URL'
    'LLDAP_ADMIN_USERNAME'
    'LLDAP_ADMIN_PASSWORD'
  )

  local dual_env_var_name=''
  for dual_env_var_name in "${dual_env_vars_list[@]}"; do
    local dual_env_var_file_name="${dual_env_var_name}_FILE"

    if [[ -z "${!dual_env_var_name}" ]] && [[ -z "${!dual_env_var_file_name}" ]]; then
      printf 'Please specify "%s" or "%s" variable!\n' "$dual_env_var_name" "$dual_env_var_file_name" >&2
      env_var_not_specified='true'
    else
      if [[ -n "${!dual_env_var_file_name}" ]]; then
        declare -g "$dual_env_var_name"="$(cat "${!dual_env_var_file_name}")"
      fi
    fi
  done

  if [[ "$env_var_not_specified" == 'true' ]]; then
    return 1
  fi
}

check_configs_validity() {
  local config_file='' config_invalid='false'
  for config_file in "$@"; do
    local error=''
    if ! error="$(jq '.' -- "$config_file" 2>&1 >/dev/null)"; then
      printf '%s: %s\n' "$config_file" "$error"
      config_invalid='true'
    fi
  done

  if [[ "$config_invalid" == 'true' ]]; then
    return 1
  fi
}

auth() {
  local url="$1" admin_username="$2" admin_password="$3"

  local response
  response="$(curl --silent --request POST \
    --url "$url/auth/simple/login" \
    --header 'Content-Type: application/json' \
    --data "$(jo -- username="$admin_username" password="$admin_password")")"

  TOKEN="$(printf '%s' "$response" | jq --raw-output .token)"
}

make_query() {
  local query_file="$1" variables_file="$2"

  curl --silent --request POST \
    --url "$LLDAP_URL/api/graphql" \
    --header "Authorization: Bearer $TOKEN" \
    --header 'Content-Type: application/json' \
    --data @<(jq --slurpfile variables "$variables_file" '. + {"variables": $variables[0]}' "$query_file")
}

get_group_list() {
  local query='{"query":"query GetGroupList {groups {id displayName}}","operationName":"GetGroupList"}'
  make_query <(printf '%s' "$query") <(printf '{}')
}

get_group_array() {
  get_group_list | jq --raw-output '.data.groups[].displayName'
}

group_exists() {
  if [[ "$(get_group_list | jq --raw-output --arg displayName "$1" '.data.groups | any(.[]; select(.displayName == $displayName))')" == 'true' ]]; then
    return 0
  else
    return 1
  fi
}

get_group_id() {
  get_group_list | jq --raw-output --arg displayName "$1" '.data.groups[] | if .displayName == $displayName then .id else empty end'
}

create_group() {
  local group_name="$1"

  if group_exists "$group_name"; then
    printf 'Group "%s" (%s) already exists\n' "$group_name" "$(get_group_id "$group_name")"
    return
  fi

  # shellcheck disable=SC2016
  local query='{"query":"mutation CreateGroup($name: String!) {createGroup(name: $name) {id displayName}}","operationName":"CreateGroup"}'

  local response='' error=''
  response="$(make_query <(printf '%s' "$query") <(jo -- name="$group_name"))"
  error="$(printf '%s' "$response" | jq --raw-output '.errors | if . != null then .[].message else empty end')"
  if [[ -n "$error" ]]; then
    printf '%s\n' "$error"
  else
    printf 'Group "%s" (%s) successfully created\n' "$group_name" "$(printf '%s' "$response" | jq --raw-output '.data.createGroup.id')"
  fi
}

delete_group() {
  local group_name="$1" id=''

  if ! group_exists "$group_name"; then
    printf '[WARNING] Group "%s" does not exist\n' "$group_name"
    return
  fi

  id="$(get_group_id "$group_name")"

  # shellcheck disable=SC2016
  local query='{"query":"mutation DeleteGroupQuery($groupId: Int!) {deleteGroup(groupId: $groupId) {ok}}","operationName":"DeleteGroupQuery"}'

  local response='' error=''
  response="$(make_query <(printf '%s' "$query") <(jo -- groupId="$id"))"
  error="$(printf '%s' "$response" | jq --raw-output '.errors | if . != null then .[].message else empty end')"
  if [[ -n "$error" ]]; then
    printf '%s\n' "$error"
  else
    printf 'Group "%s" (%s) successfully deleted\n' "$group_name" "$id"
  fi
}

get_user_details() {
  local id="$1"

  # shellcheck disable=SC2016
  local query='{"query":"query GetUserDetails($id: String!) {user(userId: $id) {id email displayName firstName lastName creationDate uuid groups {id displayName}}}","operationName":"GetUserDetails"}'
  make_query <(printf '%s' "$query") <(jo -- id="$id")
}

user_in_group() {
  local user_id="$1" group_name="$2"

  if ! group_exists "$group_name"; then
    printf '[WARNING] Group "%s" does not exist\n' "$group_name"
    return
  fi

  if ! user_exists "$user_id"; then
    printf 'User "%s" is not exists\n' "$user_id"
    return
  fi

  if [[ "$(get_user_details "$user_id" | jq --raw-output --arg displayName "$group_name" '.data.user.groups | any(.[]; select(.displayName == $displayName))')" == 'true' ]]; then
    return 0
  else
    return 1
  fi
}

add_user_to_group() {
  local user_id="$1" group_name="$2" group_id=''

  if ! group_exists "$group_name"; then
    printf '[WARNING] Group "%s" does not exist\n' "$group_name"
    return
  fi

  group_id="$(get_group_id "$group_name")"

  if user_in_group "$user_id" "$group_name"; then
    printf 'User "%s" already in group "%s" (%s)\n' "$user_id" "$group_name" "$group_id"
    return
  fi

  # shellcheck disable=SC2016
  local query='{"query":"mutation AddUserToGroup($user: String!, $group: Int!) {addUserToGroup(userId: $user, groupId: $group) {ok}}","operationName":"AddUserToGroup"}'

  local response='' error=''
  response="$(make_query <(printf '%s' "$query") <(jo -- user="$user_id" group="$group_id"))"
  error="$(printf '%s' "$response" | jq '.errors | if . != null then .[].message else empty end')"
  if [[ -n "$error" ]]; then
    printf '%s\n' "$error"
  else
    printf 'User "%s" successfully added to the group "%s" (%s)\n' "$user_id" "$group_name" "$group_id"
  fi
}

remove_user_from_group() {
  local user_id="$1" group_name="$2" group_id=''

  if ! group_exists "$group_name"; then
    printf '[WARNING] Group "%s" does not exist\n' "$group_name"
    return
  fi

  group_id="$(get_group_id "$group_name")"

  # shellcheck disable=SC2016
  local query='{"operationName":"RemoveUserFromGroup","query":"mutation RemoveUserFromGroup($user: String!, $group: Int!) {removeUserFromGroup(userId: $user, groupId: $group) {ok}}"}'

  local response='' error=''
  response="$(make_query <(printf '%s' "$query") <(jo -- user="$user_id" group="$group_id"))"
  error="$(printf '%s' "$response" | jq '.errors | if . != null then .[].message else empty end')"
  if [[ -n "$error" ]]; then
    printf '%s\n' "$error"
  else
    printf 'User "%s" successfully removed from the group "%s" (%s)\n' "$user_id" "$group_name" "$group_id"
  fi
}

get_users_list() {
  # shellcheck disable=SC2016
  local query='{"query": "query ListUsersQuery($filters: RequestFilter) {users(filters: $filters) {id email displayName firstName lastName creationDate}}","operationName": "ListUsersQuery"}'
  make_query <(printf '%s' "$query") <(jo -- filters=null)
}

user_exists() {
  if [[ "$(get_users_list | jq --raw-output --arg id "$1" '.data.users | any(.[]; contains({"id": $id}))')" == 'true' ]]; then
    return 0
  else
    return 1
  fi
}

delete_user() {
  local id="$1"

  if ! user_exists "$id"; then
    printf 'User "%s" is not exists\n' "$id"
    return
  fi

  # shellcheck disable=SC2016
  local query='{"query": "mutation DeleteUserQuery($user: String!) {deleteUser(userId: $user) {ok}}","operationName": "DeleteUserQuery"}'

  local response='' error=''
  response="$(make_query <(printf '%s' "$query") <(jo -- user="$id"))"
  error="$(printf '%s' "$response" | jq --raw-output '.errors | if . != null then .[].message else empty end')"
  if [[ -n "$error" ]]; then
    printf '%s\n' "$error"
  else
    printf 'User "%s" successfully deleted\n' "$id"
  fi
}

__common_user_mutation_query() {
  local \
    query="$1" \
    id="${2:-null}" \
    email="${3:-null}" \
    displayName="${4:-null}" \
    firstName="${5:-null}" \
    lastName="${6:-null}" \
    avatar_file="${7:-null}" \
    avatar_url="${8:-null}" \
    gravatar_avatar="${9:-false}" \
    weserv_avatar="${10:-false}"

  local variables_arr=(
    '-s' "id=$id"
    '-s' "email=$email"
    '-s' "displayName=$displayName"
    '-s' "firstName=$firstName"
    '-s' "lastName=$lastName"
  )

  local temp_avatar_file=''

  if [[ "$gravatar_avatar" == 'true' ]]; then
    avatar_url="https://gravatar.com/avatar/$(printf '%s' "$email" | sha256sum | cut -d ' ' -f 1)?size=512"
  fi

  if [[ "$avatar_url" != 'null' ]]; then
    temp_avatar_file="${TMP_AVATAR_DIR}/$(printf '%s' "$avatar_url" | md5sum | cut -d ' ' -f 1)"

    if ! [[ -f "$temp_avatar_file" ]]; then
      if [[ "$weserv_avatar" == 'true' ]]; then
        avatar_url="https://wsrv.nl/?url=$avatar_url&output=jpg"
      fi
      curl --silent --location --output "$temp_avatar_file" "$avatar_url"
    fi

    avatar_file="$temp_avatar_file"
  fi

  if [[ "$avatar_file" == 'null' ]]; then
    variables_arr+=('-s' 'avatar=null')
  else
    variables_arr+=("avatar=%$avatar_file")
  fi

  make_query <(printf '%s' "$query") <(jo -- user=:<(jo -- "${variables_arr[@]}"))
}

create_user() {
  local id="$1"

  if user_exists "$id"; then
    printf 'User "%s" already exists\n' "$id"
    return
  fi

  # shellcheck disable=SC2016
  local query='{"query":"mutation CreateUser($user: CreateUserInput!) {createUser(user: $user) {id creationDate}}","operationName":"CreateUser"}'

  local response='' error=''
  response="$(__common_user_mutation_query "$query" "$@")"
  error="$(printf '%s' "$response" | jq --raw-output '.errors | if . != null then .[].message else empty end')"
  if [[ -n "$error" ]]; then
    printf '%s\n' "$error"
  else
    printf 'User "%s" successfully created\n' "$id"
  fi
}

update_user() {
  local id="$1"

  if ! user_exists "$id"; then
    printf 'User "%s" is not exists\n' "$id"
    return
  fi

  # shellcheck disable=SC2016
  local query='{"query":"mutation UpdateUser($user: UpdateUserInput!) {updateUser(user: $user) {ok}}","operationName":"UpdateUser"}'

  local response='' error=''
  response="$(__common_user_mutation_query "$query" "$@")"
  error="$(printf '%s' "$response" | jq --raw-output '.errors | if . != null then .[].message else empty end')"
  if [[ -n "$error" ]]; then
    printf '%s\n' "$error"
  else
    printf 'User "%s" successfully updated\n' "$id"
  fi
}

create_update_user() {
  local id="$1"

  if user_exists "$id"; then
    update_user "$@"
  else
    create_user "$@"
  fi
}

main() {
  check_install_dependencies
  check_required_env_vars

  local user_config_files=("${USER_CONFIGS_DIR}"/*.json)
  local group_config_files=("${GROUP_CONFIGS_DIR}"/*.json)

  if ! check_configs_validity "${group_config_files[@]}" "${user_config_files[@]}"; then
    exit 1
  fi

  until curl --silent -o /dev/null "$LLDAP_URL"; do
    printf 'Waiting lldap to start...\n'
    sleep 10
  done

  auth "$LLDAP_URL" "$LLDAP_ADMIN_USERNAME" "$LLDAP_ADMIN_PASSWORD"

  local redundant_groups=''
  redundant_groups="$(get_group_list | jq '[ .data.groups[].displayName ]' | jq --compact-output '. - ["lldap_admin","lldap_password_manager","lldap_strict_readonly"]')"

  printf -- '\n--- groups ---\n'
  local group_config=''
  while read -r group_config; do
    local group_name=''
    group_name="$(printf '%s' "$group_config" | jq --raw-output '.name')"
    create_group "$group_name"
    redundant_groups="$(printf '%s' "$redundant_groups" | jq --compact-output --arg name "$group_name" '. - [$name]')"
  done < <(jq --compact-output '.' -- "${group_config_files[@]}")
  printf -- '--- groups ---\n'

  printf -- '\n--- redundant groups ---\n'
  if [[ "$redundant_groups" == '[]' ]]; then
    printf 'There are no redundant groups\n'
  else
    local group_name=''
    while read -r group_name; do
      if [[ "$DO_CLEANUP" == 'true' ]]; then
        delete_group "$group_name"
      else
        printf '[WARNING] Group "%s" is not declared in config files\n' "$group_name"
      fi
    done < <(printf '%s' "$redundant_groups" | jq --raw-output '.[]')
  fi
  printf -- '--- redundant groups ---\n'

  local redundant_users=''
  redundant_users="$(get_users_list | jq '[ .data.users[].id ]' | jq --compact-output --arg admin_id "$LLDAP_ADMIN_USERNAME" '. - [$admin_id]')"

  TMP_AVATAR_DIR="$(mktemp -d)"

  local user_config=''
  while read -r user_config; do
    local field='' id='' email='' displayName='' firstName='' lastName='' avatar_file='' avatar_url='' gravatar_avatar='' weserv_avatar='' password=''
    for field in 'id' 'email' 'displayName' 'firstName' 'lastName' 'avatar_file' 'avatar_url' 'gravatar_avatar' 'weserv_avatar' 'password'; do
      declare "$field"="$(printf '%s' "$user_config" | jq --raw-output --arg field "$field" '.[$field]')"
    done
    printf -- '\n--- %s ---\n' "$id"

    create_update_user "$id" "$email" "$displayName" "$firstName" "$lastName" "$avatar_file" "$avatar_url" "$gravatar_avatar" "$weserv_avatar"
    redundant_users="$(printf '%s' "$redundant_users" | jq --compact-output --arg id "$id" '. - [$id]')"

    if [[ "$password" != 'null' ]] && [[ "$password" != '""' ]]; then
      "$LLDAP_SET_PASSWORD_PATH" --base-url "$LLDAP_URL" --token "$TOKEN" --username "$id" --password "$password"
    fi

    local redundant_user_groups=''
    redundant_user_groups="$(get_user_details "$id" | jq '[ .data.user.groups[].displayName ]')"

    local group=''
    while read -r group; do
      if [[ -n "$group" ]]; then
        add_user_to_group "$id" "$group"
        redundant_user_groups="$(printf '%s' "$redundant_user_groups" | jq --compact-output --arg group "$group" '. - [$group]')"
      fi
    done < <(printf '%s' "$user_config" | jq --raw-output '.groups | if . == null then "" else .[] end')

    local user_group_name=''
    while read -r user_group_name; do
      if [[ "$DO_CLEANUP" == 'true' ]]; then
        remove_user_from_group "$id" "$user_group_name"
      else
        printf '[WARNING] User "%s" is not declared as member of the "%s" group in the config files\n' "$id" "$user_group_name"
      fi
    done < <(printf '%s' "$redundant_user_groups" | jq --raw-output '.[]')
    printf -- '--- %s ---\n' "$id"
  done < <(jq --compact-output '.' -- "${user_config_files[@]}")

  rm -r "$TMP_AVATAR_DIR"

  printf -- '\n--- redundant users ---\n'
  if [[ "$redundant_users" == '[]' ]]; then
    printf 'There are no redundant users\n'
  else
    local id=''
    while read -r id; do
      if [[ "$DO_CLEANUP" == 'true' ]]; then
        delete_user "$id"
      else
        printf '[WARNING] User "%s" is not declared in config files\n' "$id"
      fi
    done < <(printf '%s' "$redundant_users" | jq --raw-output '.[]')
  fi
  printf -- '--- redundant users ---\n'
}

main "$@"
