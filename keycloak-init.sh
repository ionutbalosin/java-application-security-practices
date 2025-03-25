#!/bin/bash
#
# Application Security for Java Developers
#
# Copyright (C) 2025 Ionut Balosin
# Website: www.ionutbalosin.com
# Social Media:
#   LinkedIn: ionutbalosin
#   Bluesky: @ionutbalosin.bsky.social
#   X: @ionutbalosin
#   Mastodon: ionutbalosin@mastodon.social
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

# Keycloak REST API docs
# - https://www.keycloak.org/docs-api/latest/rest-api/index.html

check_keycloak_initial_request() {
  # Set the timeout threshold (in seconds)
  delay=3
  timeout=30
  end_time=$((SECONDS + timeout))

  echo "Checking if Keycloak has started for realm [$REALM] ..."
  while true; do
    # Get the HTTP status code
    http_code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/realms/$REALM")

    # Check if the HTTP code is 200
    if [ "$http_code" -eq 200 ]; then
      echo "Keycloak is fully started and ready to accept requests."
      return 0
    else
      echo "Keycloak is not ready. Retrying in $delay seconds ..."
    fi

    # Check if the timeout has been reached
    if [ $SECONDS -ge $end_time ]; then
      echo "ERROR: Keycloak did not respond within $timeout seconds (timeout)."
      return 1
    fi

    sleep $delay
  done
}

retrieve_admin_token() {
  echo ""
  echo "Retrieving the access token for administrative operations for realm [$REALM] ..."
  ACCESS_TOKEN=$(curl -s -X POST "http://localhost:$PORT/realms/$REALM/protocol/openid-connect/token" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -d "client_id=admin-cli" \
       -d "username=admin" \
       -d "password=admin" \
       -d "grant_type=password" | jq -r .access_token)
  echo "Access Token: $ACCESS_TOKEN"
}

modify_token_lifespan() {
  echo ""
  echo "Modifying the access and refresh tokens lifespan for realm [$REALM] ..."
  RESPONSE=$(curl -s -X PUT "http://localhost:$PORT/admin/realms/$REALM" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"accessTokenLifespan\": 900,
        \"ssoSessionIdleTimeout\": 3600,
        \"ssoSessionMaxLifespan\": 28800
      }")
  echo "Response: ${RESPONSE:-👍}"
}

create_client() {
  CLIENT="$1"
  SECRET="$2"
  IS_PUBLIC="$3"
  IS_ACCOUNT_ENABLED="$4"

  echo ""
  echo "Creating client [$CLIENT] ..."
  RESPONSE=$(curl -s -X POST http://localhost:$PORT/realms/$REALM/clients-registrations/default \
      -H "Content-Type:application/json" \
      -H "Authorization: bearer $ACCESS_TOKEN" \
      -d "{
  	        \"clientId\": \"$CLIENT\",
  	        \"name\": \"$CLIENT name\",
  	        \"description\": \"$CLIENT description\",
      	    \"publicClient\": $IS_PUBLIC,
            \"secret\": \"$SECRET\",
  	        \"enabled\": true,
       	    \"protocol\": \"openid-connect\",
   		      \"consentRequired\": false,
            \"redirectUris\": [\"https://oauth.pstmn.io/v1/callback\"],
            \"serviceAccountsEnabled\": $IS_ACCOUNT_ENABLED,
            \"implicitFlowEnabled\": true
          }")
  echo "Response: ${RESPONSE:-👍}"
}

create_user() {
  USER="$1"
  EMAIL="$2"
  PASSWORD="$3"

  echo ""
  echo "Creating user [$USER] ..."
  RESPONSE=$(curl -s -X POST "http://localhost:$PORT/admin/realms/$REALM/users" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
          \"username\": \"$USER\",
          \"enabled\": true,
          \"email\": \"$EMAIL\",
          \"emailVerified\": true,
          \"firstName\": \"$USER firstName\",
          \"lastName\": \"$USER lastName\",
          \"credentials\": [
              {
                  \"type\": \"password\",
                  \"value\": \"$PASSWORD\",
                  \"temporary\": false
              }
          ]
      }")
  echo "Response: ${RESPONSE:-👍}"
}

create_role() {
  ROLE="$1"

  echo ""
  echo "Creating role [$ROLE] ..."
  RESPONSE=$(curl -s -X POST "http://localhost:$PORT/admin/realms/$REALM/roles" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
          \"name\": \"$ROLE\",
          \"description\": \"$ROLE description\"
      }")
  echo "Response: ${RESPONSE:-👍}"
}

assign_role_to_user() {
  ROLE="$1"
  USER="$2"

  echo ""
  echo "Getting the user Id for the user [$USER] ..."
  USER_ID=$(curl -s -X GET "http://localhost:$PORT/admin/realms/$REALM/users?username=$USER" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.[0].id')
  echo "User Id: $USER_ID"

  echo "Getting the role Id for the role [$ROLE] ..."
  ROLE_ID=$(curl -s -X GET "http://localhost:$PORT/admin/realms/$REALM/roles/$ROLE" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.id')
  echo "Role Id: $ROLE_ID"

  echo "Assigning role ID [$ROLE_ID] to user Id [$USER_ID] ..."
  RESPONSE=$(curl -s -X POST "http://localhost:$PORT/admin/realms/$REALM/users/$USER_ID/role-mappings/realm" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "[
          {
            \"id\": \"$ROLE_ID\",
            \"name\": \"$ROLE\"
          }
      ]")
  echo "Response: ${RESPONSE:-👍}"
}

assign_role_to_client() {
  ROLE="$1"
  CLIENT="$2"

  echo ""
  echo "Getting the client Id for the client [$CLIENT] ..."
  CLIENT_ID=$(curl -s -X GET "http://localhost:$PORT/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" | \
  jq -r --arg CLIENT "$CLIENT" '.[] | select(.clientId == $CLIENT) | .id')
  echo "Client Id: $CLIENT_ID"

  echo "Getting the role Id for the role [$ROLE] ..."
  ROLE_ID=$(curl -s -X GET "http://localhost:$PORT/admin/realms/$REALM/roles/$ROLE" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.id')
  echo "Role Id: $ROLE_ID"

  echo "Assigning role Id [$ROLE_ID] to client Id [$CLIENT_ID] ..."
  RESPONSE=$(curl -s -X POST "http://localhost:$PORT/admin/realms/$REALM/clients/$CLIENT_ID/roles" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
            \"id\": \"$ROLE_ID\",
            \"name\": \"$ROLE\"
      }")
  echo "Response: ${RESPONSE:-👍}"
}

# Assign a specified role to the service account of a given client.
# The assigned role will be included in the JWT token for that client service account.
# Note: Assigning the role only to the client (and not to its service account) will limit the role's functionality
# to normal users logging in with a password.
# For more details, see: https://github.com/keycloak/keycloak/discussions/30429
assign_role_to_client_service_account() {
  ROLE="$1"
  CLIENT="$2"

  echo ""
  echo "Getting the client Id for the client [$CLIENT] ..."
  CLIENT_ID=$(curl -s -X GET "http://localhost:$PORT/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" | \
  jq -r --arg CLIENT "$CLIENT" '.[] | select(.clientId == $CLIENT) | .id')
  echo "Client Id: $CLIENT_ID"

  echo "Getting the Service Account Id for the client Id [$CLIENT_ID] ..."
  SERVICE_ACCOUNT_ID=$(curl -s -X GET "http://localhost:$PORT/admin/realms/$REALM/clients/$CLIENT_ID/service-account-user" \
       -H "Authorization: Bearer $ACCESS_TOKEN" \
       -H "Content-Type: application/json" | jq -r '.id')
  echo "Service Account Id: $SERVICE_ACCOUNT_ID"

  echo "Getting the role Id for the client Id [$CLIENT_ID] ..."
  ROLE_ID=$(curl -s -X GET "http://localhost:$PORT/admin/realms/$REALM/clients/$CLIENT_ID/roles" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.[0].id')
  echo "Role Id: $ROLE_ID"

  echo "Assigning role Id [$ROLE_ID] to service account Id [$CLIENT_ID] ..."
  RESPONSE=$(curl -s -X POST "http://localhost:$PORT/admin/realms/$REALM/users/$SERVICE_ACCOUNT_ID/role-mappings/clients/$CLIENT_ID" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "[{
          \"id\": \"$ROLE_ID\",
          \"name\": \"$ROLE\"
      }]")
  echo "Response: ${RESPONSE:-👍}"
}

# Script properties used across all script commands
REALM="master"
PORT="9090"

echo
echo "*********************************************"
echo "* Initialize Keycloak with default settings *"
echo "*********************************************"
echo

check_keycloak_initial_request || exit 1

retrieve_admin_token
modify_token_lifespan

create_client "demo_public_client" "6EuUNXQzFmxu6xwPHDvvoh56z1uzrBMw" "true" "false"

create_user "demo_user" "demo_user@keycloak.com" "Test1234!"
create_role "demo_user_role"
assign_role_to_user "demo_user_role" "demo_user"

create_client "demo_private_client" "6EuUNXQzFmxu6xwPHDvvoh56z1uzrBMw" "false" "true"
create_role "demo_private_client_role"
assign_role_to_client "demo_private_client_role" "demo_private_client"
assign_role_to_client_service_account "demo_private_client_role" "demo_private_client"

echo ""
echo "🎉 Congratulations! Everything was successful."