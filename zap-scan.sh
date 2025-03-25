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

# Script properties used across all script commands
DOCKER_NETWORK="security-practices"
ZAPROXY_CONTAINER="zaproxy-zap.local"
ZAPROXY_IMAGE="zaproxy-zap:local"

echo ""
echo "**********************************"
echo "* Start ZAP scanning with Docker *"
echo "**********************************"
echo ""

# Check if Docker network exists
echo "Checking if Docker network [$DOCKER_NETWORK] exists ..."
docker network inspect $DOCKER_NETWORK > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Docker network [$DOCKER_NETWORK] does not exist."
    echo "Please ensure the other services have started (e.g., $ ./bootstrap.sh)."
    exit 1
fi

# Build the ZAP Docker image
echo "Building the ZAP Docker image [$ZAPROXY_IMAGE] ..."
docker build -t $ZAPROXY_IMAGE -f Dockerfile-zap .
if [ $? -ne 0 ]; then
    echo "Building the ZAP Docker image [$ZAPROXY_IMAGE] failed."
    exit 1
fi

# Check if the ZAP container already exists and remove it if necessary
docker ps -a --filter "name=$ZAPROXY_CONTAINER" --format "{{.Names}}" | grep -w $ZAPROXY_CONTAINER > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Removing existing ZAP container [$ZAPROXY_CONTAINER] ..."
    docker rm -f $ZAPROXY_CONTAINER
fi

# Run the ZAP container
echo "Running ZAP container [$ZAPROXY_CONTAINER] ..."
docker run -d \
    --name $ZAPROXY_CONTAINER \
    -p 17070:7070 -p 17080:7080 \
    --network $DOCKER_NETWORK \
    -v $(pwd)/zap/reports:/zap/reports \
    $ZAPROXY_IMAGE
if [ $? -ne 0 ]; then
    echo "Failed to run the ZAP container [$ZAPROXY_CONTAINER]."
    exit 1
fi

echo ""
echo "🎉 Congratulations! Everything was successful."
echo "Please check the '$(pwd)/zap/reports' folder 📂 for the HTML report."
