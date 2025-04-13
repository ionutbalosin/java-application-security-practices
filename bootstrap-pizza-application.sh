#!/bin/bash
#
# Application Security for Java Developers
#
# Copyright (C) 2025 Ionut Balosin
# Website:      www.ionutbalosin.com
# Social Media:
#   LinkedIn:   ionutbalosin
#   Bluesky:    @ionutbalosin.bsky.social
#   X:          @ionutbalosin
#   Mastodon:   ionutbalosin@mastodon.social
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

echo ""
echo "******************************************************"
echo "* [1/3] Compile and package all Spring Boot services *"
echo "******************************************************"
echo ""

BASE_DIR="${PWD}"

if ! ./mvnw package -DskipTests; then
    echo ""
    echo "ERROR: Maven encountered errors and cannot continue."
    exit 1
fi

echo ""
echo "**********************************************************"
echo "* [2/3] Build Docker images for all Spring Boot services *"
echo "**********************************************************"
echo ""

cd ./pizza-order-service
./build-docker.sh || exit 1
cd "${BASE_DIR}"

cd ./pizza-cooking-service
./build-docker.sh || exit 1
cd "${BASE_DIR}"

cd ./pizza-delivery-service
./build-docker.sh || exit 1
cd "${BASE_DIR}"

echo ""
echo "***************************************************"
echo "* [3/3] Start all Spring Boot services with Docker *"
echo "***************************************************"
echo ""

docker compose -f ./docker-compose-pizza-application.yml \
               up -d
if [ $? -ne 0 ]; then
    echo "Error: Docker services failed to start."
    exit 1
fi

echo ""
echo "🎉 Congratulations! Everything was successful."