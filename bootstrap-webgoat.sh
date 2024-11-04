#!/bin/bash
#
# Application Security for Java Developers
#
# Copyright (C) 2024 Ionut Balosin
# Website: www.ionutbalosin.com
# X: @ionutbalosin | LinkedIn: ionutbalosin | Mastodon: ionutbalosin@mastodon.social
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
echo "***********************************"
echo "* Start OWASP WebGoat with Docker *"
echo "***********************************"
echo ""

docker compose -f ./docker-compose-webgoat.yml \
               up -d
if [ $? -ne 0 ]; then
    echo "Error: Docker services failed to start."
    exit 1
fi

echo ""
echo "🎉 Congratulations! Everything was successful."