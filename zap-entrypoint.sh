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

# This script implicitly scans the 'pizza-order-service' microservice.
# TODO: To scan a different microservice, please update the TARGET_URL below.
TARGET_URL=${TARGET_URL:-http://pizza-order-service.local:8080/public/v3/api-docs/swagger-config}

echo "🔍 Starting the ZAP API scan against target: [$TARGET_URL] ..."
zap-api-scan.py -I -t $TARGET_URL -f openapi -r zap-report.html -c zap-api-scan-rules.conf
SCAN_STATUS=$?

echo "The ZAP API scan finished with status [$SCAN_STATUS]"

echo "Copying ZAP API scan report to host machine under /zap/reports/"
cp /zap/wrk/zap-report.html /zap/reports/

exit $SCAN_STATUS