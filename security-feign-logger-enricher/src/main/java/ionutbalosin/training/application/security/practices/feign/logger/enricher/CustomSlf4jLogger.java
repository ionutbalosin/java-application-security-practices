/*
 * Application Security for Java Developers
 *
 * Copyright (C) 2025 Ionut Balosin
 * Website: www.ionutbalosin.com
 * Social Media:
 *   LinkedIn: ionutbalosin
 *   Bluesky: @ionutbalosin.bsky.social
 *   X: @ionutbalosin
 *   Mastodon: ionutbalosin@mastodon.social
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package ionutbalosin.training.application.security.practices.feign.logger.enricher;

import feign.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides enhanced logging capabilities using SLF4J, allowing for customized logging of
 * Feign requests and responses while maintaining a consistent format.
 *
 * <p>This logger captures requests and logs them at the INFO level, enabling effective tracking and
 * analysis of interactions with external services.
 */
public class CustomSlf4jLogger extends feign.Logger {

  private final Logger logger;

  public CustomSlf4jLogger(Class<?> clazz) {
    this(LoggerFactory.getLogger(clazz));
  }

  public CustomSlf4jLogger() {
    this(feign.Logger.class);
  }

  private CustomSlf4jLogger(Logger logger) {
    this.logger = logger;
  }

  @Override
  protected void logRequest(String configKey, Level logLevel, Request request) {
    super.logRequest(configKey, logLevel, request);
  }

  @Override
  protected void log(String configKey, String format, Object... args) {
    logger.info(String.format(methodTag(configKey) + format, args));
  }
}
