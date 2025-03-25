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

import feign.Logger;
import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The FeignConfiguration class is responsible for configuring the logging behavior of Feign
 * clients.
 *
 * <p>By default, Feign does not provide logging, so this class enables and customizes it.
 *
 * <p>Feign supports four logging levels:
 *
 * <ul>
 *   <li>NONE: no logging (default)
 *   <li>BASIC: logs the request method, URL, response status code, and execution time
 *   <li>HEADERS: logs the request method, URL, headers, response status code, and execution time
 *   <li>FULL: logs the headers, body, and metadata for both requests and responses
 * </ul>
 *
 * <p>This configuration sets the default logging level to BASIC instead of the default NONE.
 * Additionally, it returns an instance of a custom logger bean, enabling SLF4J-based logging for
 * all Feign requests and responses.
 */
@Configuration
public class FeignConfiguration {

  @Bean
  public Logger.Level feignLoggerLevel(
      @Value("${logging.feignLevel:BASIC}") Logger.Level feignLoggingLevel) {
    return feignLoggingLevel;
  }

  @Bean
  public Logger feignLogger() {
    return new CustomSlf4jLogger();
  }

  @Bean
  public RequestInterceptor correlationIdInterceptor() {
    return new CorrelationIdInterceptor();
  }
}
