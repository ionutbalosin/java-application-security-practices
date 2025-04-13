/*
 * Application Security for Java Developers
 *
 * Copyright (C) 2025 Ionut Balosin
 * Website:      www.ionutbalosin.com
 * Social Media:
 *   LinkedIn:   ionutbalosin
 *   Bluesky:    @ionutbalosin.bsky.social
 *   X:          @ionutbalosin
 *   Mastodon:   ionutbalosin@mastodon.social
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

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

/**
 * This class adds the CorrelationId from the MDC (Mapped Diagnostic Context) to the headers of
 * outgoing Feign requests.
 *
 * <p>This ensures that the CorrelationId is propagated across other microservice calls, allowing
 * for better tracing and debugging of requests throughout the application.
 */
@Component
public class CorrelationIdInterceptor implements RequestInterceptor {

  private static final String CORRELATION_ID = "CorrelationId";

  @Override
  public void apply(RequestTemplate template) {
    final String correlationId = MDC.get(CORRELATION_ID);
    if (correlationId != null) {
      template.header(CORRELATION_ID, correlationId);
    }
  }
}
