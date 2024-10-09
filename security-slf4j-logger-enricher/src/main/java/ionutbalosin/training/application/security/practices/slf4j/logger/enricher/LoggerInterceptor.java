/*
 * Application Security for Java Developers
 *
 * Copyright (C) 2024 Ionut Balosin
 * Website: www.ionutbalosin.com
 * X: @ionutbalosin | LinkedIn: ionutbalosin | Mastodon: ionutbalosin@mastodon.social
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
package ionutbalosin.training.application.security.practices.slf4j.logger.enricher;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * This class effectively captures critical information such as the remote host, user ID,
 * correlation ID, HTTP request method, HTTP request URI, user agent, and response status. This
 * information is essential for tracking user actions, identifying potential security issues, and
 * troubleshooting. It stores this data in the Mapped Diagnostic Context (MDC), providing context in
 * log outputs, facilitating traceability, and enhancing the overall observability of the
 * application.
 */
@Component
public class LoggerInterceptor implements HandlerInterceptor {

  private static final String REMOTE_HOST = "RemoteHost";
  private static final String REMOTE_PORT = "RemotePort";
  private static final String USER_ID = "UserId";
  private static final String CORRELATION_ID = "CorrelationId";
  private static final String REQUEST_METHOD = "RequestMethod";
  private static final String REQUEST_URI = "RequestURI";
  private static final String USER_AGENT = "UserAgent";
  private static final String RESPONSE_STATUS = "ResponseStatus";

  @Override
  public boolean preHandle(
      HttpServletRequest request, HttpServletResponse response, Object handler) {
    // Add the remote host
    final String remoteHost = request.getRemoteAddr();
    MDC.put(REMOTE_HOST, remoteHost);

    // Add the remote port
    final String remotePort = String.valueOf(request.getRemotePort());
    MDC.put(REMOTE_PORT, remotePort);

    // Add the user ID
    final String userId =
        (request.getUserPrincipal() != null) ? request.getUserPrincipal().getName() : "anonymous";
    MDC.put(USER_ID, userId);

    // Add the correlation ID
    String correlationId = request.getHeader(CORRELATION_ID);
    if (correlationId == null || correlationId.isEmpty()) {
      correlationId = UUID.randomUUID().toString();
    }
    MDC.put(CORRELATION_ID, correlationId);

    // Add the request method
    String requestMethod = request.getMethod();
    MDC.put(REQUEST_METHOD, requestMethod);

    // Add the HTTP request URI
    String requestURI = request.getRequestURI();
    MDC.put(REQUEST_URI, requestURI);

    // Add the user agent
    String userAgent = request.getHeader("User-Agent");
    MDC.put(USER_AGENT, userAgent != null ? userAgent : "unknown");

    return true;
  }

  @Override
  public void postHandle(
      HttpServletRequest request,
      HttpServletResponse response,
      Object handler,
      org.springframework.web.servlet.ModelAndView modelAndView) {
    // Add the HTTP response status code
    // Note: the status is available after handling
    int status = response.getStatus();
    MDC.put(RESPONSE_STATUS, String.valueOf(status));

    // Clean up the other MDC properties, except for response status
    MDC.remove(REMOTE_HOST);
    MDC.remove(REMOTE_PORT);
    MDC.remove(USER_ID);
    MDC.remove(CORRELATION_ID);
    MDC.remove(REQUEST_METHOD);
    MDC.remove(REQUEST_URI);
  }

  @Override
  public void afterCompletion(
      HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
    // Remove response status from MDC
    MDC.remove(RESPONSE_STATUS);

    // Optionally clear the entire MDC context, but it's not strictly necessary
    // MDC.clear();
  }
}
