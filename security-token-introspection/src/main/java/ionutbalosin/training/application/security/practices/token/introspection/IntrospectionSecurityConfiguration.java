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
package ionutbalosin.training.application.security.practices.token.introspection;

import static java.util.Arrays.asList;

import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * References:
 *
 * <ul>
 *   <li><a
 *       href="https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html">Security
 *       HTTP Response Headers</a>
 * </ul>
 */
@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class IntrospectionSecurityConfiguration {

  private static final Logger LOG =
      LoggerFactory.getLogger(IntrospectionSecurityConfiguration.class);
  private static final String PERMIT_PUBLIC_URL_PATTERN = "/public/**";
  private static final List<String> ALLOWED_HTTP_METHODS =
      List.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE");

  @Value("${spring.security.oauth2.resourceserver.opaque.introspection-uri}")
  private String introspectionUri;

  @Value("${spring.security.oauth2.resourceserver.opaque.introspection-client-id}")
  private String clientId;

  @Value("${spring.security.oauth2.resourceserver.opaque.introspection-client-secret}")
  private String clientSecret;

  @Value("${cors.allowed-origins:}")
  private String[] allowedOrigins;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.ignoringRequestMatchers(PERMIT_PUBLIC_URL_PATTERN));
    http.authorizeHttpRequests(
            authorize ->
                authorize
                    // Allow preflight requests (OPTIONS) without authentication
                    .requestMatchers(HttpMethod.OPTIONS)
                    .permitAll()
                    // Allow public endpoints without being authorized
                    .requestMatchers(PERMIT_PUBLIC_URL_PATTERN)
                    .permitAll()
                    // Require authentication for all other requests
                    .anyRequest()
                    .authenticated())
        .oauth2ResourceServer(
            oauth2 ->
                oauth2.opaqueToken(
                    opaque ->
                        opaque.introspector(
                            new OpaqueJwtIntrospector(introspectionUri, clientId, clientSecret))));
    configureCors(http);
    configureCsp(http);
    configureSecurityHeaders(http);

    return http.build();
  }

  private void configureCors(HttpSecurity http) throws Exception {
    if (allowedOrigins == null || allowedOrigins.length < 1) {
      LOG.warn(
          "No CORS allowed origins defined. CORS will not be enabled, and browser-specific security"
              + " HTTP headers will not be generated.");
      return;
    }

    http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
  }

  private CorsConfigurationSource corsConfigurationSource() {
    LOG.info(
        "Configuring CORS with the following allowed origins: '{}'.",
        Arrays.toString(allowedOrigins));

    // Cross-Origin Resource Sharing
    final CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(asList(allowedOrigins));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setMaxAge(86400L);
    configuration.setAllowedMethods(ALLOWED_HTTP_METHODS);
    configuration.setAllowCredentials(true);

    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    return source;
  }

  private void configureCsp(HttpSecurity http) throws Exception {
    http.headers(
        headers ->
            headers
                // Content Security Policy
                .contentSecurityPolicy(
                csp ->
                    csp.policyDirectives(
                        "default-src 'none'; "
                            + "img-src 'self' *.ionutbalosin.com; "
                            + "script-src 'self' *.ionutbalosin.com; "
                            + "style-src 'self'; "
                            + "connect-src 'self' *.ionutbalosin.com; "
                            + "form-action 'self'; "
                            + "base-uri 'self'; "
                            + "frame-src 'self';")));
  }

  private void configureSecurityHeaders(HttpSecurity http) throws Exception {
    http.headers(
        headers ->
            headers
                // Strict-Transport-Security: max-age=63072000; includeSubdomains; preload
                .httpStrictTransportSecurity(
                    hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(63072000).preload(true))
                // X-XSS-Protection: 1; mode=block
                .xssProtection(
                    xss ->
                        xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                // X-Frame-Options: DENY
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                // X-Content-Type-Options: nosniff
                .contentTypeOptions(Customizer.withDefaults())
                // .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"))
                // Referrer-Policy: same-origin
                .referrerPolicy(
                    referrer ->
                        referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN)));
  }
}
