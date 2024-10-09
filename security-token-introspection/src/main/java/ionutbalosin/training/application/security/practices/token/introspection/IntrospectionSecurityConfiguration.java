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
package ionutbalosin.training.application.security.practices.token.introspection;

import static java.util.Arrays.asList;

import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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

  @Value("${cors.allowedOrigins:}")
  private String[] allowedOrigins;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.ignoringRequestMatchers(PERMIT_PUBLIC_URL_PATTERN));
    http.authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers(PERMIT_PUBLIC_URL_PATTERN)
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .oauth2ResourceServer(
            oauth2 ->
                oauth2.opaqueToken(
                    opaque ->
                        opaque.introspector(
                            new OpaqueJwtIntrospector(introspectionUri, clientId, clientSecret))));
    configureCors(http);

    return http.build();
  }

  private void configureCors(HttpSecurity http) throws Exception {
    if (allowedOrigins == null || allowedOrigins.length < 1) {
      LOG.warn(
          "No CORS allowed origins defined. CORS will not be enabled, and browser-specific security"
              + " HTTP headers will not be generated.");
      return;
    }

    http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .headers(
            headers ->
                headers
                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                    .referrerPolicy(
                        referrer ->
                            referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                    .xssProtection(
                        xss ->
                            xss.headerValue(
                                XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                    .addHeaderWriter(
                        new StaticHeadersWriter(
                            "Strict-Transport-Security", "max-age=63072000; includeSubDomains")));
  }

  private CorsConfigurationSource corsConfigurationSource() {
    LOG.info(
        "Configuring CORS with the following allowed origins: '{}'.",
        Arrays.toString(allowedOrigins));

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
}
