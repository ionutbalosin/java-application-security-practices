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
package ionutbalosin.training.application.security.practices.token.introspection;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;

public class OpaqueJwtIntrospector implements OpaqueTokenIntrospector {

  private static final Logger LOG = LoggerFactory.getLogger(OpaqueJwtIntrospector.class);

  private static final String RESOURCE_ACCESS_CLAIM = "realm_access";
  private static final String ROLES_CLAIM = "roles";
  private final OpaqueTokenIntrospector delegate;

  public OpaqueJwtIntrospector(String introspectionUri, String clientId, String clientSecret) {
    delegate = new SpringOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
  }

  @Override
  public OAuth2AuthenticatedPrincipal introspect(String token) {
    final OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
    return new DefaultOAuth2AuthenticatedPrincipal(
        principal.getName(), principal.getAttributes(), extractAuthorities(principal));
  }

  private Collection<GrantedAuthority> extractAuthorities(OAuth2AuthenticatedPrincipal principal) {
    final List<String> rolesClaim = getRolesClaim(principal);
    if (rolesClaim.isEmpty()) {
      LOG.warn(
          "No roles found in the JWT claim structure '{} -> {}'. Principal: {}",
          RESOURCE_ACCESS_CLAIM,
          ROLES_CLAIM,
          principal.getName());
      return emptySet();
    }

    return ((Collection<?>) rolesClaim)
        .stream().map(role -> (String) role).map(SimpleGrantedAuthority::new).collect(toSet());
  }

  /*
   * This method extracts the roles claim from a JWT token using the default Keycloak JWT token format.
   * Example structure:
   *   "realm_access": {
   *     "roles": [
   *       "role-1",
   *       "role-2",
   *       "..."
   *     ]
   *   }
   * The returned list will contain ["role-1", "role-2", ...].
   */
  private List<String> getRolesClaim(OAuth2AuthenticatedPrincipal principal) {
    return ofNullable(principal.getAttributes().get(RESOURCE_ACCESS_CLAIM))
        .filter(resourceAccessClaim -> resourceAccessClaim instanceof Map)
        .map(resourceAccessClaim -> (Map<?, ?>) resourceAccessClaim)
        .map(resourceAccess -> resourceAccess.get(ROLES_CLAIM))
        .filter(roles -> roles instanceof List)
        .map(roles -> (List<?>) roles)
        .map(
            roles ->
                roles.stream()
                    .filter(role -> role instanceof String)
                    .map(role -> (String) role)
                    .collect(toList()))
        .orElseGet(ArrayList::new);
  }
}
