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
package ionutbalosin.training.application.security.practices.jwks;

import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

  private static final String CLIENT_ID_CLAIM = "client_id";
  private static final String REALM_ACCESS_CLAIM = "realm_access";
  private static final String RESOURCE_ACCESS_CLAIM = "resource_access";
  private static final String ROLES_CLAIM = "roles";

  @Override
  public Collection<GrantedAuthority> convert(Jwt jwt) {
    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
    for (String role : getRealAccessRoles(jwt)) {
      grantedAuthorities.add(new SimpleGrantedAuthority(role));
    }
    for (String role : getResourceAccessRoles(jwt)) {
      grantedAuthorities.add(new SimpleGrantedAuthority(role));
    }
    return grantedAuthorities;
  }

  /*
   * This method extracts the roles from the 'realm_access' claim from a JWT token using the default Keycloak JWT token format.
   * Example structure:
   *   "realm_access": {
   *     "roles": [
   *       "role-1",
   *       "role-2",
   *       "..."
   *     ]
   *   }
   * The returned list will contain ["role-1", "role-2", ...].
   *
   * Note: The 'realm_access' and 'roles' claims are fixed and automatically set by Keycloak.
   */
  private Collection<String> getRealAccessRoles(Jwt jwt) {
    return ofNullable(jwt.getClaim(REALM_ACCESS_CLAIM))
        .filter(realmAccessClaim -> realmAccessClaim instanceof Map)
        .map(realmAccessClaim -> (Map<?, ?>) realmAccessClaim)
        .map(realmAccessClaim -> realmAccessClaim.get(ROLES_CLAIM))
        .filter(rolesClaim -> rolesClaim instanceof List)
        .map(rolesClaim -> (List<?>) rolesClaim)
        .map(
            roles ->
                roles.stream()
                    .filter(role -> role instanceof String)
                    .map(role -> (String) role)
                    .collect(toList()))
        .orElseGet(ArrayList::new);
  }

  /*
   * This method extracts the roles from the 'resource_access' claim from a JWT token using the default Keycloak JWT token format.
   * Example structure:
   *   "resource_access": {
   *     "demo_private_client": {
   *       "roles": [
   *         "role-1",
   *         "role-2",
   *         "..."
   *       ]
   *     }
   *   }
   * The returned list will contain ["role-1", "role-2", ...].
   *
   * Note: The 'private_client' claim contains the value of the 'client_id' claim,
   * while the 'resource_access' and 'roles' claims are fixed and automatically set by Keycloak.
   */
  private Collection<String> getResourceAccessRoles(Jwt jwt) {
    return ofNullable(jwt.getClaim(RESOURCE_ACCESS_CLAIM))
        .filter(resourceAccessClaim -> resourceAccessClaim instanceof Map)
        .map(resourceAccessClaim -> (Map<?, ?>) resourceAccessClaim)
        .map(resourceAccessClaim -> resourceAccessClaim.get(jwt.getClaim(CLIENT_ID_CLAIM)))
        .filter(clientClaim -> clientClaim instanceof Map)
        .map(clientClaim -> (Map<?, ?>) clientClaim)
        .map(clientClaim -> clientClaim.get(ROLES_CLAIM))
        .filter(rolesClaim -> rolesClaim instanceof List)
        .map(rolesClaim -> (List<?>) rolesClaim)
        .map(
            roles ->
                roles.stream()
                    .filter(role -> role instanceof String)
                    .map(role -> (String) role)
                    .collect(toList()))
        .orElseGet(ArrayList::new);
  }
}
