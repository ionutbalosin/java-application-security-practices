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
package ionutbalosin.training.application.security.practices.client.credentials.handler;

import static ionutbalosin.training.application.security.practices.client.credentials.handler.util.JsonObjectMapper.deserialize;
import static java.lang.String.format;
import static java.util.Optional.empty;
import static java.util.Optional.ofNullable;

import java.io.IOException;
import java.util.Base64;
import java.util.Optional;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * This class fetches a new access token from the Identity Provider (IdP) using the client
 * credentials flow. The client credentials flow is typically used for machine-to-machine
 * communication. In this flow, it is recommended that a refresh token SHOULD NOT be issued.
 * Therefore, whenever a new token is required, a fresh authorization request must be made to the
 * IdP. Since the backend stores the client secret locally, it can easily request a new access token
 * without needing to rely on a refresh token.
 *
 * <p>References:
 *
 * <ul>
 *   <li><a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4.3">Access Token Response</a>
 * </ul>
 */
@Service
public class IdpTokenFetcher {

  private static final Logger LOG = LoggerFactory.getLogger(IdpTokenFetcher.class);

  private static final String AUTH = "Authorization";
  private static final String CONTENT_TYPE = "Content-Type";
  private static final String CONTENT_TYPE_JSON = "application/json";
  private static final String CONTENT_TYPE_URLENCODED = "application/x-www-form-urlencoded";

  @Value("${oidc.url}")
  private String idpUrl;

  @Value("${oidc.clientId}")
  private String clientId;

  @Value("${oidc.clientSecret}")
  private String clientSecret;

  public Optional<IdpToken> fetchToken() {
    final String encodedHeader =
        new String(Base64.getEncoder().encode(format("%s:%s", clientId, clientSecret).getBytes()));
    final RequestBody body =
        RequestBody.create(
            format("grant_type=client_credentials&client_id=%s", clientId),
            MediaType.parse(CONTENT_TYPE_URLENCODED));
    final Request request =
        new Request.Builder()
            .url(idpUrl)
            .post(body)
            .addHeader(CONTENT_TYPE, CONTENT_TYPE_JSON)
            .addHeader(AUTH, format("Basic %s", encodedHeader))
            .build();

    try (Response response = new OkHttpClient().newCall(request).execute()) {
      final ResponseBody responseBody = response.body();
      if (responseBody == null) {
        throw new RuntimeException(
            "Identity Provider responded with an empty body. Unable to retrieve token.");
      }
      final IdpToken idpToken = deserialize(responseBody.string(), IdpToken.class);
      return ofNullable(idpToken);
    } catch (IOException exception) {
      LOG.error("IOException while retrieving authentication token: '{}'", exception.getMessage());
      return empty();
    }
  }
}
