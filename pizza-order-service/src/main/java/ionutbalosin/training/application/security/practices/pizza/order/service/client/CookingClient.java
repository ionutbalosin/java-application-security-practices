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
package ionutbalosin.training.application.security.practices.pizza.order.service.client;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import ionutbalosin.training.application.security.practices.feign.logger.enricher.FeignConfiguration;
import ionutbalosin.training.application.security.practices.pizza.cooking.api.model.PizzaCookingOrderDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@FeignClient(
    name = "${pizza-cooking-service.name}",
    url = "${pizza-cooking-service-endpoint.url}",
    configuration = FeignConfiguration.class)
public interface CookingClient {

  @RequestMapping(
      method = RequestMethod.POST,
      value = "/pizza/cooking/orders",
      consumes = {"application/json"})
  ResponseEntity<Void> pizzaCookingOrdersPost(
      @Parameter(
              name = "Authorization",
              description = "JWT Authorizing token to allow access to endpoint",
              required = true,
              in = ParameterIn.HEADER)
          @RequestHeader(value = "Authorization", required = true)
          @NotNull
          String authorization,
      @Parameter(
              name = "PizzaCookingOrderDto",
              description = "Partial update content",
              required = true)
          @RequestBody
          @Valid
          PizzaCookingOrderDto pizzaCookingOrderDto);
}
