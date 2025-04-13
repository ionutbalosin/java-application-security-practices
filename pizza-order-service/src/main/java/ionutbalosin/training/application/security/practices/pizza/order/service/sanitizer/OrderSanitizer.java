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
package ionutbalosin.training.application.security.practices.pizza.order.service.sanitizer;

import static java.util.Optional.ofNullable;

import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderCustomerDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderDto;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

@Service
public class OrderSanitizer {

  /**
   * This method sanitizes the special request free text field to prevent cross-site scripting (XSS)
   * attacks. It uses HTML escaping to ensure that any potentially malicious content in the free
   * text field is neutralized before processing.
   */
  public void sanitizeSpecialRequest(PizzaOrderDto pizzaOrderDto) {
    ofNullable(pizzaOrderDto.getCustomer())
        .map(PizzaOrderCustomerDto::getSpecialRequest)
        .map(HtmlUtils::htmlEscape)
        .ifPresent(
            sanitizedSpecialRequest ->
                pizzaOrderDto.getCustomer().setSpecialRequest(sanitizedSpecialRequest));
  }
}
