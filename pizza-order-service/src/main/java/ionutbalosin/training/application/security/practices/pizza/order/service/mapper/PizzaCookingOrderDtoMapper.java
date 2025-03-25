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
package ionutbalosin.training.application.security.practices.pizza.order.service.mapper;

import static java.util.stream.Collectors.toList;

import ionutbalosin.training.application.security.practices.pizza.cooking.api.model.PizzaCookingOrderDto;
import ionutbalosin.training.application.security.practices.pizza.cooking.api.model.PizzaCookingOrderItemDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderProcessingStatusDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderStatusDto;
import java.util.UUID;

public class PizzaCookingOrderDtoMapper {

  public PizzaCookingOrderDto map(PizzaOrderDto pizzaOrderDto) {
    return new PizzaCookingOrderDto()
        .orderId(UUID.randomUUID())
        .orders(
            pizzaOrderDto.getOrders().stream()
                .map(
                    orderDto ->
                        new PizzaCookingOrderItemDto()
                            .name(orderDto.getName())
                            .quantity(orderDto.getQuantity()))
                .collect(toList()));
  }

  public PizzaOrderStatusDto map(
      PizzaOrderDto pizzaOrderDto, PizzaOrderProcessingStatusDto orderStatus) {
    return new PizzaOrderStatusDto().pizzaOrder(pizzaOrderDto).orderStatus(orderStatus);
  }
}
