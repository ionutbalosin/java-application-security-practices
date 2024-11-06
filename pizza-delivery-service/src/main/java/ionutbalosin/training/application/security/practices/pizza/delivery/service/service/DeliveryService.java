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
package ionutbalosin.training.application.security.practices.pizza.delivery.service.service;

import static ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderProcessingStatusDto.*;

import ionutbalosin.training.application.security.practices.pizza.delivery.api.model.PizzaDeliveryOrderDto;
import ionutbalosin.training.application.security.practices.pizza.delivery.service.client.OrderClient;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderUpdatedStatusDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class DeliveryService {

  private static final Logger LOGGER = LoggerFactory.getLogger(DeliveryService.class);

  private OrderClient orderClient;

  public DeliveryService(OrderClient orderClient) {
    this.orderClient = orderClient;
  }

  public void pizzaDeliveryOrdersPost(
      String authorization, PizzaDeliveryOrderDto pizzaDeliveryOrderDto) {
    // TODO: Implement actual delivery process (e.g., logistics, tracking)
    LOGGER.info(
        "Pizza order '{}' has been successfully delivered.", pizzaDeliveryOrderDto.getOrderId());

    // Update the order's processing status to 'DELIVERED' in the order service
    orderClient.pizzaOrdersOrderIdPut(
        authorization,
        pizzaDeliveryOrderDto.getOrderId(),
        new PizzaOrderUpdatedStatusDto().orderStatus(DELIVERED));
  }
}
