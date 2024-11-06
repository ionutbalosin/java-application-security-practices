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
package ionutbalosin.training.application.security.practices.pizza.cooking.service.service;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import ionutbalosin.training.application.security.practices.client.credentials.handler.IdpToken;
import ionutbalosin.training.application.security.practices.client.credentials.handler.IdpTokenFetcher;
import ionutbalosin.training.application.security.practices.pizza.cooking.api.model.PizzaCookingOrderDto;
import ionutbalosin.training.application.security.practices.pizza.cooking.service.client.DeliveryClient;
import ionutbalosin.training.application.security.practices.pizza.cooking.service.mapper.PizzaDeliveryOrderDtoMapper;
import ionutbalosin.training.application.security.practices.pizza.delivery.api.model.PizzaDeliveryOrderDto;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadLocalRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class CookingService {

  private static final Logger LOGGER = LoggerFactory.getLogger(CookingService.class);

  @SuppressFBWarnings("PREDICTABLE_RANDOM")
  private static final Random RANDOM = ThreadLocalRandom.current();

  private final IdpTokenFetcher tokenFetcher;
  private final PizzaDeliveryOrderDtoMapper dtoMapper;
  private final DeliveryClient deliveryClient;
  private final Executor taskExecutor;

  public CookingService(
      IdpTokenFetcher tokenFetcher,
      PizzaDeliveryOrderDtoMapper dtoMapper,
      DeliveryClient deliveryClient,
      @Qualifier("PizzaCookingExecutor") Executor taskExecutor) {
    this.tokenFetcher = tokenFetcher;
    this.dtoMapper = dtoMapper;
    this.deliveryClient = deliveryClient;
    this.taskExecutor = taskExecutor;
  }

  public void pizzaCookingOrdersPost(PizzaCookingOrderDto pizzaCookingOrderDto) {
    taskExecutor.execute(() -> schedulePizzaCooking(pizzaCookingOrderDto));
    LOGGER.info(
        "Pizza order '{}' has been successfully scheduled for cooking.",
        pizzaCookingOrderDto.getOrderId());
  }

  private void schedulePizzaCooking(PizzaCookingOrderDto pizzaCookingOrderDto) {
    try {
      // Simulate some cooking activity between 5 and 15 seconds
      Thread.sleep(Duration.ofSeconds(5 + RANDOM.nextInt(11)).toMillis());
    } catch (InterruptedException e) {
      // Swallow exception
    }

    LOGGER.info(
        "Pizza order '{}' has been successfully cooked.", pizzaCookingOrderDto.getOrderId());
    final IdpToken idpToken = fetchToken();

    // Notify delivery service with the order details once the pizza cooking is done
    final PizzaDeliveryOrderDto deliveryOrderDto = dtoMapper.map(pizzaCookingOrderDto);
    deliveryClient.pizzaDeliveryOrdersPost(
        "Bearer " + idpToken.getAccess_token(), deliveryOrderDto);

    LOGGER.info(
        "Pizza order '{}' has been successfully sent for delivery.", deliveryOrderDto.getOrderId());
  }

  private IdpToken fetchToken() {
    return tokenFetcher
        .fetchToken()
        .orElseThrow(() -> new RuntimeException("Unable to fetch the IdP token"));
  }
}
