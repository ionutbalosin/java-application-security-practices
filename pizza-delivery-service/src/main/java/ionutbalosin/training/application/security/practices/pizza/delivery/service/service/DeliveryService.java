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

import ionutbalosin.training.application.security.practices.pizza.delivery.api.model.PizzaDeliveryOrderDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class DeliveryService {

  private static final Logger LOGGER = LoggerFactory.getLogger(DeliveryService.class);

  public void pizzaDeliveryOrdersPost(PizzaDeliveryOrderDto pizzaDeliveryOrderDto) {
    LOGGER.info(
        "Pizza order '{}' has been successfully delivered.", pizzaDeliveryOrderDto.getOrderId());
  }
}
