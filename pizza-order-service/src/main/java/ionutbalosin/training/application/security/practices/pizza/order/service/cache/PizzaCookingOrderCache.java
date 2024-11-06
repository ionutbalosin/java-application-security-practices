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
package ionutbalosin.training.application.security.practices.pizza.order.service.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderStatusDto;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public enum PizzaCookingOrderCache {
  CACHE_INSTANCE;

  private Cache<UUID, PizzaOrderStatusDto> pizzaCookingOrderCache;

  PizzaCookingOrderCache() {
    this.pizzaCookingOrderCache =
        Caffeine.newBuilder().maximumSize(1000).expireAfterWrite(3, TimeUnit.HOURS).build();
  }

  public PizzaOrderStatusDto getProduct(UUID pizzaOrderId) {
    return pizzaCookingOrderCache.getIfPresent(pizzaOrderId);
  }

  public void addProduct(UUID pizzaOrderId, PizzaOrderStatusDto pizzaOrderStatusDto) {
    pizzaCookingOrderCache.put(pizzaOrderId, pizzaOrderStatusDto);
  }
}
