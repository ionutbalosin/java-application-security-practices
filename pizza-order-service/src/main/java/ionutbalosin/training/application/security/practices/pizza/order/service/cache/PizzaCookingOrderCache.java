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

import static java.util.Optional.ofNullable;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import ionutbalosin.training.application.security.practices.pizza.cooking.api.model.PizzaCookingOrderDto;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public enum ProductCache {
  CACHE_INSTANCE;

  private Cache<UUID, PizzaCookingOrderDto> pizzaCookingOrderCache;

  ProductCache() {
    this.pizzaCookingOrderCache =
        Caffeine.newBuilder().maximumSize(1000).expireAfterWrite(4, TimeUnit.HOURS).build();
  }

  public Optional<PizzaCookingOrderDto> getProduct(UUID pizzaCookingOrderId) {
    return ofNullable(pizzaCookingOrderCache.getIfPresent(pizzaCookingOrderId));
  }

  public void addProduct(PizzaCookingOrderDto pizzaCookingOrderDto) {
    pizzaCookingOrderCache.put(pizzaCookingOrderDto.getOrderId(), pizzaCookingOrderDto);
  }
}
