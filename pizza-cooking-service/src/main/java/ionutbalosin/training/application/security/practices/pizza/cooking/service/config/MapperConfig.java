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
package ionutbalosin.training.application.security.practices.pizza.cooking.service.config;

import ionutbalosin.training.application.security.practices.pizza.cooking.service.mapper.PizzaDeliveryOrderDtoMapper;
import java.util.concurrent.Executor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
public class MapperConfig {

  @Bean
  public PizzaDeliveryOrderDtoMapper pizzaDeliveryOrderDtoMapper() {
    return new PizzaDeliveryOrderDtoMapper();
  }

  @Bean
  @Qualifier("PizzaCookingExecutor")
  public Executor executor() {
    // Configure a thread pool with a core pool size of 2, a maximum pool size of 4,
    // and leave the queue capacity at its default value (i.e., unlimited).
    // Note: Adjust these values if latency issues arise.
    final ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(2);
    executor.setMaxPoolSize(4);
    executor.setThreadNamePrefix("PizzaCookingThreadPoolExecutor");
    executor.initialize();
    return executor;
  }
}
