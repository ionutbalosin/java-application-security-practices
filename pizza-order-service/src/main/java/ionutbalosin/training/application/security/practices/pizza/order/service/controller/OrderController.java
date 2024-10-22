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
package ionutbalosin.training.application.security.practices.pizza.order.service.controller;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpStatus.CREATED;

import io.swagger.v3.oas.annotations.Parameter;
import ionutbalosin.training.application.security.practices.pizza.cooking.api.model.PizzaCookingOrderDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.PizzaApi;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderCreatedDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderCustomerDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderDto;
import ionutbalosin.training.application.security.practices.pizza.order.service.mapper.PizzaCookingOrderDtoMapper;
import ionutbalosin.training.application.security.practices.pizza.order.service.sanitizer.OrderSanitizer;
import ionutbalosin.training.application.security.practices.pizza.order.service.service.OrderService;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Controller
public class OrderController implements PizzaApi {

  private static final Logger LOGGER = LoggerFactory.getLogger(OrderController.class);

  private final OrderService orderService;
  private final OrderSanitizer orderSanitizer;
  private final PizzaCookingOrderDtoMapper dtoMapper;

  public OrderController(
      OrderService orderService,
      OrderSanitizer orderSanitizer,
      PizzaCookingOrderDtoMapper dtoMapper) {
    this.orderService = orderService;
    this.orderSanitizer = orderSanitizer;
    this.dtoMapper = dtoMapper;
  }

  @Override
  @PreAuthorize("hasAuthority('demo_user_role')")
  public ResponseEntity<PizzaOrderCreatedDto> pizzaOrdersPost(
      @Parameter(name = "Authorization") @RequestHeader String authorization,
      @RequestBody PizzaOrderDto pizzaOrderDto) {
    LOGGER.info("pizzaOrdersPost(pizzaOrder = '{}')", formatPizzaOrderDto(pizzaOrderDto));

    orderSanitizer.sanitizeSpecialRequest(pizzaOrderDto);
    final PizzaCookingOrderDto pizzaCookingOrderDto = dtoMapper.map(pizzaOrderDto);
    orderService.pizzaOrdersPost(authorization, pizzaCookingOrderDto);
    return new ResponseEntity<>(
        new PizzaOrderCreatedDto().orderId(pizzaCookingOrderDto.getOrderId()), CREATED);
  }

  private String formatPizzaOrderDto(PizzaOrderDto pizzaOrderDto) {
    // Format the list of pizza orders
    final String orders =
        pizzaOrderDto.getOrders().stream()
            .map(orderDto -> format("%s: %d", orderDto.getName(), orderDto.getQuantity()))
            .collect(Collectors.joining(", "));

    // Format customer details
    final PizzaOrderCustomerDto customerDto = pizzaOrderDto.getCustomer();
    final String customer =
        format("Customer: %s (Phone: %s)", customerDto.getName(), customerDto.getPhoneNumber());

    // Handle special request
    final String specialRequest = ofNullable(customerDto.getSpecialRequest()).orElse("none");

    // Return the formatted string
    return format("%s | Orders: [%s] | Special Request: %s", customer, orders, specialRequest);
  }
}
