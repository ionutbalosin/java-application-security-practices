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
package ionutbalosin.training.application.security.practices.pizza.order.service.controller;

import static ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderProcessingStatusDto.IN_PROCESS;
import static ionutbalosin.training.application.security.practices.pizza.order.service.cache.PizzaCookingOrderCache.CACHE_INSTANCE;
import static java.lang.String.format;
import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;

import io.swagger.v3.oas.annotations.Parameter;
import ionutbalosin.training.application.security.practices.pizza.cooking.api.model.PizzaCookingOrderDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.PizzaApi;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderCreatedDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderCustomerDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderStatusDto;
import ionutbalosin.training.application.security.practices.pizza.order.api.model.PizzaOrderUpdatedStatusDto;
import ionutbalosin.training.application.security.practices.pizza.order.service.mapper.PizzaCookingOrderDtoMapper;
import ionutbalosin.training.application.security.practices.pizza.order.service.sanitizer.OrderSanitizer;
import ionutbalosin.training.application.security.practices.pizza.order.service.service.OrderService;
import ionutbalosin.training.application.security.practices.pizza.order.service.validator.UploadFileValidator;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class OrderController implements PizzaApi {

  private static final Logger LOGGER = LoggerFactory.getLogger(OrderController.class);

  private final OrderService orderService;
  private final OrderSanitizer orderSanitizer;
  private final UploadFileValidator uploadFileValidator;
  private final PizzaCookingOrderDtoMapper dtoMapper;

  public OrderController(
      OrderService orderService,
      OrderSanitizer orderSanitizer,
      UploadFileValidator uploadFileValidator,
      PizzaCookingOrderDtoMapper dtoMapper) {
    this.orderService = orderService;
    this.orderSanitizer = orderSanitizer;
    this.uploadFileValidator = uploadFileValidator;
    this.dtoMapper = dtoMapper;
  }

  @Override
  public ResponseEntity<Void> pizzaOrdersOptions() {
    LOGGER.info("pizzaOrdersOptions()");
    return new ResponseEntity<>(CREATED);
  }

  @Override
  public ResponseEntity<Void> pizzaOrdersOrderIdOptions(
      @Parameter(name = "orderId") @PathVariable UUID orderId) {
    LOGGER.info("pizzaOrdersOrderIdOptions()");
    return new ResponseEntity<>(OK);
  }

  @Override
  @PreAuthorize("hasAuthority('demo_user_role')")
  public ResponseEntity<PizzaOrderCreatedDto> pizzaOrdersPost(
      @Parameter(name = "Authorization") @RequestHeader String authorization,
      @RequestBody PizzaOrderDto pizzaOrderDto) {
    LOGGER.info("pizzaOrdersPost(pizzaOrder = '{}')", formatPizzaOrderDto(pizzaOrderDto));

    // Sanitize and map the order request
    orderSanitizer.sanitizeSpecialRequest(pizzaOrderDto);
    final PizzaCookingOrderDto pizzaCookingOrderDto = dtoMapper.map(pizzaOrderDto);
    final UUID pizzaOrderId = pizzaCookingOrderDto.getOrderId();

    // Update internal cache with the order command
    final PizzaOrderStatusDto pizzaOrderStatusDto = dtoMapper.map(pizzaOrderDto, IN_PROCESS);
    CACHE_INSTANCE.addProduct(pizzaOrderId, pizzaOrderStatusDto);

    // Send the order command to the cooking service
    orderService.pizzaOrdersPost(authorization, pizzaCookingOrderDto);

    return new ResponseEntity<>(new PizzaOrderCreatedDto().orderId(pizzaOrderId), CREATED);
  }

  @Override
  @PreAuthorize("hasAuthority('demo_user_role')")
  public ResponseEntity<PizzaOrderStatusDto> pizzaOrdersOrderIdGet(
      @Parameter(name = "Authorization") @RequestHeader String authorization,
      @Parameter(name = "orderId") @PathVariable UUID orderId) {
    LOGGER.info("pizzaOrdersOrderIdGet(orderId = '{}')", orderId);

    return ofNullable(CACHE_INSTANCE.getProduct(orderId))
        .map(pizzaOrderDto -> new ResponseEntity<>(pizzaOrderDto, OK))
        .orElse(new ResponseEntity<>(NOT_FOUND));
  }

  @Override
  @PreAuthorize("hasAuthority('demo_user_role')")
  @RequestMapping(
      method = RequestMethod.POST,
      value = "/pizza/upload/menu",
      consumes = {"multipart/form-data"})
  public ResponseEntity<Void> pizzaUploadMenuPost(
      @Parameter(name = "Authorization") @RequestHeader String authorization,
      @Parameter(name = "upload", required = true) @RequestPart(value = "upload")
          MultipartFile upload) {
    LOGGER.info("pizzaUploadMenuPost()");

    uploadFileValidator.validate(upload);
    // TODO: implement file upload processing (e.g., save the file or parse contents)

    return new ResponseEntity<>(CREATED);
  }

  @Override
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<Void> pizzaOrdersOrderIdPut(
      @Parameter(name = "Authorization") @RequestHeader String authorization,
      @Parameter(name = "orderId") @PathVariable UUID orderId,
      @RequestBody PizzaOrderUpdatedStatusDto pizzaOrderUpdatedStatusDto) {
    LOGGER.info("pizzaOrdersOrderIdPut(orderId = '{}')", pizzaOrderUpdatedStatusDto);

    return ofNullable(CACHE_INSTANCE.getProduct(orderId))
        .map(
            pizzaOrderDto -> {
              pizzaOrderDto.setOrderStatus(pizzaOrderUpdatedStatusDto.getOrderStatus());
              return new ResponseEntity<Void>(OK);
            })
        .orElse(new ResponseEntity<>(NOT_FOUND));
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
