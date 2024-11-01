# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

> ⏰: 80 minutes

## Best Practices to Mitigate Java Process Security Attacks

### 👨‍💼 Trainer: Hands-On Demo

#### 🕵️‍♂️ Input Data Validation and Sanitization

The application source code includes several validation and sanitization techniques, such as:
- Whitelisting
- Regular Expressions
- Type Validation
- Range Validation
- Length and Size Validation

These mechanisms are implemented in various locations, including:
- [service-api.yaml](pizza-order-api/src/main/resources/service-api.yaml) using the OpenAPI JSON Schema validation keywords (e.g., `pattern`, `maxLength`, `minItems`, `maxItems`, `minimum`, `maximum`, etc.)
- [UploadFileValidator.java](pizza-order-service/src/main/java/ionutbalosin/training/application/security/practices/pizza/order/service/validator/UploadFileValidator.java)
- [OrderSanitizer.java](pizza-order-service/src/main/java/ionutbalosin/training/application/security/practices/pizza/order/service/sanitizer/OrderSanitizer.java)
- [application.properties](pizza-order-service/src/main/resources/application.properties)

To demonstrate this, use `Postman` to initiate a pizza order request with the endpoint `POST /pizza/orders`.
Try intentionally malforming the request using:
- An empty pizza list
- A very big number for the pizza quantity
- An invalid phone number format
- An invalid email address format

---

#### 🕵️‍♂️ Handling Input Files from External Sources

The application source code includes several mitigation strategies for handling input files from external sources, including:
- Filename length check
- File extension validation
- File size validation
- MIME type validation using [Apache Tika](https://tika.apache.org/)
- Protection against file path traversal attacks

These mechanisms are implemented in:
- [UploadFileValidator.java](pizza-order-service/src/main/java/ionutbalosin/training/application/security/practices/pizza/order/service/validator/UploadFileValidator.java)

To demonstrate this, use `Postman` to initiate a file upload request with the endpoint `POST /pizza/upload/menu`. 
Try intentionally malforming the request by:
- Uploading a non-supported file type (e.g., `.PDF`)
- Uploading a mismatched file content type (e.g., renaming a `.PDF` file to have a `.txt` extension)

---

#### 🕵️‍♂️ Security Logging

The application source code adds the following fields to each logged line corresponding to every incoming request:
- Remote host
- Remote port
- User ID
- Correlation ID
- Request method
- HTTP request URI
- User agent

These mechanisms are implemented in various locations, including:
- [LoggerInterceptor.java](security-slf4j-logger-enricher/src/main/java/ionutbalosin/training/application/security/practices/slf4j/logger/enricher/LoggerInterceptor.java)
- [CorrelationIdInterceptor.java](security-feign-logger-enricher/src/main/java/ionutbalosin/training/application/security/practices/feign/logger/enricher/CorrelationIdInterceptor.java)

To demonstrate this, open the Docker console logs of one of the containers (e.g., `pizza-order-service`) using the following command:

```bash
docker logs -f <CONTAINER_ID>
```

---

#### 🕵️‍♂️ Content Security Policy

The application source code implements several Content Security Policy directives, including:
- `img-src`
- `script-src`
- `style-src`
- `connect-src`
- `form-action`
- `base-uri`
- `frame-src`

These directives are implemented in:
- [IntrospectionSecurityConfiguration.java](security-token-introspection/src/main/java/ionutbalosin/training/application/security/practices/token/introspection/IntrospectionSecurityConfiguration.java)

To demonstrate this, use `Postman` to initiate another pizza order request with the endpoint `POST /pizza/orders`.
Then, check the HTTP response headers for the `Content-Security-Policy` header.

---

#### 🕵️‍♂️ Cross-Origin Resource Sharing

The application source code implements several Cross-Origin Resource Sharing directives, including:
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Allow-Credentials`

These mechanisms are implemented in various locations, including:
- [service-api.yaml](pizza-order-api/src/main/resources/service-api.yaml) and the `OPTIONS /pizza/orders` endpoint definition
- [IntrospectionSecurityConfiguration.java](security-token-introspection/src/main/java/ionutbalosin/training/application/security/practices/token/introspection/IntrospectionSecurityConfiguration.java)

To demonstrate CORS from the same machine can be challenging, as it requires calling the API from a different origin. 
However, you can use `Postman` to initiate a CORS preflight request with the endpoint `OPTIONS /pizza/orders`.
Then, check the HTTP response headers for CORS-related headers, including:
- `Vary: Origin`
- `Vary: Access-Control-Request-Method`
- `Vary: Access-Control-Request-Headers`

**Notes:**
- The primary purpose of the `Vary` header is to inform browser caches that they may need to store different versions of a response based on certain request headers, allowing for more accurate caching behavior.

---

#### 🕵️‍♂️ HTTP Security Headers

The application source code implements several HTTP Security Headers, including:
- `Strict-Transport-Security`
- `X-XSS-Protection`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`

These directives are implemented in:
- [IntrospectionSecurityConfiguration.java](security-token-introspection/src/main/java/ionutbalosin/training/application/security/practices/token/introspection/IntrospectionSecurityConfiguration.java)

To demonstrate this, use `Postman` to initiate another pizza order request with the endpoint `POST /pizza/orders`.
Then, check the HTTP response headers for the implemented security headers.

---

#### 🕵️‍♂️ Java Deserialization

The application source code demonstrates several potential Java deserialization exploits and strategies to mitigate them, including:
- Java Deserialization Attack
- XML External Entity (XXE)
- YAML Nested Anchors and Aliases
- Zip Bomb

These mechanisms are implemented in various locations, including:
- [MaliciousClazzDeserializer.java](serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/clazz/MaliciousClazzDeserializer.java)
- [XmlXxeDeserializer.java](serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/xml/XmlXxeDeserializer.java)
- [YamlBombDeserializer.java](serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/yaml/YamlBombDeserializer.java)
- [ZipBombDeserializer.java](serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/zip/ZipBombDeserializer.java)