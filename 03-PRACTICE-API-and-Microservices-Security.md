# Application Security for Java Developers

Copyright (C) 2025 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

## API and Microservices Security

> ⏰ 40 minutes

> 👨‍💼 Conducted By Trainer

### 📖 Informational: Software Architecture Diagram

This software architecture diagram for the `Pizza` distributed application highlights key security aspects, including OAuth 2.0 flows (e.g., Token introspection, JWKS) and endpoint roles checks.

<img src="assets/diagrams/software-architecture-diagram.svg">

---

### 🏋️ Hands-On Demo

**Note:** Please ensure that the Docker daemon is running; otherwise, the commands will not execute successfully.

1. Open a terminal and start the `Pizza` application, which includes multiple microservices running in Docker, by using the following command:

    ```bash
    ./bootstrap-pizza-application.sh
    ```

2. Next, open `Postman` and import the [Postman collections](postman).

3. From the provided `Postman` collections, choose one of the following OAuth 2.0 flows to obtain a proper JWT token:
    - `Password Flow`
    - `Client Credentials Flow`
    - `Authorization Code Flow with PKCE` (using the credentials `demo_user:Test1234!`) *(recommended)*

4. Finally, initiate a pizza order request using the endpoint `POST /pizza/orders`. If the command succeeds, the response should be `201 Created`.

5. To view further request processing details, open the console logs of each Docker container by running:

    ```bash
    docker logs -f <CONTAINER_ID>
    ```

   where `<CONTAINER_ID>` can be retrieved by running:

    ```bash
    docker ps -a
    ```

6. Additionally, to better understand the `Token Introspection`, `JSON Web Key Set`, and `roles-based access control` implementations, please check out the following modules:
    - [security-token-introspection](security-token-introspection)
    - [security-token-jwks](security-token-jwks)
    - [security-token-client-credentials-fetcher](security-token-client-credentials-fetcher)
