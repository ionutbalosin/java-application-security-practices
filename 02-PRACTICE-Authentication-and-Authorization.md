# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

## Authentication and Authorization

### 🕵️‍♂️ Identify the Appropriate Flows

> ⏰ 60 minutes

> 👨‍🎓 Attendees' Exercise

Consider the software architecture diagram below, explicitly designed to be agnostic to any specific business application domain. However, since security is mission-critical, each component must be protected, and all communication between components must be both authenticated and authorized.

<p align="center">
  <img alt="eCommerce" title="eCommerce" src="assets/diagrams/software-architecture-diagram-authn-authz.svg">
</p>

The system is accessed by different types of clients or systems:

- `External OIDC Users`: Public users authenticated through an external OIDC provider, such as Google or Facebook.
- `Internal OIDC Users`: Public users authenticated via the organization’s internal Identity Provider (IdP).
- `Employees`: Internal company users authenticated via the organization’s internal IdP.
- `External/Internal Services`: Public external systems and internal services from other departments, authenticated via the organization’s internal IdP.

The system is divided into three distinct layers:

- `Public Clients Layer`: Publicly exposed APIs accessed by users or external systems, involving both the internal IdP and an external (i.e., third-party) IdP for authentication.
- `Internal Core Services Layer`: Internal organizational services usually within the same company department, requiring secure service-to-service authentication and authorization.
- `Internal Non-core Services Layer`: Auxiliary, non-core systems usually belonging to other departments within the organization, also requiring service-to-service authentication and authorization.

Communication between clients and services is primarily based on synchronous HTTP RESTful API calls; however, in some cases, asynchronous communication is used, with events placed into queues.

**Task:** Each red arrow, labeled with an index from `1` to `12`, links a specific client or service to the IdP. 
For each of these arrows, identify the most suitable OAuth 2.0 or OpenID Connect (OIDC) flow based on the interaction type and the client or service  involved. 
Options may include, but are not limited to:

- `OpenID Connect`
- `Authorization Code Flow with PKCE`
- `Client Credentials Flow`
- `Password Flow`
- `Implicit Flow`
- `Token Introspection`
- `JSON Web Key Set`
- etc.

**Note:** Other flows may be suitable too, so don't limit your choice to only the options listed above.

---

### 🏋️ Hands-On Demo

> ⏰ 60 minutes

> 👨‍💼 Conducted By Trainer

**Note:** Please ensure that the Docker daemon is running; otherwise, the commands will not execute successfully.

1. Open a terminal and run the following command to bootstrap the `Keycloak` service:

    ```bash
    ./bootstrap-keycloak.sh
    ```

2. From another terminal, trigger the `Keycloak` initialization setup using the following command:

    ```bash
    ./keycloak-init.sh
    ```

3. Once everything has been started and properly initialized, open a browser and navigate to [http://localhost:9090](http://localhost:9090) to access the **Keycloak UI** (using the credentials `admin:admin`) and review the configuration.

4. As the next and final step, open `Postman`, import the [Postman collection](postman) and trigger the following IdP endpoints and OAuth 2.0 flows:
    - OpenID Connect configuration
    - `Client Credentials Flow`
    - `Password Flow`
    - `Implicit Flow`
    - `Authorization Code Flow with PKCE`

**Notes:**
- Depending on the flow, not all types of tokens (e.g., identity, access, and refresh tokens) are returned.
- To understand the structure of a JWT token, copy and paste it into [jwt.io](https://jwt.io) and examine its structure (e.g., header, payload, signature) and the specific claims like `exp`, `iat`, `iss`, `sub`, `typ`, `azp`, `roles`, `client_id`, etc.
