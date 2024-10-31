# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](../license/LICENSE) file for full license.

---

> ⏰: 120 minutes

## Authentication and Authorization

### 👨‍🎓 Attendees: Identify the Appropriate Flows

Consider the software architecture template diagram below, explicitly designed to be agnostic to any specific business application domain. However, since security is mission-critical, each component must be protected, and all communication between components must be both authenticated and authorized.

<p align="center">
  <img alt="eCommerce" title="eCommerce" src="../assets/diagrams/software-architecture-diagram-authn-authz.svg">
</p>

The system is accessed by different types of clients or systems:

- `External OIDC Users`: Public users authenticated through an external OIDC provider, such as Google or Facebook.
- `Internal OIDC Users`: Public users authenticated via the organization’s internal Identity Provider (IdP).
- `Employees`: Internal company users authenticated via the organization’s internal IdP.
- `Public/Internal Services`: Public external systems and internal services from other departments, authenticated via the organization’s internal IdP.

The system is divided into three distinct layers:

- `Public Clients`: Publicly exposed APIs accessed by users or external systems, involving both the internal IdP and an external (i.e., third-party) IdP for authentication.
- `Internal Core Services`: Internal organizational services usually within the same company department, requiring secure service-to-service authentication and authorization.
- `Internal Non-core Services`: Auxiliary, non-core systems usually belonging to other departments within the organization, also requiring service-to-service authentication and authorization.

Communication between clients and services is primarily based on synchronous HTTP RESTful API calls; however, in some cases, asynchronous communication is used, with events placed into queues.

🏋️ **Task:** Each red arrow, labeled with an index from `1` to `12`, links a specific client or service to the IdP. 
For each of these arrows, identify the most suitable OAuth 2.0 or OpenID Connect (OIDC) flow based on the interaction type and the client or service  involved. 
Options may include, but are not limited to:

- `OpenID Connect`
- `Authorization Code Flow with PKCE`
- `Client Credentials Flow`
- `Token Introspection`
- `JSON Web Key Set`
- etc.

---

### 👨‍💼 Trainer: Hands-On Demo

Open a terminal and start the `Pizza` distributed application, which includes multiple microservices running in Docker, using the following command:

```bash
bootstrap.sh
```

From another terminal, trigger the `Keycloak` initialization setup using the following command:

```bash
keycloak-init.sh
```

Once everything has been started and properly initialized, open `Postman` and trigger the following IdP endpoints/flows
- OpenID Connect configuration
- `Client Credentials Flow`
- `Password Flow`
- `Implicit Flow`
- `Authorization Code Flow with PKCE`

**Notes:**
- Depending on the flow, not all types of tokens (e.g., identity, access, and refresh tokens) are returned.
- To understand the structure of a KWT token, copy and paste it into [jwt.io](https://jwt.io) and examine its structure (e.g., header, payload, and specific claims like `roles`, `iss`, `aud`, `exp`, etc.). 
