# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

> ⏰: 40 minutes

## API and Microservices Security

### 📖 Informational: Software Architecture Diagram

This software architecture diagram for the `Pizza` distributed application highlights key security aspects, including OAuth 2.0 flows (e.g., JWT introspection, JWKS) and endpoint roles checks.

<img src="assets/diagrams/software-architecture-diagram.svg">

### 👨‍💼 Trainer: Hands-On Demo

Open a terminal and start the `Pizza` application, which includes multiple microservices running in Docker, by using the following command:

```bash
./bootstrap-pizza-application.sh
```

Open the [Postman collection](postman) and choose one of the following OAuth 2.0 flows to obtain a proper JWT token:
- `Password Flow`
- `Client Credentials Flow`
- `Authorization Code Flow with PKCE`

Then, initiate a pizza order request by using the endpoint `POST /pizza/orders`. If the command succeeds, the result should be `201 Created`.

Now, you can open the console logs of each Docker container for further request processing details and check the logs:

```bash
docker logs -f <CONTAINER_ID>
```

where `<CONTAINER_ID>` can be retrieved by running this command:

```bash
docker ps -a
```

Additionally, to better understand the `Token Introspection`, `JSON Web Key Set`, and `roles-based access control` implementations, please check out the following modules:
- [security-token-introspection](security-token-introspection)
- [security-token-jwks](security-token-jwks)
- [security-token-client-credentials-fetcher](security-token-client-credentials-fetcher)