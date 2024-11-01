# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

> ⏰: 30 minutes

## Security Testing

### 👨‍💼 Trainer: Hands-On Demo

#### 🕵️‍♂️ Software Composition Analysis

Open a terminal and execute the following command to check for any known dependency vulnerabilities in your libraries:

```bash
./mvnw clean compile org.owasp:dependency-check-maven:check
```

The detailed report containing all libraries and their vulnerabilities, including links to the sources where they were reported, can also be found in `<project_module>/target/dependency-check-report.html`.

---

#### 🕵️‍♂️ Static Application Security Testing

To check for potential code vulnerabilities, execute the following command:

```bash
./mvnw clean compile spotbugs:check
```

---

#### 🕵️‍♂️ Dynamic Application Security Testing

Please ensure the `Pizza` application is already started; otherwise, the command will not execute successfully.

To check for API security vulnerabilities, execute the following command:

```bash
./zap-scan.sh
```

The command starts ZAP in Docker, launches an API scan using the [zap-api-scan rules](zap/zap-api-scan-rules.conf) against one of the services, and saves the scan report in the [./zap/reports](zap/reports) folder.
