# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

> ⏰: 30 minutes

## Security Testing

### 👨‍💼 Trainer: Hands-On Demo

#### 🕵️‍♂️ Software Composition Analysis

A **Software Composition Analysis (SCA)** tool identifies vulnerabilities in project dependencies by using [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe) identifiers—a structured naming scheme—and linking them to [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/) entries.

Each identified vulnerability is assigned a **Common Vulnerability Scoring System (CVSS)** score, which ranges from `1` to `10`, with `10` representing the most severe vulnerabilities.

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/products/cpe), a U.S. government-managed repository, maintains a structured CPE dictionary. This dictionary allows tools like [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check) to identify vulnerable dependencies and reveal known risks.

Open a terminal and execute the following command to check for any known dependency vulnerabilities:

```bash
./mvnw clean compile org.owasp:dependency-check-maven:check
```

**Note:** The first run of this command might take a significant amount of time (e.g., a couple of minutes) to initially download the [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) hosted by NIST.

The detailed report containing all libraries and their vulnerabilities, including links to the sources where they were reported, can also be found in `<project_module>/target/dependency-check-report.html`.

---

#### 🕵️‍♂️ Static Application Security Testing

**Static Application Security Testing (SAST)** is used to secure software by reviewing its source code to identify potential sources of vulnerabilities. It runs at compile time and requires access to the source code to determine if any possible security vulnerabilities might occur based on specific patterns.

Main SAST Drawbacks:
- `False Positives`: SAST tools frequently report vulnerabilities that are not actual security issues, leading to unnecessary alerts and potentially overwhelming developers with false alarms.
- `Dependency on Code Quality`: The effectiveness of SAST tools can be compromised by poorly written or obfuscated code.

[Spotbugs](https://spotbugs.github.io/) is an open-source static analysis tool that detects bugs in Java programs by analyzing bytecode.

With the help of the [FindSecBugs plugin](https://find-sec-bugs.github.io/) plugin, it can be used as a **Static Application Security Testing (SAST)** tool to identify security vulnerabilities in Java applications.

To check for potential code vulnerabilities, execute the following command:

```bash
./mvnw clean compile spotbugs:check
```

---

#### 🕵️‍♂️ Dynamic Application Security Testing

A **Dynamic Application Security Testing (DAST)** tool analyzes running applications to detect potential security issues without requiring access to the source code. It is particularly effective for uncovering vulnerabilities in web applications and APIs in real time.

[The Zed Attack Proxy (ZAP)](https://github.com/zaproxy/zaproxy) is an open-source DAST tool specifically designed for identifying vulnerabilities in applications during runtime.

To check for API security vulnerabilities, execute the following command:

```bash
./zap-scan.sh
```

**Note:** Please ensure the `Pizza` application is already started; otherwise, the command will not execute successfully.

The command starts ZAP in Docker, launches an API scan using the [zap-api-scan rules](zap/zap-api-scan-rules.conf) against one of the services, and saves the scan report in the [./zap/reports](zap/reports) folder.
