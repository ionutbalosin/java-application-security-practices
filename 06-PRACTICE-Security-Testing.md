# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

## Security Testing

> ⏰ 30 minutes

> 👨‍🎓 Attendees' Exercise

### 📖 Informational: SCA, SAST and DAST

**Software Composition Analysis (SCA)** identifies vulnerabilities in project dependencies by using [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe) identifiers, a standardized naming scheme that maps software components to known vulnerabilities documented as [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/) entries.

Each identified vulnerability is assigned a [Common Vulnerability Scoring System (CVSS)](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) score, which ranges from `1` to `10`, with `10` representing the most severe vulnerabilities.

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/products/cpe) is a U.S. government-managed repository that maintains comprehensive records of publicly known vulnerabilities. 
It includes the CPE dictionary, which organizes information about affected software products. 
This database is widely used by SCA code-scanning tools to identify vulnerable dependencies and assess known security risks associated with them.

**Static Application Security Testing (SAST)** is a method used to secure software by analyzing its source code, or bytecode code to identify potential vulnerabilities early in the development process. 
SAST tools run at compile time and require access to the codebase to detect security weaknesses based on specific patterns, such as hardcoded secrets, input validation issues, or coding flaws that could lead to vulnerabilities.

Main Drawbacks:
- `False Positives`: SAST tools often report potential vulnerabilities that are not actual security issues, leading to unnecessary alerts and potentially overwhelming developers with false alarms.
- `Dependency on Code Quality`: The accuracy of SAST tools can be impacted by poorly written, obfuscated, or highly complex code, which may result in missed vulnerabilities or excessive false positives.
- `Limited Context Awareness`: SAST tools analyze code statically and cannot fully simulate runtime behaviors or interactions, sometimes missing issues that would only appear during execution."

**Dynamic Application Security Testing (DAST)** is a security testing method that analyzes running applications to identify potential vulnerabilities without requiring access to the source code. DAST tools simulate external attacks on live applications, making them particularly effective for uncovering vulnerabilities in web applications, APIs, and services in real time.

Key Features:
- `Black-Box Testing`: DAST operates as an external attacker would, focusing on the application's exposed interfaces and user interactions, which helps uncover issues like authentication flaws, injection vulnerabilities, and configuration errors.
- `Runtime Context`: By analyzing applications in a live environment, DAST tools can detect vulnerabilities that static methods may miss, such as input handling issues and misconfigurations.

---

### 🕵️‍♂️ Software Composition Analysis

[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check) is an open-source SCA tool that identifies vulnerabilities in project dependencies, helping reveal and address known security risks.

Open a terminal and execute the following command to check for any known dependency vulnerabilities:

```bash
./mvnw clean compile org.owasp:dependency-check-maven:check
```

**Note:** The first run of this command might take a significant amount of time (e.g., from a couple of minutes to even tens of minutes, depending on the internet connection) to initially download the [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) hosted by NIST.

The detailed report containing all libraries and their vulnerabilities, including links to the sources where they were reported, can also be found in `<project_module>/target/dependency-check-report.html`.

---

### 🕵️‍♂️ Static Application Security Testing

[Spotbugs](https://spotbugs.github.io/) is an open-source static analysis tool that detects bugs in Java programs by analyzing bytecode.

With the help of the [FindSecBugs plugin](https://find-sec-bugs.github.io/) plugin, it can be used as a SAST tool to identify security vulnerabilities in Java applications.

To check for potential code vulnerabilities, execute the following command:

```bash
./mvnw clean compile spotbugs:check
```

---

### 🕵️‍♂️ Dynamic Application Security Testing

[The Zed Attack Proxy (ZAP)](https://github.com/zaproxy/zaproxy) is an open-source DAST tool specifically designed for identifying vulnerabilities in applications during runtime.

To check for API security vulnerabilities, execute the following command:

```bash
./zap-scan.sh
```

**Note:** Please ensure the `Pizza` application is already started; otherwise, the command will not execute successfully.

The command starts ZAP in Docker, launches an API scan using the [zap-api-scan rules](zap/zap-api-scan-rules.conf) against one of the services, and saves the scan report in the [./zap/reports](zap/reports) folder.
