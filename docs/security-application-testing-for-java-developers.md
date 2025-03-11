# Security Application Testing for Java Developers

## Content

- [Introduction](#introduction)
- [Software Composition Analysis (SCA)](#software-composition-analysis-sca)
- [Static Application Security Testing (SAST)](#static-application-security-testing-sast)
- [Dynamic Application Security Testing (DAST)](#dynamic-application-security-testing-dast)
- [Penetration Testing (PenTest)](#penetration-testing-pentest)
- [Summary](#summary)
- [References](#references)

---

🔒 This article is tailored for Java developers and provides an overview of essential security testing tools, including Software Composition Analysis (SCA), Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), and Penetration Testing (PenTest), with practical examples and commands for integrating these tools into Java projects.

📚 It is part of a series of security-related articles for Java developers.
I highly recommend checking out the others for a more comprehensive understanding:
- [API Web Application Security for Java Developers](https://ionutbalosin.com/2025/03/api-web-application-security-for-java-developers): Covers key security aspects to secure the Java application surface and APIs (e.g., authentication and authorization), and how Java applications can enhance the security of web or single-page applications (e.g., Content Security Policy, HTTP security headers).
- [Core Application Security for Java Developers](https://ionutbalosin.com/2025/03/core-application-security-for-java-developers): Covers internal Java application security measures after receiving external requests, focusing on securing resource access, input validation, encryption, hashing, secrets management, logging, and deserialization vulnerabilities.

## Introduction

Security has become a built-in quality attribute of modern software. Ensuring that a system is secure and compliant with regulations is crucial in certain domains, such as banking, otherwise, you risk going out of business.

Depending on the criticality of these systems (e.g., non-critical, critical, or mission-critical), internal and external regulations, as well as the sensitivity and confidentiality of the data they hold, multiple security checks can be implemented using different tools at various stages:
- `Build time`: SCA and SAST.
- `Deploy time`/`Target running environment`: DAST and PenTest.

The diagram below illustrates where these tools can be integrated within the deployment pipeline.

[![Security Testing.svg](https://github.com/ionutbalosin/java-application-security-practices/blob/main/docs/images/security_testing.svg?raw=true)](https://github.com/ionutbalosin/java-application-security-practices/blob/main/docs/images/security_testing.svg?raw=true)

In this article, I will explain each of them and provide an example of how to integrate them into your application.

## Software Composition Analysis (SCA)

**Software Composition Analysis (SCA)** identifies vulnerabilities in project dependencies by using [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe) identifiers, a standardized naming scheme that maps software components to known vulnerabilities documented as [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/) entries.

Each identified vulnerability is assigned a [Common Vulnerability Scoring System (CVSS)](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) score, which ranges from `1` to `10`, with `10` representing the most severe vulnerabilities.

The [National Vulnerability Database (NVD)](https://nvd.nist.gov/products/cpe) is a U.S. government-managed repository that maintains comprehensive records of publicly known vulnerabilities.
It includes the CPE dictionary, which organizes information about affected software products.
This database is widely used by SCA code-scanning tools to identify vulnerable dependencies and assess known security risks associated with them.

### OWASP Dependency-Check

[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check) is an open-source SCA tool that identifies vulnerabilities in project dependencies, helping reveal and address known security risks.

To run the tool as a Maven plugin and check for known dependency vulnerabilities, use the following command in the provided [application](https://github.com/ionutbalosin/java-application-security-practices):

```bash
./mvnw clean compile org.owasp:dependency-check-maven:check
```

The detailed report containing all libraries and their vulnerabilities, including links to the sources where they were reported, can be found in `<project_module>/target/dependency-check-report.html`.

## Static Application Security Testing (SAST)

**Static Application Security Testing (SAST)** is a method used to secure software by analyzing its source code, or bytecode code to identify potential vulnerabilities early in the development process.
SAST tools run at compile time and require access to the codebase to detect security weaknesses based on specific patterns, such as hardcoded secrets, input validation issues, or coding flaws that could lead to vulnerabilities.

However, SAST tools come with some drawbacks:
- `False Positives`: SAST tools often report potential vulnerabilities that are not actual security issues, leading to unnecessary alerts and potentially overwhelming developers with false alarms.
- `Limited Context Awareness`: SAST tools analyze code statically and cannot fully simulate runtime behaviors or interactions, sometimes missing issues that would only appear during execution.
- `Dependency on Code Quality`: The accuracy of SAST tools can be impacted by poorly written, obfuscated, or highly complex code, which may result in missed vulnerabilities or excessive false positives.

There are multiple SAST options available, such as [CodeQL](https://codeql.github.com/), [Spotbugs](https://spotbugs.github.io/), and others.

### Spotbugs

[Spotbugs](https://spotbugs.github.io/) is an open-source static analysis tool that detects bugs in Java programs by analyzing bytecode. It may not be the most reliable option, but it is included here to provide an example of how a SAST tool can be integrated into a project.

To scan for potential code vulnerabilities, run the following Maven command inside the [application](https://github.com/ionutbalosin/java-application-security-practices) directory:

```bash
./mvnw clean compile spotbugs:check
```

## Dynamic Application Security Testing (DAST)

**Dynamic Application Security Testing (DAST)** is a security testing method that analyzes running applications to identify potential vulnerabilities without requiring access to the source code. DAST tools simulate external attacks on live applications, making them particularly effective for uncovering vulnerabilities in web applications, APIs, and services in real time.

Key Features:
- `Black-Box Testing`: DAST operates as an external attacker would, focusing on the application's exposed interfaces and user interactions, which helps uncover issues like authentication flaws, injection vulnerabilities, and configuration errors.
- `Runtime Context`: By analyzing applications in a live environment, DAST tools can detect vulnerabilities that static methods may miss, such as input handling issues and misconfigurations.

### The Zed Attack Proxy

[The Zed Attack Proxy (ZAP)](https://github.com/zaproxy/zaproxy) is an open-source DAST tool specifically designed for identifying vulnerabilities in applications during runtime.

To check for API security vulnerabilities, execute the following command inside the [application](https://github.com/ionutbalosin/java-application-security-practices) directory:

```bash
./zap-scan.sh
```

This command starts ZAP in Docker, launches an API scan using the [zap-api-scan rules](https://github.com/ionutbalosin/java-application-security-practices/blob/main/zap/zap-api-scan-rules.conf) against one of the services, and saves the scan report in the [./zap/reports](https://github.com/ionutbalosin/java-application-security-practices/tree/main/zap/reports) folder.

## Penetration Testing (PenTest)

Penetration Testing (PenTest) is a security testing method where ethical hackers simulate real-world attacks on a system to identify vulnerabilities and weaknesses. 

It is typically performed by external specialized security teams to ensure an unbiased and comprehensive evaluation of the system's security.
Ideally, these teams should be rotated periodically to avoid over-reliance on the same testers.

It is crucial that penetration testing is conducted in an environment that closely resembles production.

The frequency of penetration testing should generally align with major releases and their criticality. However, since it is a time-consuming and costly activity, most projects conduct it every few months (a few times a year), which is generally acceptable.

## Summary

It is not mandatory to include all of these testing strategies in your project, as they can be cumbersome and require significant time and resources. Nevertheless, you should incorporate the ones that make sense for your specific needs.

In my humble opinion, including **SAST** and **DAST** alone can already significantly help mitigate a large portion of security issues.

Of course, you can use other similar tools besides those I have presented here, including commercial ones, depending on your budget and strategy. Nevertheless, in this article, I have mainly focused on open-source solutions while still presenting the core concepts.

## References

- [Application Security for Java Developers Course](https://ionutbalosin.com/training/application-security-for-java-developers-course) – Level up your Java security skills! 🎓 🚀
- [Java Application Security Practices](https://github.com/ionutbalosin/java-application-security-practices) - GitHub source code
