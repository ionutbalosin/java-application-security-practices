# Application Security for Java Developers

Copyright (C) 2025 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

## Security Design Principles

> ⏰ 20 minutes

> 👨‍🎓 Attendees' Exercise

A company, `SecureBank`, recently launched an online banking platform. However, users have reported various security issues. Here’s what happened in some key events.

### 1. User Accounts Compromised

`SecureBank`’s employees use shared administrator accounts to access customer data. Due to this, one employee accidentally deleted critical customer information.

❓ **Question**: Which principle is lacking here, and what would you recommend to address it?

    1. Defense in depth
    2. Least privilege
    3. Fail securely
    4. Compartmentalization

---

### 2. System Breach Through a Single Firewall

Hackers breached `SecureBank`'s platform by exploiting a vulnerability in its single-layer firewall. With no additional protective layers, attackers gained direct access to sensitive data.

❓ **Question**: Which security principle could have mitigated this risk?

    1. Compartmentalization
    2. Defense in depth
    3. Least privilege
    4. Fail securely

---

### 3. Sensitive Data Exposure During System Error

During a system crash, users noticed that sensitive data, such as account balances, were briefly exposed on error pages.

❓ **Question**: Which principle is missing, and how would applying it prevent this issue?

    1. Least privilege
    2. Compartmentalization
    3. Fail securely
    4. Defense in depth

---

### 4. Cross-System Data Leakage

The `SecureBank` platform stores credit card information alongside other non-sensitive data in the same database. When an unrelated feature failed, developers inadvertently accessed credit card data during troubleshooting.

❓ **Question**: Which principle should `SecureBank` implement to prevent this kind of issue?

    1. Compartmentalization
    2. Defense in depth
    3. Fail securely
    4. Least privilege