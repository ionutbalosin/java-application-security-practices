# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

## Security Design Principles Answers

### 🕵️‍♂️ User Accounts Compromised
🔑 `Least privilege` - Limiting access per role would prevent unnecessary permissions for sensitive actions.

### 🕵️‍♂️ System Breach Through a Single Firewall
🔑 `Defense in depth` - Layered security controls (e.g., multiple firewalls, IDS) would add protection against breaches.

### 🕵️‍♂️ Sensitive Data Exposure During System Error
🔑 `Fail securely` - Error messages should avoid revealing sensitive information during a failure.

### 🕵️‍♂️ Cross-System Data Leakage
🔑 `Compartmentalization` - Separating sensitive data in a different database would limit access and exposure.

---

## Authentication And Authorization Answers

🔑 `1` - `OpenID Connect`

🔑 `2` - `Authorization Code Flow with PKCE`

🔑 `3` - `Client Credentials Flow`

🔑 `4` - Ideally, `Authorization Code Flow with PKCE`. The `Password Flow` is also acceptable for internal users but must include `Multi-Factor Authentication (MFA)`.

🔑 `5` - Ideally, `Token Introspection`. `JSON Web Key Set (JWKS)` also works.

🔑 `6`, `7` - Ideally, `JSON Web Key Set`. `Token Introspection` also works.

🔑 `8`, `9`, `12` - Authorization can be done using either `JWKS (JSON Web Key Set)` or `Token Introspection` if the queue message contains the JWT as a header. However, this is not the most common or ideal approach because JWTs are time-sensitive and can expire. If a message isn't consumed immediately, the token could become invalid, leading to authorization issues.

Instead, **queue clients (the systems that publish/consume messages to/from the queue) are typically authorized** independently of the message itself. This ensures they have the necessary permissions to send and receive messages.

🔑 `10` - `Client Credentials Flow`

🔑 `11` - Ideally, `JSON Web Key Set`. `Token Introspection` also works.

---

## Security General Quiz Answers

### 1. Email Account Verification

🔑 Even though the `FROM` address may seem legitimate, this email could still be a phishing attempt. Attackers often use `email spoofing` to make their messages appear genuine.

In this example, the URL in the link (https://www.penny-bank-customer-verification.com) doesn’t match the bank’s actual domain (`penny-bank.com`). Carefully examining URLs is crucial, as any deviation from the expected domain can indicate fraud.

If you receive a suspicious email, do not click any links. Instead, contact your bank directly using the official contact information on their website or on your card to verify the situation.

### 2. Suspicious Transaction Phone Call

🔑 Hang up and call Penny Bank using the official contact details (the number on the back of your card or from their official website). Although the caller ID might look legitimate, fraudsters can use advanced techniques like `call spoofing` to make it appear as though the call is from a trusted source. 

As a rule of thumb, never provide sensitive information (e.g., `name on the credit card`, `credit card number`, `expiration date`, `CVV`) over the phone, especially if you did not initiate the call.

### 3. Failed Delivery Notification Text Message

🔑 The link provided is suspicious and does not match Amazon’s official domain (e.g., it uses https://www.amazon-package-delivery.com instead of `amazon.com`). 
Even if you were expecting a package, the mismatch in the domain is a strong indication that this could be an `SMS phishing (smishing)` attack. 

Do not call the phone number in the message, as there is a high chance it could also be part of the scam. Instead, if you are expecting a package, check its status on the official Amazon website or contact Amazon customer support directly for more details.

### 4. Legitimate URL

🔑 https://support.apple.com/account is the only URL that uses an official company domain (`apple.com`). All other URLs contain additional terms (e.g., `apple-id.com`, `paypal-user.com`, `amazon-center.com`, `netflix-security.com`) that make them look suspicious, even though they appear similar to legitimate domains.

### 5. A Friend is Asking for Money

🔑 Contacting your friend via a different method is the safest choice because it allows you to verify the situation through a trusted and secure channel, rather than relying on the potentially fraudulent message.