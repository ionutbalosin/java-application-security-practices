# Application Security for Java Developers

Copyright (C) 2024 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

## Topmost Common Attacks

> ⏰ 30 minutes

> 👨‍💼 Conducted By Trainer

### 📖 Informational: XSS, CSRF, OWASP WebGoat

**Cross-Site Scripting (XSS)** is a security vulnerability that allows attackers to inject malicious scripts into web pages, enabling them to execute in users' browsers and potentially steal sensitive information or perform unauthorized actions.

**XSS** can be categorized into two main types:
- `Reflected XSS`: This type involves malicious scripts that are immediately executed in a user's browser when they click a crafted link or submit a form. It typically targets the same user and is not stored on the server.
- `Stored XSS`: The malicious scripts are stored on the server (e.g., in a database) and executed whenever the affected content is accessed by any user, allowing the attacker to target multiple victims over time.

**Cross-Site Request Forgery (CSRF)** is a security vulnerability that tricks users into unconsciously submitting unauthorized requests to a web application in which they are authenticated, potentially allowing attackers to perform actions on behalf of the user without their consent.

**XSS** vs **CSRF**:
- **XSS** involves injecting malicious scripts into web pages that are executed in the user's browser, while **CSRF** involves tricking the user into submitting unauthorized requests (often through an external image, link, or email received from the attacker) to a server while the user is authenticated.
- **XSS** targets the client (the user's browser) by executing scripts directly in it, while **CSRF** targets the server by sending forged requests that the server processes as legitimate actions while the user remains authenticated.

[OWASP WebGoat](https://owasp.org/www-project-webgoat) is a deliberately insecure application that contains lessons for almost all [OWASP Top 10](https://owasp.org/www-project-top-ten/) vulnerabilities (including **XSS**, **CSRF**, etc.). It allows developers to test vulnerabilities commonly found in Java-based applications that use popular open-source components.

Some solutions to the challenges in the `OWASP WebGoat` application can be found in the [WebGoat Solutions](https://github.com/WebGoat/WebGoat/wiki/Main-Exploits) wiki.

---

### 🏋️ Hands-On Demo

1. Open a terminal and start the `OWASP WebGoat` application in Docker using the following command:

   ```bash
   ./bootstrap-webgoat.sh
   ```

2. Next, open a browser and navigate to http://localhost:48080/WebGoat/login to access the **OWASP WebGoat UI**.

3. Create a user account to log in:
    - Username: `administrator`
    - Password: `Test1234!`

####  🕵️‍♂️ Cross-Site Scripting Attack

To demonstrate a simple reflected **XSS** attack, navigate to the `OWASP WebGoat` [Lesson 7 Exercise](http://localhost:48080/WebGoat/start.mvc?username=administrator#lesson/CrossSiteScripting.lesson/6).

You can find the solution to this exercise in the `OWASP WebGoat` [Solutions - Lesson 7 Exercise](https://github.com/WebGoat/WebGoat/wiki/Main-Exploits#cross-site-scripting-lesson-7-exercise) or simply inject and submit the following value for the `credit card number`:

   ```html
   <script>alert('This is an example of reflected XSS attack!')</script>
   ```

#### 🕵️‍♂️ Cross-Site Request Forgery Attack

To demonstrate a simple reflected **CSRF** attack, navigate to the `OWASP WebGoat` [Lesson 4 Exercise](http://localhost:48080/WebGoat/start.mvc?username=administrator#lesson/CSRF.lesson/3).

You can find the solution to this exercise in the `OWASP WebGoat` [Solutions - Lesson 4 Exercise](https://github.com/WebGoat/WebGoat/wiki/Main-Exploits#cross-site-request-forgeries-lesson-4-exercise) or simply save and open the `html` file below while logged into the application:

   ```html
   <html>
      <body>
         <form action="http://localhost:48080/WebGoat/csrf/review" method="POST"><input type="hidden" name="reviewText" value="This is an example of an CRSF attack!"><input type="hidden" name="stars" value="5"><input type="hidden" name="validateReq" value="2aa14227b9a13d0bede0388a7fba9aa9"></form>
         <script>document.forms[0].submit();</script>
      </body>
   </html>
   ```

**Note:** The CSRF attack will not work if the user is not logged into the application when opening this `html` file.