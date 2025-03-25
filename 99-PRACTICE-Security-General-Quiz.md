# Application Security for Java Developers

Copyright (C) 2025 Ionut Balosin

This project is licensed under the Apache License, Version 2.0.
Please see the [LICENSE](license/LICENSE) file for full license.

---

### 1. Email Account Verification

You receive the following email from your bank, called Penny Bank and registered at [penny-bank.com](http://penny-bank.com), where you hold an account:

```html
FROM: support@penny-bank.com
SUBJECT: URGENT: Action Required to Avoid Account Suspension

Dear Valued Customer,

We have detected suspicious activity on your account and have temporarily restricted access. To restore full access, you must verify your identity immediately.

Click the link below to confirm your email and restore your account:
[Verify Your Account](https://www.penny-bank-customer-verification.com)

Failure to act within 24 hours will result in permanent suspension.

Thank you for your prompt attention.

Sincerely,
Support Team
Penny Bank
```

❓ **Question**: How should you behave?

    1. Simply mark the email as spam.
    2. Do not act on this email but rather call the bank directly to ask what is happening.
    3. Click the link and proceed further.

---

### 2. Suspicious Transaction Phone Call

You receive a phone call from a lady claiming to be from the payment supervision department of Penny Bank, where you hold both a credit card and an account.
The caller ID on your smartphone displays Penny Bank's name, so it looks legitimate.

The lady informs you that she noticed an unusual transaction from your account, and as a result, your account has been temporarily locked.

She then asks you to confirm your identity, informs you that you will shortly receive an email, and requests that you click the activation link in the email to reactivate your account.

❓ **Question**: What should you do?

    1. Confirm your identity and click the link in the email to reactivate your account, since the call appears to be from Penny Bank.
    2. Hang up and call Penny Bank directly using the number from the official website or the back of your credit card.
    3. Tell them you will visit a local branch to resolve the issue.

---

### 3. Failed Delivery Notification Text Message

You receive a text message saying:

```html
Your delivery package number #1234 failed. Click this link to change the delivery contact information: 
https://www.amazon-package-delivery.com/update-contact/1234.

If you do not provide an update within 24 hours, the delivery will be rejected.
```

The sender's number is `+43664111111111`, and it appears to be from Amazon.

❓ **Question**: What is the best action to take?

    1. Click the link to update the data and resolve the issue.
    2. Call the number +43664111111111 from the text message to ask for more details.
    3. Check the Amazon website for the official customer service phone number and call that to ask for more details.
    4. Ignore the message and delete it, since you are not expecting any package.

---

### 4. Legitimate URL

❓ **Question**: Which of the following URLs is legitimate?

    1. https://secure.apple-id.com/login
    2. https://login.authenticate.paypal-user.com
    3. https://support.amazon-center.com/help
    4. https://help.netflix-security.com
    5. https://support.apple.com/account

---

### 5. A Friend is Asking for Money

You receive a message in a social media chat from your friend, Martin Mustermann, asking you to send him money. He tells you he is on a private holiday, but his wallet with his credit card and phone were stolen. He says he is using a computer in the hotel lobby and urgently needs around 5,000 EUR to check out, pay the hotel fees, and return home. He promises to return the money once he’s back in a few days. He urges you to help him, saying he’s desperate, and asks that you not tell his parents.

❓ **Question**: What is the best course of action to take?

    1. Click the transfer link from the chat and send him the money.
    2. Contact your friend via a different method (e.g., a video chat) to verify his identity and confirm the situation.
    3. Ignore the message, as it is likely a joke or scam. If not, your friend should ask someone else for help.