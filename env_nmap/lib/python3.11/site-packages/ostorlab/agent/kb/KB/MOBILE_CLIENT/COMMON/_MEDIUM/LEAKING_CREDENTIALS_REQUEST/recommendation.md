To avoid having credentials leaked in application logs and/or backend servers logs, consider the following:

- **Avoid Storing Credentials in URLs:** Refrain from placing sensitive information such as session tokens directly into URLs whenever possible.
- **Utilize Secure Session Management:** Implement secure session management techniques that do not rely on embedding credentials in URLs. Instead, use methods like session cookies with proper security configurations.
- **Encrypt Sensitive Data in Transit:** Employ encryption protocols such as HTTPS to ensure that sensitive data, including URLs containing credentials, are encrypted during transmission between the user's device and the web server.
- **Implement URL Redaction:** Implement mechanisms to automatically redact or obfuscate sensitive information, such as credentials, from URLs displayed on-screen or logged to minimize the risk of exposure.
