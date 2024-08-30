By default, SSL certificates are validated. If it's not the case with your application, consider:

1. **Avoid tampering with SSL classes:** Avoid overriding TrustManager or SSLSocketFactory to allow invalid certificates.
2. **Certificate Pinning:** Implement certificate pinning to ensure that the application only accepts certificates from trusted sources. By hardcoding or storing trusted certificates within the application, it can verify the authenticity of the server's certificate during the SSL/TLS handshake process, thereby preventing MITM attacks using self-signed certificates.

