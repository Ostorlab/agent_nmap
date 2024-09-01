There are six protocols in the SSL/TLS family: SSL v2, SSL v3, TLS v1.0, TLS v1.1, TLS v1.2, and TLS v1.3:

- SSL v2 is insecure and must not be used. This protocol version can attack RSA keys and sites with the same
  name using the DROWN attack.
- SSL v3 is insecure when used with HTTP due to the SSLv3 POODLE attack. The protocol is considered weak when used with
  other protocols. The protocol is deprecated and must not be used.
- TLS v1.0 and TLS v1.1 are legacy protocol that suffers from the BEAST attack. Although modern have implemented some
  mitigations, the protocol still suffers from known weaknesses and has been deprecated by PCI DSS and browsers starting
  January 2020.
- TLS v1.2 and v1.3 are not known to have security issues.
