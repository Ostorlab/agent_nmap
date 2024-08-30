To mitigate the risks of using weak hashing algorithms, consider the following:

- Avoid MD5 and SHA-1 as these algorithms are insecure and prone to collisions. They should not be used for any purpose, including HMAC.

- For hashing and signature verification, opt for SHA-256 or SHA-3. They offer high security and are widely accepted industry standards.

- For sensitive data (PII, PHI...) hashing, consider Argon2 or Bcrypt. They are designed to resist brute-force attacks and are recommended by security standards.

- When using HMAC for message authentication, ensure it's coupled with secure hash algorithms like SHA-256 or SHA-3 to maintain robust security.
