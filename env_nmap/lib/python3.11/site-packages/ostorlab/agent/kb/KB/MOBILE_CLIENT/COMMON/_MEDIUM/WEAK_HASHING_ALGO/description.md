A hash function is a function that is used to encode data and return a -fixed size- hash value with the purpose of minimizing the chance of colision (two different inputs having the exact same hash value is incredibly small), these functions could be used for verifying the integrity of a message or files, identifying a file or data or checking a secret or password.


Common hashing algorithms:

* `MD5`: Message Digest Algorithm (MD5) was designed in 1991 as a replacement for MD4. On March 2005,
    two different files with the same MD5 hash were presented. And a year later an algorithm that can find collisions within a minute was published.
    When it comes to hashing algorithms finding two distinct inputs with the same hash should be computationally infeasible, MD5 fails this requirement catastrophically, in 2008 the software engineering institute concluded that MD5 is "cryptographically broken and unsuitable for further use".
* `SHA1`: Secure Hash Algorithm 1 (SHA1) was designed by the NSA. Like MD5, SHA1 is vulnerable to collision attacks. By 2005 SHA1 was considered insecure, in 2011 the National Institute of Standards and Technology (NIST) formally deprecated it.
* `SHA2`: is a set of hashing algorithms that was also designed by the NSA, SHA-2 is significantly different from SHA1 and is considered highly secure.
* `SHA-256`: is a member of the SHA-2 set. the suffix 256 stands for 256 bits which is the length of the hash value produced. SHA-256 is a secure and trusted industry standard with near impossible chance of collisions (2^256).
* `SHA3`: SHA3 is the latest member of the Secure Hash Algorithm family of standards, released by NIST in 2015. Although part of the same series of standards, SHA3 is internally different from the MD5-like structure of SHA1 and SHA2, and is also considered highly secure.
* `Argon2`: is the winner of the 2015 Password Hashing Competition. and it is now considered one of the most secure password hashing algorithms available. It has been adopted by a number of security and cryptography standards, including the Internet Engineering Task Force (IETF), the Password Hashing Competition (PHC) and The Open Worldwide Application Security Project (OWASP).
* `Bcrypt`: Introduced in 1999, Bcrypt is a slow adaptive algorithm designed to be highly resistant to brute-force. Its adaptivity is that it gives control to the user over the computational cost, which means that it can be adjusted as hardware evolve over time.
    Bcrypt is also adopted by many security standards, including the Open Web Application Security Project (OWASP) and the Payment Card Industry Data Security Standard (PCI DSS).
* `HMAC`: Hash-based message authentication code is not a hashing algorithm but rather a cryptographic authentication technique that uses a hashing algorithm coupled with a secret key, the strength of HMAC depends on the underlying hash algorithm, and therefore should not be used with deprecated and weak hash algorithms.


`MD5` and `SHA-1` are insecure and must not be used, even with HMAC.