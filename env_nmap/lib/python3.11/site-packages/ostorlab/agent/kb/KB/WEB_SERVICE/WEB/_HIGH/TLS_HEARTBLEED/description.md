Heartbleed (CVE-2014-0160) is a security bug in the OpenSSL cryptography library, a widely used implementation of Transport Layer Security (TLS) protocol. It was introduced into the software in 2012 and publicly disclosed in April 2014.

Heartbleed may be exploited regardless of whether the vulnerable OpenSSL instance runs as a TLS server or client.
It results from improper input validation (due to a missing bounds check) in the implementation of the TLS heartbeat
extension; thus, the bug's name derives from heartbeat. Additionally, the vulnerability is classified as a buffer
over-read, where more data can be read than should be allowed.
