The server must add the header `Strict-Transport-Security` to all HTTP
responses to instruct the browser to use transport security.

HSTS is only true on first use, a user who has never accessed the application is still vulnerable to SSL stripping attacks.
