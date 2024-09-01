HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying
user agents (such as a web browser) are to interact with it using only secure (HTTPS) connections. The server
communicates the HSTS Policy to the user agent via an HTTP response header field named "Strict-Transport-Security". HSTS
The policy specifies a period during which the user agent shall access the server in only a secure fashion.

When a web application issues HSTS Policy to user agents, conformant user agents behave as follows:

- Automatically turn any insecure (HTTP) links referencing the web application into secure (HTTPS) links. (For
  instance, http://example.com/some/page/ will be modified to https://example.com/some/page/ before accessing the
  server.)
- If the connection's security cannot be ensured (e.g., the server's TLS certificate is self-signed), user agents
  show an error message and do not allow the user to access the web application.
