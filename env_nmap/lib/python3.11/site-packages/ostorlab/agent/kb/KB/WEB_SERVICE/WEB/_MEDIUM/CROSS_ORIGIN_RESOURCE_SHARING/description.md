Cross-Origin Resource Sharing (CORS) uses HTTP headers to let a web client gain access to resources from a server on a
different domain. Browsers restrict cross-origin HTTP requests initiated from within scripts for security purposes.

If the policy allows another domain, then that domain can attack users of the application. If a user is logged in
to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can
retrieve content from the application, and carry out actions within the security context of the logged-in user.
