Insecure Authorization Restriction refers to weaknesses in server-side restrictions that can be exploited through HTTP request manipulation techniques. This vulnerability allows attackers to bypass access controls, leading to unauthorized access to resources, privilege escalation, and allowing unauthorized users to retrieve, create, update, or delete sensitive data.

Targeting Insecure Authorization Restrictions on a web server, for example, would involve these techniques:

   * **HTTP Request Method fuzzing**: Testing invalid, malformed, or unexpected HTTP methods on the server.
   * **HTTP Request Path fuzzing**: Manipulating the HTTP request path by deforming it, adding to it, or subtracting from it.
   * **HTTP Request Query Paramete**r fuzzing: Adding, removing, or changing the original query parameters.
   * **HTTP Request Header fuzzing**: Adding familiar headers, removing headers, or adding proxy headers.

All these techniques target defects, vulnerabilities, or mistakes in a server's logic.

=== "Python"
  ```python
    import requests

    response = requests.get("http://www.some-url.com/unauthorized_path")

    '''if we have some unauthorized path that gets us a 403 code,
    we can try something like adding a query parameter like "debug=true" to see if we can
    trick the server by exploiting some mistake.'''

    response = requests.get("http://www.some-url.com/unauthorized_path?debug=true")

    '''Might get us the resource we want''
  ```