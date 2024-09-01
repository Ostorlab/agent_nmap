Server-Side Include (SSI) injection vulnerabilities occur when an application incorporates user-controllable data into a response that is subsequently parsed for Server-Side Include directives. If the provided user input is not strictly validated, malicious actors can manipulate or insert directives to execute malicious code.

Exploiting SSI injection vulnerabilities often enables the injection of arbitrary content, such as JavaScript, into the application's response, presenting similar risks as cross-site scripting (XSS). Depending on the server's configuration, the vulnerability may also allow to access protected files or execute arbitrary system commands on the server.

SSI injection can have multiple injection points such as post forms, http headers, cookies..


- Code Execution:

=== "http"
  ```http
  GET / HTTP/1.1
  Host: localhost
  Referer: <!--#exec cmd="/bin/ls"-->
  ```

- File inclusion:

=== "http"
  ```http
  POST /contact HTTP/1.1
  Host: localhost
  
  body=<!--#include virtual="/proc/version"-->
  ```