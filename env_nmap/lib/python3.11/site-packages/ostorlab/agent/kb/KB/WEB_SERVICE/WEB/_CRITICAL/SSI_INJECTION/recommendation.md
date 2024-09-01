To mitigate the risk of server-side include injection vulnerabilities, consider the following recommendations:

- __Disable SSI__: if not needed, disabling SSI is the bulletproof recommendation to mitigate the risk of SSI injection, restricting SSI to a limited number of pages would also help mitigate some of the risks.

- __Input Validation and Sanitization__: Sanitize and/or encode user supplied input (notably HTML special characters like <>) before passing it to a page with SSI execution permissions.

- __Use suEXEC__: Use suEXEC to restrict the permissions of the user running SSI directives.


=== "SSI"
  ```ssi
  <!--#if expr="$user_input =~ /^[a-zA-Z0-9_\-]+$/i" -->
     <!--#include virtual="/web/$user_input" -->
  <!--#else -->
     Invalid input!
  <!--#endif -->
  ```