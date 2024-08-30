Cordova offers a powerful security model to provide developers with the tools to prevent unauthorized access and
Cross-Site Scripting vulnerabilities.

Cordova whitelist manages network security access and must authorize explicitly accessible resources only.

=== "XML"
  ```xml
  <!-- Allow access to a specific domain -->
  <allow-navigation href="http://example.com/*" />
  ```