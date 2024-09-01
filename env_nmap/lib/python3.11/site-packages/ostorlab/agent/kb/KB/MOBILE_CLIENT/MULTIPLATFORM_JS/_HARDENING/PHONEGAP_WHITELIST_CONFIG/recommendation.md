Cordova offers a powerful security model to provide developers with the tools to prevent unauthorized access and
Cross-Site Scripting vulnerabilities.

Cordova whitelist manages network security access and must authorize explicitly accessible resources only.

To enable Cordova whitelisting, follow the steps:

1. **Install the Cordova Whitelist Plugin:** If you haven't already, you'll need to install the Cordova Whitelist Plugin. You can do this by running the following command in your project directory:

```bash
cordova plugin add cordova-plugin-whitelist
```

2. **Configure the Whitelist**: Once the plugin is installed, you can configure the whitelist in your `config.xml` file. You can specify which external resources your application is allowed to access by adding `<allow-navigation>` and `<allow-intent>` tags. 

=== "XML"
  ```xml
  <!-- Allow access to a specific domain -->
  <allow-navigation href="http://example.com/*" />
  
  <!-- Allow access to all URLs -->
  <allow-navigation href="*" />
  
  <!-- Allow opening specific URLs in the system browser -->
  <allow-intent href="http://*/*" />
  <allow-intent href="https://*/*" />
  ```